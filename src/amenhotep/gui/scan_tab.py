"""Scans tab: run a scan in a worker thread (progress + cancel) and show scan history."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, QThread, Signal, Slot
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from amenhotep.core.models import PROFILES
from amenhotep.core.netutil import TargetError, local_networks, validate_target
from amenhotep.core.paths import data_dir
from amenhotep.services.homemapper import ImportResult, import_homemapper
from amenhotep.services.scan import ScanResult, ScanService
from amenhotep.store import db
from amenhotep.store.repo import Repository

ServiceFactory = Callable[[Repository, Callable[[str], None]], ScanService]


def default_factory(repo: Repository, progress: Callable[[str], None]) -> ScanService:
    return ScanService(repo, progress=progress)


class ScanWorker(QObject):
    """Runs in its own QThread with its own SQLite connection (connections are thread-bound)."""

    progress = Signal(str)
    done = Signal(object)  # ScanResult
    failed = Signal(str)

    def __init__(
        self,
        db_path: Path | str,
        targets: list[Any],
        profile: str,
        factory: ServiceFactory,
        db_connect: Callable[[Path | str], Any] = db.connect,
    ) -> None:
        super().__init__()
        self.db_path, self.targets, self.profile = db_path, targets, profile
        self.factory, self.db_connect = factory, db_connect
        self.service: ScanService | None = None

    def cancel(self) -> None:
        if self.service:
            self.service.cancel.set()  # threading.Event: safe from the GUI thread

    @Slot()
    def run(self) -> None:
        conn = None
        try:
            conn = self.db_connect(self.db_path)
            self.service = self.factory(Repository(conn), self.progress.emit)
            result = self.service.run(self.targets, self.profile)
            self.done.emit(result)
        except Exception as exc:  # report any failure to the UI instead of dying silently
            self.failed.emit(str(exc))
        finally:
            if conn is not None:
                conn.close()


class ScanTab(QWidget):
    scanFinished = Signal(object)  # ScanResult
    importFinished = Signal(object)  # ImportResult

    def __init__(
        self,
        db_path: Path | str,
        repo: Repository,
        factory: ServiceFactory = default_factory,
        parent: Any = None,
    ) -> None:
        super().__init__(parent)
        self.db_path, self.repo, self.factory = db_path, repo, factory
        self._thread: QThread | None = None
        self._worker: ScanWorker | None = None
        self._closing = False  # set on shutdown: late worker signals must not touch the DB

        self.target = QLineEdit("auto")
        self.target.setToolTip("'auto' = local private networks, or CIDR list like 192.168.1.0/24")
        self.profile = QComboBox()
        for name in (*PROFILES, "watch"):
            self.profile.addItem(name)
        self.profile.setToolTip(
            "watch = light presence pass (who is online now); fingerprints only new devices"
        )
        self.profile.setCurrentText("standard")
        self.start_btn = QPushButton("Start scan")
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.status = QLabel("Idle")
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setMaximumBlockCount(500)
        self.history = QTableWidget(0, 5)
        self.history.setHorizontalHeaderLabels(["#", "Started", "Profile", "Target", "Status"])
        self.history.horizontalHeader().setStretchLastSection(True)
        self.history.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.import_btn = QPushButton("Import HomeMapper CSV…")
        self.import_btn.setToolTip(
            "Merge an export of the HomeMapper iPhone app (Home app names, rooms, serials, "
            "firmware, Thread details) into Devices and Thread/Matter"
        )
        self.import_btn.clicked.connect(self.choose_import)
        self.imports = QTableWidget(0, 7)
        self.imports.setHorizontalHeaderLabels(
            ["File", "Imported", "Rows", "Merged", "New", "Thread/Matter", "Conflicts"]
        )
        self.imports.horizontalHeader().setStretchLastSection(True)
        self.imports.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)

        self.start_btn.clicked.connect(self.start)
        self.cancel_btn.clicked.connect(self.cancel)

        row = QHBoxLayout()
        row.addWidget(QLabel("Target"))
        row.addWidget(self.target, 1)
        row.addWidget(QLabel("Profile"))
        row.addWidget(self.profile)
        row.addWidget(self.start_btn)
        row.addWidget(self.cancel_btn)
        layout = QVBoxLayout(self)
        layout.addLayout(row)
        layout.addWidget(self.status)
        layout.addWidget(self.log, 1)
        layout.addWidget(QLabel("History"))
        layout.addWidget(self.history, 1)
        imp_row = QHBoxLayout()
        imp_row.addWidget(QLabel("Imports"))
        imp_row.addStretch(1)
        imp_row.addWidget(self.import_btn)
        layout.addLayout(imp_row)
        layout.addWidget(self.imports, 1)
        self.refresh_history()

    # ---- actions -----------------------------------------------------
    def resolve_targets(self) -> list[Any]:
        text = self.target.text().strip() or "auto"
        if text == "auto":
            nets = local_networks()
            if not nets:
                raise TargetError("no private local network found; enter a CIDR")
            return nets
        return [validate_target(t) for t in text.split(",")]

    def start(self) -> None:
        if self._thread is not None:
            return
        try:
            targets = self.resolve_targets()
        except TargetError as exc:
            self.status.setText(f"Cannot scan: {exc}")
            return
        self.log.clear()
        self._set_running(True)
        self._thread = QThread(self)
        self._worker = ScanWorker(self.db_path, targets, self.profile.currentText(), self.factory)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._on_progress)
        self._worker.done.connect(self._on_done)
        self._worker.failed.connect(self._on_failed)
        self._thread.start()

    def cancel(self) -> None:
        if self._worker:
            self.status.setText("Cancelling…")
            self.cancel_btn.setEnabled(False)
            self._worker.cancel()

    # ---- worker callbacks (GUI thread) ----------------------------
    def _on_progress(self, message: str) -> None:
        if self._closing:
            return
        self.status.setText(message)
        self.log.appendPlainText(message)

    def _on_done(self, result: ScanResult) -> None:
        if self._closing:
            return
        for w in result.warnings:
            self.log.appendPlainText(f"warning: {w}")
        if result.status == "cancelled":
            self.status.setText("Scan cancelled")
        else:
            self.status.setText(
                f"Scan #{result.scan_id} {result.status}: {result.hosts_seen} hosts, "
                f"{result.new_devices} new"
                + (f"; {len(result.warnings)} warning(s), see log" if result.warnings else "")
            )
        self._finish()
        self.scanFinished.emit(result)

    def _on_failed(self, message: str) -> None:
        if self._closing:
            return
        self.status.setText(f"Scan failed: {message}")
        self.log.appendPlainText(f"error: {message}")
        self._finish()

    def _finish(self) -> None:
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait(5000)
            self._thread = None
            self._worker = None
        self._set_running(False)
        self.refresh_history()

    def _set_running(self, running: bool) -> None:
        self.start_btn.setEnabled(not running)
        self.cancel_btn.setEnabled(running)
        self.target.setEnabled(not running)
        self.profile.setEnabled(not running)

    def is_running(self) -> bool:
        return self._thread is not None

    def set_editable(self, editable: bool) -> None:
        """Importing changes stored information, so it follows the global edit switch."""
        self.import_btn.setEnabled(editable)

    def choose_import(self) -> None:
        start = str(data_dir())
        path, _ = QFileDialog.getOpenFileName(
            self, "Import HomeMapper CSV", start, "CSV files (*.csv);;All files (*)"
        )
        if path:
            self.import_file(path)

    def import_file(self, path: str) -> ImportResult | None:
        try:
            result = import_homemapper(self.repo, path)
        except (ValueError, OSError) as exc:
            self.status.setText(f"Import failed: {exc}")
            self.log.appendPlainText(f"error: {exc}")
            return None
        self.log.appendPlainText(f"imported {result.filename}")
        for m in result.messages:
            self.log.appendPlainText(f"  {m}")
        self.status.setText(
            f"Imported {result.filename}: {result.matched} merged, {result.created} new, "
            f"{result.thread} Thread/Matter, {result.conflicts} conflict(s)"
        )
        self.refresh_history()
        self.importFinished.emit(result)
        return result

    def refresh_history(self) -> None:
        imports = self.repo.list_imports()
        self.imports.setRowCount(len(imports))
        for r, i in enumerate(imports):
            vals = (i.filename, i.imported_at, i.rows, i.matched, i.created, i.thread, i.conflicts)
            for c, v in enumerate(vals):
                self.imports.setItem(r, c, QTableWidgetItem(str(v)))
            self.imports.item(r, 0).setToolTip("\n".join(i.detail))  # type: ignore[union-attr]
        scans = self.repo.list_scans()
        self.history.setRowCount(len(scans))
        for r, s in enumerate(scans):
            for c, key in enumerate(("id", "started", "profile", "target", "status")):
                self.history.setItem(r, c, QTableWidgetItem(str(s[key])))

    def shutdown(self) -> None:
        """Stop a running scan and wait for its thread (called on window close)."""
        self._closing = True
        if self._worker:
            self._worker.cancel()
        if self._thread is not None:
            self._thread.quit()
            self._thread.wait(10000)
            self._thread = None
