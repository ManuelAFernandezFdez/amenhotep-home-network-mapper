import ipaddress
import subprocess
from datetime import datetime, timedelta

from amenhotep import cli
from amenhotep.collectors.nmap import NmapCollector
from amenhotep.core.lock import single_instance
from amenhotep.core.models import utcnow
from amenhotep.services import notify as notify_mod
from amenhotep.services.presence import hours_label, presence_all, presence_for, summarize
from amenhotep.services.scan import ScanService
from amenhotep.store import db
from amenhotep.store.repo import Repository

NET = [ipaddress.ip_network("192.0.2.0/24")]


class FakeNeigh:
    def collect(self):
        return []


def service(repo, online=(10, 11)):
    cmds = []

    def addr(n, mac):
        return (
            f'<address addr="192.0.2.{n}" addrtype="ipv4"/><address addr="{mac}" addrtype="mac"/>'
        )

    hosts = {10: addr(10, "da:11:22:33:44:10"), 11: addr(11, "b8:27:eb:00:00:11")}

    def runner(cmd, timeout):
        cmds.append(cmd)
        if "-sn" in cmd:  # the cheap sweep
            body = "".join(f'<host><status state="up"/>{hosts[i]}</host>' for i in online)
            return 0, f"<nmaprun>{body}</nmaprun>", ""
        asked = [h for h in cmd if h.startswith("192.0.2.")]  # the fingerprint: nothing open
        body = "".join(
            f'<host><status state="up"/>{hosts[int(a.split(".")[-1])]}</host>' for a in asked
        )
        return 0, f"<nmaprun>{body}</nmaprun>", ""

    nmap = NmapCollector(runner=runner, nmap_path="/usr/bin/nmap", raw_capable=False)
    svc = ScanService(repo, nmap=nmap, neigh=FakeNeigh(), discovery=[])
    return svc, cmds


def fingerprints(cmds):
    return [c for c in cmds if "-sn" not in c]


# ---- pure presence maths -----------------------------------------------------------------
def at(day, hour):
    return datetime(2026, 11, day, hour, 5)


def test_hours_label_merges_ranges():
    assert hours_label([17, 18, 19, 23]) == "17:00-20:00, 23:00-24:00"
    assert hours_label([]) == ""


def test_summarize_typical_hours_need_enough_checks():
    scans = [at(d, h) for d in range(1, 6) for h in (9, 20, 21)]
    seen = [t for t in scans if t.hour in (20, 21)]
    info = summarize(scans, seen)
    assert (info.seen, info.total) == (10, 15)
    assert info.online_hours == [20, 21]  # 9h: never seen; 5 checks per hour is enough evidence
    assert info.last_seen == at(5, 21)
    assert "seen in 10 of 15 checks (67%); typically online 20:00-22:00" == info.summary()
    sparse = summarize([at(1, 9), at(2, 9)], [at(1, 9)])  # only 2 checks in that hour
    assert sparse.online_hours == []
    assert summarize([], []).summary() == "no checks yet"


# ---- watch pass ------------------------------------------------------------------------------
def test_watch_is_light_records_sightings_and_probes_new_hosts_once(repo):
    svc, cmds = service(repo)
    r = svc.watch(NET)
    assert r.status == "done" and r.hosts_seen == 2 and r.new_devices == 2 and r.probed == 2
    assert "-sn" in cmds[0] and "-sV" not in cmds[0]  # the sweep itself is the cheap one
    assert len(fingerprints(cmds)) == 1  # one fingerprint run covering both new hosts
    assert len(repo.conn.execute("SELECT * FROM sighting").fetchall()) == 2
    assert all(d.online for d in repo.list_devices())
    # a second pass finds nothing new: sweep only, no fingerprinting
    svc2, cmds2 = service(repo)
    r2 = svc2.watch(NET)
    assert r2.probed == 0 and not fingerprints(cmds2)


def test_unidentified_device_is_reprobed_only_after_cooldown(repo):
    svc, _ = service(repo)
    svc.watch(NET)
    unknown = next(d for d in repo.list_devices() if d.device_type == "unknown")
    svc_b, cmds_b = service(repo)
    svc_b.watch(NET)
    assert not fingerprints(cmds_b)  # probed minutes ago: leave fragile devices alone
    old = (utcnow() - timedelta(hours=7)).isoformat(timespec="seconds")
    repo.conn.execute("UPDATE device SET last_probed=? WHERE uuid=?", (old, unknown.uuid))
    repo.commit()
    svc_c, cmds_c = service(repo)
    r = svc_c.watch(NET)
    assert r.probed == 1 and fingerprints(cmds_c)[0][-1] == "192.0.2.10"


def test_sleeper_waking_up_is_caught_and_reported_as_new_unknown(repo):
    svc, _ = service(repo, online=(11,))
    svc.watch(NET)
    assert {d.ip for d in repo.list_devices() if d.online} == {"192.0.2.11"}
    svc2, cmds2 = service(repo, online=(10, 11))  # the other device wakes up
    r = svc2.watch(NET)
    assert r.new_devices == 1 and r.new_unknown == ["192.0.2.10 (unknown vendor)"]
    assert r.probed == 1 and fingerprints(cmds2)[0][-1] == "192.0.2.10"


def test_offline_flag_and_presence_stats_follow_scans(repo):
    service(repo)[0].watch(NET)
    service(repo, online=(11,))[0].watch(NET)  # .10 went away
    by_ip = {d.ip: d for d in repo.list_devices()}
    assert by_ip["192.0.2.11"].online is True and by_ip["192.0.2.10"].online is False
    info = presence_all(repo)
    assert (info[by_ip["192.0.2.10"].uuid].seen, info[by_ip["192.0.2.10"].uuid].total) == (1, 2)
    assert presence_for(repo, by_ip["192.0.2.11"].uuid).ratio == 1.0
    assert presence_for(repo, "missing").seen == 0


def test_cancelled_watch_leaves_no_sightings(repo):
    svc, _ = service(repo)
    svc.cancel.set()
    assert svc.watch(NET).status == "cancelled"
    assert repo.conn.execute("SELECT COUNT(*) FROM sighting").fetchone()[0] == 0


def test_run_with_watch_profile_delegates_and_full_scans_mark_probed(repo):
    svc, _ = service(repo)
    assert svc.run(NET, "watch").probed == 2
    repo2 = Repository(db.connect(":memory:"))
    svc2, _ = service(repo2)
    svc2.run(NET, "standard")
    rows = repo2.conn.execute("SELECT last_probed FROM device").fetchall()
    assert rows and all(r["last_probed"] for r in rows)  # a standard scan counts as a probe
    assert repo2.conn.execute("SELECT COUNT(*) FROM sighting").fetchone()[0] == 2


def test_quick_scan_records_sightings_but_does_not_mark_probed(repo):
    svc, _ = service(repo)
    svc.run(NET, "quick")
    assert repo.conn.execute("SELECT COUNT(*) FROM sighting").fetchone()[0] == 2
    assert all(
        r["last_probed"] is None for r in repo.conn.execute("SELECT last_probed FROM device")
    )


def test_prune_drops_old_scans_but_keeps_the_latest(repo):
    svc, _ = service(repo)
    svc.watch(NET)
    old = (utcnow() - timedelta(days=200)).isoformat(timespec="seconds")
    repo.conn.execute("UPDATE scan SET started=?", (old,))
    repo.commit()
    repo.prune(90)
    assert repo.conn.execute("SELECT COUNT(*) FROM scan").fetchone()[0] == 1  # latest is kept
    svc.watch(NET)  # a newer scan exists now
    repo.conn.execute("UPDATE scan SET started=? WHERE id=1", (old,))
    repo.prune(90)
    assert [r["id"] for r in repo.conn.execute("SELECT id FROM scan")] == [2]
    assert repo.conn.execute("SELECT COUNT(*) FROM sighting WHERE scan_id=1").fetchone()[0] == 0


# ---- lock, notify, CLI -------------------------------------------------------------------------
def test_single_instance_lock(tmp_path):
    path = tmp_path / "x.lock"
    with single_instance(path) as first:
        assert first
        with single_instance(path) as second:
            assert second is False
    with single_instance(path) as again:
        assert again


def test_notify_neutralises_markup_and_uses_arg_list(monkeypatch):
    seen = {}
    monkeypatch.setattr(notify_mod.shutil, "which", lambda n: "/usr/bin/notify-send")
    monkeypatch.setattr(
        notify_mod.subprocess,
        "run",
        lambda argv, **kw: seen.update(argv=argv, kw=kw) or subprocess.CompletedProcess(argv, 0),
    )
    assert notify_mod.notify("New <b>device</b>", "evil&<script>")
    assert isinstance(seen["argv"], list) and "shell" not in seen["kw"]
    assert "<" not in " ".join(seen["argv"][3:]) and "&amp;" in seen["argv"][-1]
    monkeypatch.setattr(notify_mod.shutil, "which", lambda n: None)
    assert notify_mod.notify("t", "b") is False


def test_cli_presence_and_watch_skip_when_locked(capsys, monkeypatch, tmp_path):
    repo = Repository(db.connect(cli.db_path()))
    service(repo)[0].watch(NET)
    repo.conn.close()
    assert cli.main(["presence"]) == 0
    out = capsys.readouterr().out
    assert "192.0.2.10" in out and "online" in out and "checks in the last 7 days" in out
    assert cli.main(["presence", "--offline"]) == 0
    assert "192.0.2.10" not in capsys.readouterr().out
    with single_instance(cli.data_dir() / "watch.lock"):
        assert cli.main(["watch", "--target", "192.0.2.0/24"]) == 0
    assert "skipping" in capsys.readouterr().err
    assert cli.main(["watch", "--target", "8.8.8.0/24"]) == 2


def test_gui_shows_status_column_and_presence_line(qtbot, tmp_path):
    from amenhotep.gui.main_window import MainWindow

    path = tmp_path / "w.db"
    conn = db.connect(path)
    repo = Repository(conn)
    service(repo)[0].watch(NET)
    service(repo, online=(11,))[0].watch(NET)
    conn.close()
    w = MainWindow(path)
    qtbot.addWidget(w)
    from tests.test_gui import COL, select_row_with_ip

    assert COL["Status"] is not None
    states = {
        w.devices.proxy.index(r, COL["IP"]).data(): w.devices.proxy.index(r, COL["Status"]).data()
        for r in range(w.devices.proxy.rowCount())
    }
    assert states == {"192.0.2.10": "offline", "192.0.2.11": "online"}
    select_row_with_ip(w.devices, "192.0.2.10")
    assert "seen in 1 of 2 checks" in w.devices.detail.presence.text()


def test_scans_from_before_presence_tracking_are_not_counted_as_checks(repo):
    old = repo.start_scan("standard", "192.0.2.0/24")  # an old scan: nothing was logged for it
    repo.finish_scan(old, "done")
    service(repo)[0].watch(NET)
    assert len(repo.scan_times()) == 1
