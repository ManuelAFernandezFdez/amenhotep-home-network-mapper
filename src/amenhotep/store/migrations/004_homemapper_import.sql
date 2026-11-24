-- M5: import of HomeMapper (iPhone app) CSV exports.
ALTER TABLE device ADD COLUMN serial TEXT;               -- HomeKit serial number, a stable key
ALTER TABLE matter_node ADD COLUMN notes TEXT;           -- Thread/Matter details that have no column
ALTER TABLE thread_border_router ADD COLUMN notes TEXT;

CREATE TABLE import_log (
    id          INTEGER PRIMARY KEY,
    filename    TEXT NOT NULL,        -- base name of the imported file
    source      TEXT NOT NULL,        -- 'homemapper'
    imported_at TEXT NOT NULL,
    rows        INTEGER NOT NULL,
    matched     INTEGER NOT NULL,     -- rows merged into an existing device
    created     INTEGER NOT NULL,     -- rows that became new devices
    thread      INTEGER NOT NULL,     -- rows merged into a Matter/Thread node
    conflicts   INTEGER NOT NULL,     -- rows whose identity disagreed with the stored device
    detail      TEXT NOT NULL DEFAULT '[]'   -- JSON array of per-row messages
);
