-- M5: Matter nodes (often IPv6-only, on Thread) and Thread border routers.
CREATE TABLE matter_node (
    instance     TEXT PRIMARY KEY,    -- "<compressed fabric id>-<node id>" from the _matter._tcp name
    fabric       TEXT NOT NULL,
    node         TEXT NOT NULL,
    addresses    TEXT NOT NULL DEFAULT '[]',   -- JSON array of IPv4/IPv6 strings
    host_uuid    TEXT REFERENCES device(uuid) ON DELETE SET NULL,  -- set when it is a known LAN host
    label        TEXT,                -- user-given name ("Kitchen plug 1"); never overwritten by scans
    area_id      INTEGER REFERENCES area(id) ON DELETE SET NULL,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL
);

CREATE TABLE thread_border_router (
    device_uuid  TEXT PRIMARY KEY REFERENCES device(uuid) ON DELETE CASCADE,
    network_name TEXT,                -- "nn"
    vendor       TEXT,                -- "vn"
    model        TEXT,                -- "mn"
    last_seen    TEXT NOT NULL
);
