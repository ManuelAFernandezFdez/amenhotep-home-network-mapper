-- Amenhotep SQLite schema, version 1
PRAGMA foreign_keys = ON;
PRAGMA user_version = 1;

CREATE TABLE area (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('zone','room')),
    parent_id   INTEGER REFERENCES area(id) ON DELETE SET NULL,
    house_ref   TEXT,                       -- room/outdoor id in house.json
    UNIQUE (kind, name)
);

CREATE TABLE device (
    uuid               TEXT PRIMARY KEY,
    display_name       TEXT,
    device_type        TEXT NOT NULL DEFAULT 'unknown',
    os_family          TEXT NOT NULL DEFAULT 'unknown'
        CHECK (os_family IN ('linux','windows','ios','ipados','macos','tvos','android','embedded','unknown')),
    os_detail          TEXT,
    vendor             TEXT,
    model              TEXT,
    hardware_notes     TEXT,
    location_mode      TEXT NOT NULL DEFAULT 'fixed' CHECK (location_mode IN ('fixed','roaming')),
    area_id            INTEGER REFERENCES area(id) ON DELETE SET NULL,
    is_infrastructure  INTEGER NOT NULL DEFAULT 0,
    locked_fields      TEXT NOT NULL DEFAULT '[]',   -- JSON array of user-edited columns
    notes              TEXT,
    first_seen         TEXT NOT NULL,
    last_seen          TEXT
);

CREATE TABLE interface (
    id           INTEGER PRIMARY KEY,
    device_uuid  TEXT NOT NULL REFERENCES device(uuid) ON DELETE CASCADE,
    mac          TEXT,
    mac_random   INTEGER NOT NULL DEFAULT 0,
    ip           TEXT,
    hostname     TEXT,
    medium       TEXT NOT NULL DEFAULT 'wired' CHECK (medium IN ('wired','wifi','unknown')),
    last_seen    TEXT,
    UNIQUE (mac)
);
CREATE INDEX idx_interface_ip ON interface(ip);
CREATE INDEX idx_interface_device ON interface(device_uuid);

CREATE TABLE link (
    id           INTEGER PRIMARY KEY,
    child_uuid   TEXT NOT NULL REFERENCES device(uuid) ON DELETE CASCADE,
    parent_uuid  TEXT NOT NULL REFERENCES device(uuid) ON DELETE CASCADE,
    port_label   TEXT,                -- "Gi0/5", "port 3", or "SSID/5GHz"
    medium       TEXT NOT NULL DEFAULT 'wired' CHECK (medium IN ('wired','wifi')),
    rssi         INTEGER,
    source       TEXT NOT NULL CHECK (source IN ('manual','snmp','lldp','api','inferred')),
    confirmed    INTEGER NOT NULL DEFAULT 0,
    last_seen    TEXT,
    CHECK (child_uuid <> parent_uuid),
    UNIQUE (child_uuid)               -- one uplink per device
);

CREATE TABLE homekit_accessory (
    device_uuid  TEXT PRIMARY KEY REFERENCES device(uuid) ON DELETE CASCADE,
    hap_id       TEXT UNIQUE,         -- "id" TXT record (AA:BB:CC:DD:EE:FF form)
    category_id  INTEGER,             -- "ci"
    model        TEXT,                -- "md"
    paired       INTEGER,             -- derived from "sf" (0 = paired)
    config_num   INTEGER,             -- "c#"
    protocol     TEXT NOT NULL DEFAULT 'hap' CHECK (protocol IN ('hap','matter'))
);

CREATE TABLE evidence (
    id           INTEGER PRIMARY KEY,
    device_uuid  TEXT NOT NULL REFERENCES device(uuid) ON DELETE CASCADE,
    field        TEXT NOT NULL,       -- os_family | device_type | vendor | model
    value        TEXT NOT NULL,
    confidence   REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    source       TEXT NOT NULL,       -- nmap | mdns | ssdp | oui | ttl | rule:<id> | manual
    detail       TEXT,
    seen_at      TEXT NOT NULL
);
CREATE INDEX idx_evidence_device ON evidence(device_uuid, field);

CREATE TABLE scan (
    id        INTEGER PRIMARY KEY,
    started   TEXT NOT NULL,
    finished  TEXT,
    profile   TEXT NOT NULL,          -- quick | standard | deep
    target    TEXT NOT NULL,          -- CIDR(s)
    status    TEXT NOT NULL CHECK (status IN ('running','done','cancelled','failed'))
);

CREATE TABLE observation (
    id          INTEGER PRIMARY KEY,
    scan_id     INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    source      TEXT NOT NULL,
    ip          TEXT,
    mac         TEXT,
    facts_json  TEXT NOT NULL DEFAULT '{}',
    ts          TEXT NOT NULL
);
CREATE INDEX idx_observation_scan ON observation(scan_id);

-- Default zones and rooms
INSERT INTO area (id, name, kind, parent_id, house_ref) VALUES
 (1,'Ground floor','zone',NULL,'ground'),
 (2,'First floor','zone',NULL,'first'),
 (3,'Second floor','zone',NULL,'second'),
 (4,'Garden','zone',NULL,'garden'),
 (5,'Veranda','zone',NULL,'veranda'),
 (6,'Roaming','zone',NULL,NULL),
 (10,'Kitchen','room',1,'kitchen'),
 (11,'Living room','room',1,'living'),
 (12,'Main bedroom','room',2,'main_bedroom'),
 (13,'Secondary bedroom','room',2,'secondary_bedroom'),
 (14,'Third bedroom','room',2,'third_bedroom'),
 (15,'Second-floor bedroom','room',3,'second_floor_bedroom');
