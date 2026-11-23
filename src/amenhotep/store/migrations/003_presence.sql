-- Presence history: which devices were seen in which scan, and when a device was last probed.
CREATE TABLE sighting (
    device_uuid  TEXT NOT NULL REFERENCES device(uuid) ON DELETE CASCADE,
    scan_id      INTEGER NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    ts           TEXT NOT NULL,
    PRIMARY KEY (device_uuid, scan_id)
);
CREATE INDEX idx_sighting_ts ON sighting(ts);

ALTER TABLE device ADD COLUMN last_probed TEXT;  -- last full fingerprint attempt (nmap -sV/-O)

-- Devices that already exist went through full scans: do not re-fingerprint them all at once.
UPDATE device SET last_probed = last_seen;
