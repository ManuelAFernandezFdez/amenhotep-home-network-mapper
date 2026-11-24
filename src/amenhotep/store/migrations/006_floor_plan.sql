-- M7: flat floor-plan view. Positions are fractions (0..1) of a level's rectangle, so changing
-- the level's size in metres never moves anything.
CREATE TABLE plan_level (
    id     TEXT PRIMARY KEY,                -- 'ground', 'first', 'second', 'back_garden', ...
    name   TEXT NOT NULL,
    kind   TEXT NOT NULL CHECK (kind IN ('floor','garden','roaming')),
    ord    INTEGER NOT NULL,                -- higher = physically higher; drives the selector
    width  REAL NOT NULL DEFAULT 10,        -- metres, informational
    depth  REAL NOT NULL DEFAULT 8
);

-- Which areas (zones) a level shows; a room belongs to the level of its zone.
CREATE TABLE plan_level_area (
    area_id  INTEGER PRIMARY KEY REFERENCES area(id) ON DELETE CASCADE,
    level_id TEXT NOT NULL REFERENCES plan_level(id) ON DELETE CASCADE
);

CREATE TABLE plan_room (
    area_id INTEGER PRIMARY KEY REFERENCES area(id) ON DELETE CASCADE,
    x REAL NOT NULL, y REAL NOT NULL, w REAL NOT NULL, h REAL NOT NULL
);

-- Manual device positions (a device without one is placed automatically inside its room).
CREATE TABLE plan_placement (
    device_uuid TEXT PRIMARY KEY REFERENCES device(uuid) ON DELETE CASCADE,
    level_id    TEXT NOT NULL REFERENCES plan_level(id) ON DELETE CASCADE,
    x REAL NOT NULL, y REAL NOT NULL
);

-- A wire passage between levels (cable duct, hole in a floor, stairwell): same x,y on each level.
CREATE TABLE plan_riser (
    id     INTEGER PRIMARY KEY,
    name   TEXT NOT NULL,
    x REAL NOT NULL, y REAL NOT NULL,
    levels TEXT NOT NULL DEFAULT '[]'       -- JSON array of level ids it passes through
);
