-- M7: Thread/Matter devices without a LAN host can be placed on the plan too.
CREATE TABLE plan_matter_placement (
    instance TEXT PRIMARY KEY REFERENCES matter_node(instance) ON DELETE CASCADE,
    level_id TEXT NOT NULL REFERENCES plan_level(id) ON DELETE CASCADE,
    x REAL NOT NULL, y REAL NOT NULL
);
