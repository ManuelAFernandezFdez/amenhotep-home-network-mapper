-- M6: topology. Switch/AP port count (shown as slots); the link table exists since 001.
ALTER TABLE device ADD COLUMN ports INTEGER;
