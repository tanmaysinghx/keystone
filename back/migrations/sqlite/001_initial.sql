CREATE TABLE IF NOT EXISTS reactions (
    slug TEXT NOT NULL,
    visitor TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('like', 'view')),
    bucket TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (slug, visitor, action, bucket)
);
CREATE INDEX reactions_by_post ON reactions(slug, action);
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject TEXT NOT NULL,
    event TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
