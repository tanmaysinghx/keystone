-- Operational features: master-key verification, token IP allow-lists, protected environments
-- with two-person change approval, and console-managed settings (alert webhook).

-- `kek_check`: a known value sealed by the master key, so a wrong key is caught at startup.
CREATE TABLE vault_meta (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

-- Comma-separated CIDRs (10.0.0.0/8,2001:db8::/32). NULL: any address.
ALTER TABLE vault_tokens ADD COLUMN allowed_cidrs TEXT;

-- Writes to a protected environment become change requests another administrator approves.
ALTER TABLE vault_environments ADD COLUMN protected INTEGER NOT NULL DEFAULT 0;

CREATE TABLE vault_change_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Random reference bound into the payload's associated data.
    ref TEXT NOT NULL UNIQUE,
    app_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    operation TEXT NOT NULL CHECK (operation IN ('put', 'delete', 'import')),
    kind TEXT NOT NULL CHECK (kind IN ('key', 'file')),
    name TEXT NOT NULL,
    -- Proposed content, sealed with the application's data key. NULL for deletes.
    payload BLOB,
    content_type TEXT NOT NULL DEFAULT 'text/plain',
    summary TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'applied', 'rejected', 'cancelled')),
    decided_by TEXT,
    decided_at INTEGER,
    note TEXT,
    FOREIGN KEY (app_id, environment) REFERENCES vault_environments(app_id, name) ON DELETE CASCADE
);
CREATE INDEX vault_change_requests_pending ON vault_change_requests(status, app_id);

-- Values sealed by the master key (they may be credentials, e.g. a Slack webhook URL).
CREATE TABLE vault_settings (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
