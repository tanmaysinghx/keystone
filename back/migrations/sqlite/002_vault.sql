-- Keystone Vault: per-application secrets and configuration files, versioned and encrypted.
-- An application id is its Portal SSO client_id, so Portal and Keystone name apps the same way.
CREATE TABLE vault_apps (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    portal_client_id TEXT,
    -- Application data key, AES-256-GCM wrapped by KEYSTONE_MASTER_KEY.
    wrapped_key BLOB NOT NULL,
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Environments behave like Spring profiles. Every app has `default`, which other environments
-- inherit from and override.
CREATE TABLE vault_environments (
    app_id TEXT NOT NULL REFERENCES vault_apps(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (app_id, name)
);

-- kind 'key': one property (spring.datasource.password = ...).
-- kind 'file': a whole file (application.properties, keystore.p12, service-account.json ...).
CREATE TABLE vault_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    app_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('key', 'file')),
    name TEXT NOT NULL,
    current_version INTEGER NOT NULL,
    content_type TEXT NOT NULL DEFAULT 'text/plain',
    updated_by TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    UNIQUE (app_id, environment, kind, name),
    FOREIGN KEY (app_id, environment) REFERENCES vault_environments(app_id, name) ON DELETE CASCADE
);

CREATE TABLE vault_versions (
    item_id INTEGER NOT NULL REFERENCES vault_items(id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    ciphertext BLOB NOT NULL,
    size INTEGER NOT NULL,
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (item_id, version)
);

-- Read-only machine credentials an application presents at startup.
CREATE TABLE vault_tokens (
    id TEXT PRIMARY KEY,
    app_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    name TEXT NOT NULL,
    secret_hash BLOB NOT NULL,
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    expires_at INTEGER,
    last_used_at INTEGER,
    revoked_at INTEGER,
    FOREIGN KEY (app_id, environment) REFERENCES vault_environments(app_id, name) ON DELETE CASCADE
);
CREATE INDEX vault_tokens_by_app ON vault_tokens(app_id);

ALTER TABLE audit_events ADD COLUMN target TEXT;
CREATE INDEX audit_events_by_time ON audit_events(created_at);
