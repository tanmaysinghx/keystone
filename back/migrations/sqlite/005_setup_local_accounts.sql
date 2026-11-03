-- First-run setup state (license acceptance, completion) and local accounts for running without
-- Portal SSO (or alongside it).
CREATE TABLE keystone_state (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE local_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Stored lower-case; sign-in is case-insensitive on the address.
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    -- Argon2id PHC string.
    password_hash TEXT NOT NULL,
    -- Comma-separated: ROLE_ADMIN and/or ROLE_VAULT_<APP>, the same names Portal SSO uses.
    roles TEXT NOT NULL DEFAULT '',
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    last_login_at INTEGER
);

CREATE TABLE local_sessions (
    -- SHA-256 of the session token; the token itself is never stored.
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES local_users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    ip TEXT,
    user_agent TEXT
);
CREATE INDEX local_sessions_by_user ON local_sessions(user_id);
