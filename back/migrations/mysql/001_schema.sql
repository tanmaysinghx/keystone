-- Keystone Vault schema for MySQL 8.0+ (and MariaDB 10.6+), equivalent to the SQLite migrations
-- 001-005. Text that is compared or indexed uses binary collation, so key names stay
-- case-sensitive exactly as on SQLite. Integers are BIGINT and text VARCHAR, which is what the
-- database-agnostic driver decodes.

CREATE TABLE reactions (
    slug VARCHAR(100) NOT NULL,
    visitor VARCHAR(64) NOT NULL,
    action VARCHAR(8) NOT NULL,
    bucket VARCHAR(16) NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (slug, visitor, action, bucket),
    INDEX reactions_by_post (slug, action)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE audit_events (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    subject VARCHAR(320) NOT NULL,
    event VARCHAR(64) NOT NULL,
    created_at BIGINT NOT NULL,
    target VARCHAR(1024) NULL,
    ip VARCHAR(64) NULL,
    user_agent VARCHAR(256) NULL,
    INDEX audit_events_by_time (created_at),
    INDEX audit_events_by_event (event)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE vault_apps (
    id VARCHAR(63) NOT NULL PRIMARY KEY,
    name VARCHAR(80) NOT NULL,
    description VARCHAR(500) NOT NULL DEFAULT '',
    portal_client_id VARCHAR(63) NULL,
    wrapped_key VARBINARY(128) NOT NULL,
    created_by VARCHAR(320) NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE vault_environments (
    app_id VARCHAR(63) NOT NULL,
    name VARCHAR(40) NOT NULL,
    created_at BIGINT NOT NULL,
    protected BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (app_id, name),
    FOREIGN KEY (app_id) REFERENCES vault_apps(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE vault_items (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    app_id VARCHAR(63) NOT NULL,
    environment VARCHAR(40) NOT NULL,
    kind VARCHAR(8) NOT NULL,
    name VARCHAR(200) NOT NULL,
    current_version BIGINT NOT NULL,
    content_type VARCHAR(100) NOT NULL DEFAULT 'text/plain',
    updated_by VARCHAR(512) NOT NULL,
    updated_at BIGINT NOT NULL,
    UNIQUE KEY vault_items_location (app_id, environment, kind, name),
    FOREIGN KEY (app_id, environment) REFERENCES vault_environments(app_id, name) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE vault_versions (
    item_id BIGINT NOT NULL,
    version BIGINT NOT NULL,
    ciphertext LONGBLOB NOT NULL,
    size BIGINT NOT NULL,
    created_by VARCHAR(512) NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (item_id, version),
    FOREIGN KEY (item_id) REFERENCES vault_items(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE vault_tokens (
    id VARCHAR(16) NOT NULL PRIMARY KEY,
    app_id VARCHAR(63) NOT NULL,
    environment VARCHAR(40) NOT NULL,
    name VARCHAR(80) NOT NULL,
    secret_hash VARBINARY(32) NOT NULL,
    created_by VARCHAR(320) NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NULL,
    last_used_at BIGINT NULL,
    revoked_at BIGINT NULL,
    allowed_cidrs VARCHAR(2048) NULL,
    INDEX vault_tokens_by_app (app_id),
    FOREIGN KEY (app_id, environment) REFERENCES vault_environments(app_id, name) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE vault_meta (
    `key` VARCHAR(64) NOT NULL PRIMARY KEY,
    value VARBINARY(256) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE vault_change_requests (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ref VARCHAR(36) NOT NULL UNIQUE,
    app_id VARCHAR(63) NOT NULL,
    environment VARCHAR(40) NOT NULL,
    operation VARCHAR(8) NOT NULL,
    kind VARCHAR(8) NOT NULL,
    name VARCHAR(200) NOT NULL,
    payload LONGBLOB NULL,
    content_type VARCHAR(100) NOT NULL DEFAULT 'text/plain',
    summary VARCHAR(500) NOT NULL,
    requested_by VARCHAR(320) NOT NULL,
    created_at BIGINT NOT NULL,
    status VARCHAR(12) NOT NULL DEFAULT 'pending',
    decided_by VARCHAR(320) NULL,
    decided_at BIGINT NULL,
    note VARCHAR(500) NULL,
    INDEX vault_change_requests_pending (status, app_id),
    FOREIGN KEY (app_id, environment) REFERENCES vault_environments(app_id, name) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE vault_settings (
    `key` VARCHAR(64) NOT NULL PRIMARY KEY,
    value VARBINARY(2048) NOT NULL,
    updated_by VARCHAR(320) NOT NULL,
    updated_at BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE keystone_state (
    name VARCHAR(64) NOT NULL PRIMARY KEY,
    value VARCHAR(2048) NOT NULL,
    updated_at BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE local_users (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(254) NOT NULL UNIQUE,
    name VARCHAR(120) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    roles VARCHAR(2048) NOT NULL DEFAULT '',
    disabled BIGINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    last_login_at BIGINT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;

CREATE TABLE local_sessions (
    token_hash VARCHAR(64) NOT NULL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    ip VARCHAR(64) NULL,
    user_agent VARCHAR(256) NULL,
    INDEX local_sessions_by_user (user_id),
    FOREIGN KEY (user_id) REFERENCES local_users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
