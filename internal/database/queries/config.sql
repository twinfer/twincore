-- Configuration Management Queries

-- name: CreateConfigTables
CREATE TABLE IF NOT EXISTS configs (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    data TEXT NOT NULL,
    version INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS caddy_configs (
    id INTEGER PRIMARY KEY,
    config TEXT NOT NULL,
    patches TEXT,
    version INTEGER NOT NULL,
    active INTEGER DEFAULT 0 CHECK(active IN (0, 1)),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- name: CreateConfigIndexes
CREATE INDEX IF NOT EXISTS idx_configs_type ON configs(type);
CREATE INDEX IF NOT EXISTS idx_configs_updated ON configs(updated_at);
CREATE INDEX IF NOT EXISTS idx_caddy_active ON caddy_configs(active);
CREATE INDEX IF NOT EXISTS idx_caddy_version ON caddy_configs(version);

-- General Configuration Queries
-- name: UpsertConfig
INSERT INTO configs (id, type, data, version, created_at, updated_at)
VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT(id) DO UPDATE SET
    type = excluded.type,
    data = excluded.data,
    version = version + 1,
    updated_at = excluded.updated_at;

-- name: GetConfig
SELECT id, type, data, version, created_at, updated_at
FROM configs
WHERE id = ?;

-- name: GetConfigsByType
SELECT id, type, data, version, created_at, updated_at
FROM configs
WHERE type = ?
ORDER BY updated_at DESC;

-- name: DeleteConfig
DELETE FROM configs WHERE id = ?;

-- name: ListAllConfigs
SELECT id, type, data, version, created_at, updated_at
FROM configs
ORDER BY type, updated_at DESC;

-- name: ConfigExists
SELECT EXISTS(SELECT 1 FROM configs WHERE id = ?);

-- Caddy Configuration Queries
-- name: InsertCaddyConfig
INSERT INTO caddy_configs (config, patches, version, active, created_at)
VALUES (?, ?, ?, 0, CURRENT_TIMESTAMP);

-- name: GetActiveCaddyConfig
SELECT id, config, patches, version, active, created_at
FROM caddy_configs
WHERE active = 1
ORDER BY version DESC
LIMIT 1;

-- name: GetCaddyConfigByVersion
SELECT id, config, patches, version, active, created_at
FROM caddy_configs
WHERE version = ?;

-- name: SetActiveCaddyConfig
UPDATE caddy_configs SET active = 0 WHERE active = 1;
UPDATE caddy_configs SET active = 1 WHERE version = ?;

-- name: ListCaddyConfigs
SELECT id, config, patches, version, active, created_at
FROM caddy_configs
ORDER BY version DESC;

-- name: DeleteOldCaddyConfigs
DELETE FROM caddy_configs 
WHERE active = 0 AND version < (
    SELECT MAX(version) - ? FROM caddy_configs
);

-- name: GetLatestCaddyConfigVersion
SELECT COALESCE(MAX(version), 0) FROM caddy_configs;

-- name: CountCaddyConfigs
SELECT COUNT(*) FROM caddy_configs;

-- Stream Configuration Storage (Benthos-specific)
-- name: UpsertStreamConfig
INSERT INTO configs (id, type, data, version, created_at, updated_at)
VALUES (?, 'benthos_stream', ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT(id) DO UPDATE SET
    data = excluded.data,
    version = version + 1,
    updated_at = excluded.updated_at;

-- name: GetBenthosStreamConfig
SELECT id, data, version, created_at, updated_at
FROM configs
WHERE id = ? AND type = 'benthos_stream';

-- name: DeleteBenthosStreamConfig
DELETE FROM configs WHERE id = ? AND type = 'benthos_stream';

-- name: ListStreamConfigs
SELECT id, data, version, created_at, updated_at
FROM configs
WHERE type = 'benthos_stream'
ORDER BY updated_at DESC;

-- Application Settings
-- name: UpsertAppSetting
INSERT INTO configs (id, type, data, version, created_at, updated_at)
VALUES (?, 'app_setting', ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT(id) DO UPDATE SET
    data = excluded.data,
    version = version + 1,
    updated_at = excluded.updated_at;

-- name: GetAppSetting
SELECT data FROM configs
WHERE id = ? AND type = 'app_setting';

-- name: ListAppSettings
SELECT id, data, version, created_at, updated_at
FROM configs
WHERE type = 'app_setting'
ORDER BY id;