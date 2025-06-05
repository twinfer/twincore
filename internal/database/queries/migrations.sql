-- Database Migration Queries

-- name: CreateMigrationTable
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    checksum TEXT
);

-- name: GetAppliedMigrations
SELECT version, description, applied_at, checksum
FROM schema_migrations
ORDER BY version;

-- name: GetLatestMigrationVersion
SELECT COALESCE(MAX(version), 0) FROM schema_migrations;

-- name: InsertMigration
INSERT INTO schema_migrations (version, description, applied_at, checksum)
VALUES (?, ?, CURRENT_TIMESTAMP, ?);

-- name: MigrationExists
SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = ?);

-- Initial Schema Creation (Migration Version 1)
-- name: CreateInitialSchema
-- This will be managed by the migration system

-- Schema Version Information
-- name: GetSchemaVersion
PRAGMA user_version;

-- name: SetSchemaVersion
PRAGMA user_version = ?;

-- Database Health and Maintenance
-- name: AnalyzeDatabase
ANALYZE;

-- name: VacuumDatabase
VACUUM;

-- name: CheckDatabaseIntegrity
PRAGMA integrity_check;

-- name: GetDatabaseSize
SELECT 
    page_count * page_size as total_size,
    page_count,
    page_size
FROM pragma_page_count(), pragma_page_size();

-- name: GetTableSizes
SELECT 
    name as table_name,
    COUNT(*) as row_count
FROM sqlite_master 
WHERE type = 'table' 
GROUP BY name
ORDER BY name;