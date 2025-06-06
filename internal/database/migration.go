package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

// MigrationManager handles database schema migrations
type MigrationManager struct {
	manager    *Manager
	logger     *logrus.Logger
	migrations []Migration
}

// Migration represents a single database migration
type Migration struct {
	Version     int
	Description string
	Up          string
	Down        string
	Checksum    string
}

// NewMigrationManager creates a new migration manager
func NewMigrationManager(manager *Manager, logger *logrus.Logger) *MigrationManager {
	mm := &MigrationManager{
		manager: manager,
		logger:  logger,
	}
	mm.loadMigrations()
	return mm
}

// loadMigrations defines all database migrations
func (mm *MigrationManager) loadMigrations() {
	mm.migrations = []Migration{
		{
			Version:     1,
			Description: "Create initial schema",
			Up: `
-- Create configs table
CREATE TABLE IF NOT EXISTS configs (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    data TEXT NOT NULL,
    version INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create things table
CREATE TABLE IF NOT EXISTS things (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    td_jsonld TEXT NOT NULL,
    td_parsed TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create caddy_configs table
CREATE TABLE IF NOT EXISTS caddy_configs (
    id INTEGER PRIMARY KEY,
    config TEXT NOT NULL,
    patches TEXT,
    version INTEGER NOT NULL,
    active BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create basic indexes
CREATE INDEX IF NOT EXISTS idx_configs_type ON configs(type);
CREATE INDEX IF NOT EXISTS idx_configs_updated ON configs(updated_at);
CREATE INDEX IF NOT EXISTS idx_things_updated ON things(updated_at);
CREATE INDEX IF NOT EXISTS idx_things_title ON things(title);
CREATE INDEX IF NOT EXISTS idx_caddy_active ON caddy_configs(active);
CREATE INDEX IF NOT EXISTS idx_caddy_version ON caddy_configs(version);
`,
			Down: `
DROP INDEX IF EXISTS idx_caddy_version;
DROP INDEX IF EXISTS idx_caddy_active;
DROP INDEX IF EXISTS idx_things_title;
DROP INDEX IF EXISTS idx_things_updated;
DROP INDEX IF EXISTS idx_configs_updated;
DROP INDEX IF EXISTS idx_configs_type;
DROP TABLE IF EXISTS caddy_configs;
DROP TABLE IF EXISTS things;
DROP TABLE IF EXISTS configs;
`,
		},
		{
			Version:     2,
			Description: "Add stream management tables",
			Up: `
-- Create stream_configs table
CREATE TABLE IF NOT EXISTS stream_configs (
    stream_id TEXT PRIMARY KEY,
    thing_id TEXT NOT NULL,
    interaction_type TEXT NOT NULL,
    interaction_name TEXT NOT NULL,
    direction TEXT NOT NULL,
    input_config TEXT NOT NULL,
    output_config TEXT NOT NULL,
    processor_chain TEXT,
    status TEXT DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata TEXT,
    config_yaml TEXT,
    validation_error TEXT
);

-- Create property_state table
CREATE TABLE IF NOT EXISTS property_state (
    thing_id TEXT NOT NULL,
    property_name TEXT NOT NULL,
    value TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (thing_id, property_name)
);

-- Create action_state table
CREATE TABLE IF NOT EXISTS action_state (
    action_id TEXT PRIMARY KEY,
    thing_id TEXT NOT NULL,
    action_name TEXT NOT NULL,
    input TEXT,
    output TEXT,
    status TEXT DEFAULT 'pending',
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    error TEXT
);

-- Create stream indexes
CREATE INDEX IF NOT EXISTS idx_streams_thing_id ON stream_configs(thing_id);
CREATE INDEX IF NOT EXISTS idx_streams_status ON stream_configs(status);
CREATE INDEX IF NOT EXISTS idx_streams_interaction ON stream_configs(interaction_type, interaction_name);
CREATE INDEX IF NOT EXISTS idx_streams_updated ON stream_configs(updated_at);

-- Create state indexes
CREATE INDEX IF NOT EXISTS idx_property_thing ON property_state(thing_id);
CREATE INDEX IF NOT EXISTS idx_property_updated ON property_state(updated_at);
CREATE INDEX IF NOT EXISTS idx_action_thing ON action_state(thing_id);
CREATE INDEX IF NOT EXISTS idx_action_status ON action_state(status);
CREATE INDEX IF NOT EXISTS idx_action_started ON action_state(started_at);
`,
			Down: `
DROP INDEX IF EXISTS idx_action_started;
DROP INDEX IF EXISTS idx_action_status;
DROP INDEX IF EXISTS idx_action_thing;
DROP INDEX IF EXISTS idx_property_updated;
DROP INDEX IF EXISTS idx_property_thing;
DROP INDEX IF EXISTS idx_streams_updated;
DROP INDEX IF EXISTS idx_streams_interaction;
DROP INDEX IF EXISTS idx_streams_status;
DROP INDEX IF EXISTS idx_streams_thing_id;
DROP TABLE IF EXISTS action_state;
DROP TABLE IF EXISTS property_state;
DROP TABLE IF EXISTS stream_configs;
`,
		},
		{
			Version:     3,
			Description: "Add security tables",
			Up: `
-- Create local_users table
CREATE TABLE IF NOT EXISTS local_users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    roles TEXT NOT NULL,
    email TEXT,
    name TEXT,
    disabled BOOLEAN DEFAULT FALSE,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create user_sessions table
CREATE TABLE IF NOT EXISTS user_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    username TEXT NOT NULL,
    token TEXT NOT NULL,
    refresh_token TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT,
    user_agent TEXT
);

-- Create thing_security_policies table
CREATE TABLE IF NOT EXISTS thing_security_policies (
    thing_id TEXT PRIMARY KEY,
    policy_data TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create device_credentials table
CREATE TABLE IF NOT EXISTS device_credentials (
    credential_key TEXT PRIMARY KEY,
    credentials_data TEXT NOT NULL,
    encrypted BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create security_templates table
CREATE TABLE IF NOT EXISTS security_templates (
    name TEXT PRIMARY KEY,
    template_data TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create api_policies table
CREATE TABLE IF NOT EXISTS api_policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    principal TEXT,
    resources TEXT,
    actions TEXT,
    conditions TEXT,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create security_audit_events table
CREATE TABLE IF NOT EXISTS security_audit_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id TEXT,
    thing_id TEXT,
    operation TEXT,
    resource TEXT,
    success BOOLEAN,
    error TEXT,
    ip_address TEXT,
    user_agent TEXT,
    details TEXT
);

-- Create security indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON local_users(email);
CREATE INDEX IF NOT EXISTS idx_users_updated ON local_users(updated_at);
CREATE INDEX IF NOT EXISTS idx_sessions_username ON user_sessions(username);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(token);
CREATE INDEX IF NOT EXISTS idx_policies_enabled ON api_policies(enabled);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON security_audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_user ON security_audit_events(user_id);
`,
			Down: `
DROP INDEX IF EXISTS idx_audit_user;
DROP INDEX IF EXISTS idx_audit_timestamp;
DROP INDEX IF EXISTS idx_policies_enabled;
DROP INDEX IF EXISTS idx_sessions_token;
DROP INDEX IF EXISTS idx_sessions_expires;
DROP INDEX IF EXISTS idx_sessions_username;
DROP INDEX IF EXISTS idx_users_updated;
DROP INDEX IF EXISTS idx_users_email;
DROP TABLE IF EXISTS security_audit_events;
DROP TABLE IF EXISTS api_policies;
DROP TABLE IF EXISTS security_templates;
DROP TABLE IF EXISTS device_credentials;
DROP TABLE IF EXISTS thing_security_policies;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS local_users;
`,
		},
	}

	// Calculate checksums for all migrations
	for i := range mm.migrations {
		mm.migrations[i].Checksum = mm.calculateChecksum(mm.migrations[i].Up)
	}
}

// RunMigrations executes all pending migrations
func (mm *MigrationManager) RunMigrations(ctx context.Context) error {
	// Ensure migration table exists
	if err := mm.createMigrationTable(ctx); err != nil {
		return fmt.Errorf("failed to create migration table: %w", err)
	}

	// Get current migration version
	currentVersion, err := mm.getCurrentVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current migration version: %w", err)
	}

	// Find migrations to apply
	pendingMigrations := mm.getPendingMigrations(currentVersion)
	if len(pendingMigrations) == 0 {
		mm.logger.Info("No pending migrations")
		return nil
	}

	mm.logger.WithFields(logrus.Fields{
		"current_version": currentVersion,
		"pending_count":   len(pendingMigrations),
		"target_version":  pendingMigrations[len(pendingMigrations)-1].Version,
	}).Info("Starting database migrations")

	// Apply migrations
	for _, migration := range pendingMigrations {
		if err := mm.applyMigration(ctx, migration); err != nil {
			return fmt.Errorf("failed to apply migration %d: %w", migration.Version, err)
		}
	}

	mm.logger.WithField("new_version", pendingMigrations[len(pendingMigrations)-1].Version).Info("Migrations completed successfully")
	return nil
}

// createMigrationTable creates the migration tracking table
func (mm *MigrationManager) createMigrationTable(ctx context.Context) error {
	query := `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    checksum TEXT
);`

	_, err := mm.manager.db.ExecContext(ctx, query)
	return err
}

// getCurrentVersion gets the current migration version
func (mm *MigrationManager) getCurrentVersion(ctx context.Context) (int, error) {
	query := "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"

	var version int
	err := mm.manager.db.QueryRowContext(ctx, query).Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("failed to get current version: %w", err)
	}

	return version, nil
}

// getPendingMigrations returns migrations that need to be applied
func (mm *MigrationManager) getPendingMigrations(currentVersion int) []Migration {
	var pending []Migration
	for _, migration := range mm.migrations {
		if migration.Version > currentVersion {
			pending = append(pending, migration)
		}
	}
	return pending
}

// applyMigration applies a single migration
func (mm *MigrationManager) applyMigration(ctx context.Context, migration Migration) error {
	mm.logger.WithFields(logrus.Fields{
		"version":     migration.Version,
		"description": migration.Description,
	}).Info("Applying migration")

	start := time.Now()

	// Use transaction to ensure atomicity
	err := mm.manager.Transaction(ctx, func(tx *sql.Tx) error {
		// Execute migration SQL
		if _, err := tx.ExecContext(ctx, migration.Up); err != nil {
			return fmt.Errorf("failed to execute migration SQL: %w", err)
		}

		// Record migration as applied
		insertQuery := `
INSERT INTO schema_migrations (version, description, applied_at, checksum)
VALUES (?, ?, CURRENT_TIMESTAMP, ?)`

		if _, err := tx.ExecContext(ctx, insertQuery, migration.Version, migration.Description, migration.Checksum); err != nil {
			return fmt.Errorf("failed to record migration: %w", err)
		}

		return nil
	})

	if err != nil {
		return err
	}

	mm.logger.WithFields(logrus.Fields{
		"version":  migration.Version,
		"duration": time.Since(start),
	}).Info("Migration applied successfully")

	return nil
}

// RollbackMigration rolls back the last applied migration
func (mm *MigrationManager) RollbackMigration(ctx context.Context) error {
	// Get current version
	currentVersion, err := mm.getCurrentVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	if currentVersion == 0 {
		return fmt.Errorf("no migrations to rollback")
	}

	// Find migration to rollback
	var migrationToRollback *Migration
	for _, migration := range mm.migrations {
		if migration.Version == currentVersion {
			migrationToRollback = &migration
			break
		}
	}

	if migrationToRollback == nil {
		return fmt.Errorf("migration %d not found", currentVersion)
	}

	mm.logger.WithFields(logrus.Fields{
		"version":     migrationToRollback.Version,
		"description": migrationToRollback.Description,
	}).Warn("Rolling back migration")

	// Execute rollback in transaction
	err = mm.manager.Transaction(ctx, func(tx *sql.Tx) error {
		// Execute rollback SQL
		if _, err := tx.ExecContext(ctx, migrationToRollback.Down); err != nil {
			return fmt.Errorf("failed to execute rollback SQL: %w", err)
		}

		// Remove migration record
		deleteQuery := "DELETE FROM schema_migrations WHERE version = ?"
		if _, err := tx.ExecContext(ctx, deleteQuery, migrationToRollback.Version); err != nil {
			return fmt.Errorf("failed to remove migration record: %w", err)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}

	mm.logger.WithField("version", migrationToRollback.Version).Info("Migration rolled back successfully")
	return nil
}

// GetMigrationStatus returns the status of all migrations
func (mm *MigrationManager) GetMigrationStatus(ctx context.Context) ([]MigrationStatus, error) {
	// Get applied migrations
	appliedQuery := "SELECT version, description, applied_at, checksum FROM schema_migrations ORDER BY version"
	rows, err := mm.manager.db.QueryContext(ctx, appliedQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to query applied migrations: %w", err)
	}
	defer rows.Close()

	appliedMap := make(map[int]MigrationStatus)
	for rows.Next() {
		var status MigrationStatus
		err := rows.Scan(&status.Version, &status.Description, &status.AppliedAt, &status.Checksum)
		if err != nil {
			return nil, fmt.Errorf("failed to scan migration: %w", err)
		}
		status.Applied = true
		appliedMap[status.Version] = status
	}

	// Build complete status list
	var statuses []MigrationStatus
	for _, migration := range mm.migrations {
		if applied, exists := appliedMap[migration.Version]; exists {
			// Check if checksum matches
			applied.ChecksumMatch = applied.Checksum == migration.Checksum
			statuses = append(statuses, applied)
		} else {
			statuses = append(statuses, MigrationStatus{
				Version:       migration.Version,
				Description:   migration.Description,
				Applied:       false,
				ChecksumMatch: true, // Not applicable for unapplied migrations
			})
		}
	}

	return statuses, nil
}

// MigrationStatus represents the status of a migration
type MigrationStatus struct {
	Version       int
	Description   string
	Applied       bool
	AppliedAt     *time.Time
	Checksum      string
	ChecksumMatch bool
}

// calculateChecksum generates a checksum for migration content
func (mm *MigrationManager) calculateChecksum(content string) string {
	hash := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", hash)
}

// ValidateMigrations checks if applied migrations match expected checksums
func (mm *MigrationManager) ValidateMigrations(ctx context.Context) error {
	statuses, err := mm.GetMigrationStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to get migration status: %w", err)
	}

	var invalidMigrations []int
	for _, status := range statuses {
		if status.Applied && !status.ChecksumMatch {
			invalidMigrations = append(invalidMigrations, status.Version)
		}
	}

	if len(invalidMigrations) > 0 {
		return fmt.Errorf("invalid migration checksums for versions: %v", invalidMigrations)
	}

	mm.logger.Info("All applied migrations have valid checksums")
	return nil
}

// GetCurrentVersion returns the current migration version
func (mm *MigrationManager) GetCurrentVersion(ctx context.Context) (int, error) {
	return mm.getCurrentVersion(ctx)
}
