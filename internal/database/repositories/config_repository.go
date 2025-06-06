package repositories

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/database"
)

// ConfigRepository implements the ConfigRepositoryInterface
type ConfigRepository struct {
	dbManager database.DatabaseManager
	logger    logrus.FieldLogger
}

// NewConfigRepository creates a new ConfigRepository
func NewConfigRepository(dbManager database.DatabaseManager, logger logrus.FieldLogger) *ConfigRepository {
	return &ConfigRepository{
		dbManager: dbManager,
		logger:    logger,
	}
}

// IsHealthy checks if the repository is healthy
func (r *ConfigRepository) IsHealthy(ctx context.Context) bool {
	return r.dbManager.IsHealthy()
}

// General configuration methods

// UpsertConfig inserts or updates a configuration entry
func (r *ConfigRepository) UpsertConfig(ctx context.Context, id, configType, data string) error {
	result, err := r.dbManager.Execute(ctx, "UpsertConfig", id, configType, data, 1)
	if err != nil {
		return fmt.Errorf("failed to upsert config: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	r.logger.WithFields(logrus.Fields{
		"id":           id,
		"type":         configType,
		"rowsAffected": rows,
	}).Debug("Config upserted")

	return nil
}

// GetConfig retrieves a configuration entry by ID
func (r *ConfigRepository) GetConfig(ctx context.Context, id string) (*database.ConfigEntity, error) {
	row := r.dbManager.QueryRow(ctx, "GetConfig", id)

	var config database.ConfigEntity
	err := row.Scan(&config.ID, &config.Type, &config.Data, &config.Version, &config.CreatedAt, &config.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("config not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get config: %w", err)
	}

	return &config, nil
}

// GetConfigsByType retrieves all configurations of a specific type
func (r *ConfigRepository) GetConfigsByType(ctx context.Context, configType string) ([]*database.ConfigEntity, error) {
	rows, err := r.dbManager.Query(ctx, "GetConfigsByType", configType)
	if err != nil {
		return nil, fmt.Errorf("failed to get configs by type: %w", err)
	}
	defer rows.Close()

	var configs []*database.ConfigEntity
	for rows.Next() {
		var config database.ConfigEntity
		err := rows.Scan(&config.ID, &config.Type, &config.Data, &config.Version, &config.CreatedAt, &config.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan config: %w", err)
		}
		configs = append(configs, &config)
	}

	return configs, nil
}

// DeleteConfig deletes a configuration entry
func (r *ConfigRepository) DeleteConfig(ctx context.Context, id string) error {
	result, err := r.dbManager.Execute(ctx, "DeleteConfig", id)
	if err != nil {
		return fmt.Errorf("failed to delete config: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("config not found: %s", id)
	}

	r.logger.WithField("id", id).Debug("Config deleted")
	return nil
}

// ListAllConfigs retrieves all configuration entries
func (r *ConfigRepository) ListAllConfigs(ctx context.Context) ([]*database.ConfigEntity, error) {
	rows, err := r.dbManager.Query(ctx, "ListAllConfigs")
	if err != nil {
		return nil, fmt.Errorf("failed to list all configs: %w", err)
	}
	defer rows.Close()

	var configs []*database.ConfigEntity
	for rows.Next() {
		var config database.ConfigEntity
		err := rows.Scan(&config.ID, &config.Type, &config.Data, &config.Version, &config.CreatedAt, &config.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan config: %w", err)
		}
		configs = append(configs, &config)
	}

	return configs, nil
}

// ConfigExists checks if a configuration entry exists
func (r *ConfigRepository) ConfigExists(ctx context.Context, id string) (bool, error) {
	row := r.dbManager.QueryRow(ctx, "ConfigExists", id)

	var exists bool
	err := row.Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check config existence: %w", err)
	}

	return exists, nil
}

// Caddy configuration methods

// CreateCaddyConfig creates a new Caddy configuration version
func (r *ConfigRepository) CreateCaddyConfig(ctx context.Context, config, patches string, version int) error {
	result, err := r.dbManager.Execute(ctx, "InsertCaddyConfig", config, patches, version)
	if err != nil {
		return fmt.Errorf("failed to create caddy config: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	r.logger.WithFields(logrus.Fields{
		"version":      version,
		"rowsAffected": rows,
	}).Debug("Caddy config created")

	return nil
}

// GetActiveCaddyConfig retrieves the currently active Caddy configuration
func (r *ConfigRepository) GetActiveCaddyConfig(ctx context.Context) (*database.CaddyConfigEntity, error) {
	row := r.dbManager.QueryRow(ctx, "GetActiveCaddyConfig")

	var config database.CaddyConfigEntity
	var patches sql.NullString
	err := row.Scan(&config.ID, &config.Config, &patches, &config.Version, &config.Active, &config.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No active config
		}
		return nil, fmt.Errorf("failed to get active caddy config: %w", err)
	}

	if patches.Valid {
		config.Patches = &patches.String
	}

	return &config, nil
}

// GetCaddyConfigByVersion retrieves a specific Caddy configuration version
func (r *ConfigRepository) GetCaddyConfigByVersion(ctx context.Context, version int) (*database.CaddyConfigEntity, error) {
	row := r.dbManager.QueryRow(ctx, "GetCaddyConfigByVersion", version)

	var config database.CaddyConfigEntity
	var patches sql.NullString
	err := row.Scan(&config.ID, &config.Config, &patches, &config.Version, &config.Active, &config.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("caddy config version not found: %d", version)
		}
		return nil, fmt.Errorf("failed to get caddy config by version: %w", err)
	}

	if patches.Valid {
		config.Patches = &patches.String
	}

	return &config, nil
}

// SetActiveCaddyConfig sets a specific version as the active Caddy configuration
func (r *ConfigRepository) SetActiveCaddyConfig(ctx context.Context, version int) error {
	// This requires two queries, so we use a transaction
	return r.dbManager.Transaction(ctx, func(tx *sql.Tx) error {
		// Deactivate all configs
		_, err := tx.Exec("UPDATE caddy_configs SET active = FALSE WHERE active = TRUE")
		if err != nil {
			return fmt.Errorf("failed to deactivate configs: %w", err)
		}

		// Activate the specified version
		result, err := tx.Exec("UPDATE caddy_configs SET active = TRUE WHERE version = ?", version)
		if err != nil {
			return fmt.Errorf("failed to activate config: %w", err)
		}

		rows, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get rows affected: %w", err)
		}

		if rows == 0 {
			return fmt.Errorf("caddy config version not found: %d", version)
		}

		return nil
	})
}

// ListCaddyConfigs retrieves all Caddy configurations
func (r *ConfigRepository) ListCaddyConfigs(ctx context.Context) ([]*database.CaddyConfigEntity, error) {
	rows, err := r.dbManager.Query(ctx, "ListCaddyConfigs")
	if err != nil {
		return nil, fmt.Errorf("failed to list caddy configs: %w", err)
	}
	defer rows.Close()

	var configs []*database.CaddyConfigEntity
	for rows.Next() {
		var config database.CaddyConfigEntity
		var patches sql.NullString
		err := rows.Scan(&config.ID, &config.Config, &patches, &config.Version, &config.Active, &config.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan caddy config: %w", err)
		}

		if patches.Valid {
			config.Patches = &patches.String
		}

		configs = append(configs, &config)
	}

	return configs, nil
}

// DeleteOldCaddyConfigs deletes old inactive Caddy configurations
func (r *ConfigRepository) DeleteOldCaddyConfigs(ctx context.Context, keepVersions int) error {
	result, err := r.dbManager.Execute(ctx, "DeleteOldCaddyConfigs", keepVersions)
	if err != nil {
		return fmt.Errorf("failed to delete old caddy configs: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	r.logger.WithField("deleted", rows).Debug("Old Caddy configs deleted")
	return nil
}

// GetLatestCaddyConfigVersion retrieves the latest Caddy configuration version number
func (r *ConfigRepository) GetLatestCaddyConfigVersion(ctx context.Context) (int, error) {
	row := r.dbManager.QueryRow(ctx, "GetLatestCaddyConfigVersion")

	var version int
	err := row.Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("failed to get latest caddy config version: %w", err)
	}

	return version, nil
}

// CountCaddyConfigs returns the total number of Caddy configurations
func (r *ConfigRepository) CountCaddyConfigs(ctx context.Context) (int, error) {
	row := r.dbManager.QueryRow(ctx, "CountCaddyConfigs")

	var count int
	err := row.Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count caddy configs: %w", err)
	}

	return count, nil
}

// Stream configuration methods

// UpsertStreamConfig inserts or updates a stream configuration
func (r *ConfigRepository) UpsertStreamConfig(ctx context.Context, id, data string) error {
	result, err := r.dbManager.Execute(ctx, "UpsertStreamConfig", id, data)
	if err != nil {
		return fmt.Errorf("failed to upsert stream config: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	r.logger.WithFields(logrus.Fields{
		"id":           id,
		"rowsAffected": rows,
	}).Debug("Stream config upserted")

	return nil
}

// GetStreamConfig retrieves a stream configuration
func (r *ConfigRepository) GetStreamConfig(ctx context.Context, id string) (*database.ConfigEntity, error) {
	row := r.dbManager.QueryRow(ctx, "GetBenthosStreamConfig", id)

	var config database.ConfigEntity
	err := row.Scan(&config.ID, &config.Data, &config.Version, &config.CreatedAt, &config.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("stream config not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get stream config: %w", err)
	}

	config.Type = "benthos_stream"
	return &config, nil
}

// DeleteStreamConfig deletes a stream configuration
func (r *ConfigRepository) DeleteStreamConfig(ctx context.Context, id string) error {
	result, err := r.dbManager.Execute(ctx, "DeleteBenthosStreamConfig", id)
	if err != nil {
		return fmt.Errorf("failed to delete stream config: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("stream config not found: %s", id)
	}

	r.logger.WithField("id", id).Debug("Stream config deleted")
	return nil
}

// ListStreamConfigs retrieves all stream configurations
func (r *ConfigRepository) ListStreamConfigs(ctx context.Context) ([]*database.ConfigEntity, error) {
	rows, err := r.dbManager.Query(ctx, "ListStreamConfigs")
	if err != nil {
		return nil, fmt.Errorf("failed to list stream configs: %w", err)
	}
	defer rows.Close()

	var configs []*database.ConfigEntity
	for rows.Next() {
		var config database.ConfigEntity
		err := rows.Scan(&config.ID, &config.Data, &config.Version, &config.CreatedAt, &config.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan stream config: %w", err)
		}
		config.Type = "benthos_stream"
		configs = append(configs, &config)
	}

	return configs, nil
}

// Application settings methods

// UpsertAppSetting inserts or updates an application setting
func (r *ConfigRepository) UpsertAppSetting(ctx context.Context, id, data string) error {
	result, err := r.dbManager.Execute(ctx, "UpsertAppSetting", id, data)
	if err != nil {
		return fmt.Errorf("failed to upsert app setting: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	r.logger.WithFields(logrus.Fields{
		"id":           id,
		"rowsAffected": rows,
	}).Debug("App setting upserted")

	return nil
}

// GetAppSetting retrieves an application setting
func (r *ConfigRepository) GetAppSetting(ctx context.Context, id string) (string, error) {
	row := r.dbManager.QueryRow(ctx, "GetAppSetting", id)

	var data string
	err := row.Scan(&data)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("app setting not found: %s", id)
		}
		return "", fmt.Errorf("failed to get app setting: %w", err)
	}

	return data, nil
}

// ListAppSettings retrieves all application settings
func (r *ConfigRepository) ListAppSettings(ctx context.Context) ([]*database.ConfigEntity, error) {
	rows, err := r.dbManager.Query(ctx, "ListAppSettings")
	if err != nil {
		return nil, fmt.Errorf("failed to list app settings: %w", err)
	}
	defer rows.Close()

	var configs []*database.ConfigEntity
	for rows.Next() {
		var config database.ConfigEntity
		err := rows.Scan(&config.ID, &config.Data, &config.Version, &config.CreatedAt, &config.UpdatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan app setting: %w", err)
		}
		config.Type = "app_setting"
		configs = append(configs, &config)
	}

	return configs, nil
}
