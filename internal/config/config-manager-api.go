// internal/config/config_manager.go
package config

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/caddyserver/caddy/v2" // Import caddy
	"github.com/josephburnett/jd"
	"github.com/sirupsen/logrus" // Import logrus
)

// ConfigManager manages configurations via API
type ConfigManager struct {
	db     *sql.DB
	logger *logrus.Logger

	// Current configs
	caddyConfig    *caddy.Config
	benthosConfigs map[string]string // streamName -> YAML

	// Config history for rollback
	caddyPatches []jd.Patch

	mu sync.RWMutex
}

func NewConfigManager(db *sql.DB, logger *logrus.Logger) *ConfigManager {
	return &ConfigManager{
		db:             db,
		logger:         logger,
		benthosConfigs: make(map[string]string),
	}
}

// LoadFromDB loads configurations from database on startup
func (cm *ConfigManager) LoadFromDB() error {
	cm.logger.Debug("Loading configurations from database")

	// Load active Caddy config
	var configJSON string
	err := cm.db.QueryRow(`
        SELECT config FROM caddy_configs 
        WHERE active = true 
        ORDER BY created_at DESC 
        LIMIT 1
    `).Scan(&configJSON)

	if err == nil {
		var config caddy.Config
		if err := json.Unmarshal([]byte(configJSON), &config); err == nil {
			cm.caddyConfig = &config
			cm.logger.Info("Loaded Caddy config from database")
		}
	} else if err != sql.ErrNoRows {
		return fmt.Errorf("failed to load Caddy config: %w", err)
	}

	// Load Benthos configs
	rows, err := cm.db.Query(`
        SELECT id, data FROM configs 
        WHERE type = 'benthos_stream'
    `)
	if err != nil {
		return fmt.Errorf("failed to load Benthos configs: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var streamName, yamlConfig string
		if err := rows.Scan(&streamName, &yamlConfig); err != nil {
			cm.logger.Errorf("Failed to scan Benthos config: %v", err)
			continue
		}
		cm.benthosConfigs[streamName] = yamlConfig
	}

	cm.logger.Infof("Loaded %d Benthos stream configs", len(cm.benthosConfigs))
	return nil
}

// UpdateCaddyConfig updates Caddy configuration with JD patches for rollback
func (cm *ConfigManager) UpdateCaddyConfig(newConfig *caddy.Config) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.logger.Debug("Updating Caddy configuration")

	// Validate new config
	if err := caddy.Validate(newConfig); err != nil {
		cm.logger.Errorf("Invalid Caddy config: %v", err)
		return fmt.Errorf("config validation failed: %w", err)
	}

	// Generate patches if we have current config
	var patches []jd.Patch
	if cm.caddyConfig != nil {
		oldJSON, _ := json.Marshal(cm.caddyConfig)
		newJSON, _ := json.Marshal(newConfig)
		patches, _ = jd.Diff(oldJSON, newJSON)

		cm.logger.Debugf("Generated %d JD patches", len(patches))
	}

	// Save to database
	newJSON, _ := json.Marshal(newConfig)
	patchesJSON, _ := json.Marshal(patches)

	tx, err := cm.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Deactivate current config
	_, err = tx.Exec("UPDATE caddy_configs SET active = false WHERE active = true")
	if err != nil {
		return err
	}

	// Insert new config
	_, err = tx.Exec(`
        INSERT INTO caddy_configs (config, patches, version, active)
        VALUES (?, ?, (SELECT COALESCE(MAX(version), 0) + 1 FROM caddy_configs), true)
    `, string(newJSON), string(patchesJSON))
	if err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	// Update in-memory config
	cm.caddyConfig = newConfig
	cm.caddyPatches = patches

	cm.logger.Info("Caddy config updated successfully")
	return nil
}

// RollbackCaddyConfig rolls back to previous Caddy configuration
func (cm *ConfigManager) RollbackCaddyConfig() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if len(cm.caddyPatches) == 0 {
		return fmt.Errorf("no rollback data available")
	}

	cm.logger.Info("Rolling back Caddy configuration")

	// Apply patches in reverse
	currentJSON, _ := json.Marshal(cm.caddyConfig)
	for i := len(cm.caddyPatches) - 1; i >= 0; i-- {
		currentJSON, _ = cm.caddyPatches[i].Apply(currentJSON)
	}

	var rolledBackConfig caddy.Config
	if err := json.Unmarshal(currentJSON, &rolledBackConfig); err != nil {
		return err
	}

	// Save rolled back config
	return cm.UpdateCaddyConfig(&rolledBackConfig)
}

// UpdateBenthosStream updates a Benthos stream configuration (no JD, just reload)
func (cm *ConfigManager) UpdateBenthosStream(streamName string, yamlConfig string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.logger.Debugf("Updating Benthos stream: %s", streamName)

	// Save to database
	_, err := cm.db.Exec(`
        INSERT OR REPLACE INTO configs (id, type, data, version)
        VALUES (?, 'benthos_stream', ?, 
            (SELECT COALESCE(MAX(version), 0) + 1 FROM configs WHERE id = ?))
    `, streamName, yamlConfig, streamName)

	if err != nil {
		return fmt.Errorf("failed to save Benthos config: %w", err)
	}

	// Update in-memory
	cm.benthosConfigs[streamName] = yamlConfig

	cm.logger.Infof("Benthos stream %s updated", streamName)
	return nil
}

// GetCaddyConfig returns current Caddy configuration
func (cm *ConfigManager) GetCaddyConfig() (*caddy.Config, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.caddyConfig == nil {
		return nil, fmt.Errorf("no Caddy config loaded")
	}

	return cm.caddyConfig, nil
}

// GetBenthosConfig returns Benthos stream configuration
func (cm *ConfigManager) GetBenthosConfig(streamName string) (string, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	config, exists := cm.benthosConfigs[streamName]
	if !exists {
		return "", fmt.Errorf("stream %s not found", streamName)
	}

	return config, nil
}

// GetAllBenthosConfigs returns all Benthos configurations
func (cm *ConfigManager) GetAllBenthosConfigs() map[string]string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	configs := make(map[string]string)
	for k, v := range cm.benthosConfigs {
		configs[k] = v
	}

	return configs
}
