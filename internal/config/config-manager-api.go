// internal/config/config_manager.go
package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/caddyserver/caddy/v2" // Import caddy
	"github.com/sirupsen/logrus"      // Import logrus
	"github.com/wI2L/jsondiff"
	"github.com/twinfer/twincore/internal/database"
	"maps"
)

// ConfigManager manages configurations via API
type ConfigManager struct {
	dbManager database.DatabaseManager
	logger    *logrus.Logger

	// Current configs
	caddyConfig    *caddy.Config
	benthosConfigs map[string]string // streamName -> YAML

	// Config history for rollback
	caddyPatches []byte // Store JSON representation of jsondiff.Patch

	mu sync.RWMutex
}

func NewConfigManager(dbManager database.DatabaseManager, logger *logrus.Logger) *ConfigManager {
	return &ConfigManager{
		dbManager:      dbManager,
		logger:         logger,
		benthosConfigs: make(map[string]string),
	}
}

// LoadFromDB loads configurations from database on startup
func (cm *ConfigManager) LoadFromDB() error {
	cm.logger.Debug("Loading configurations from database")

	ctx := context.Background()

	// Load active Caddy config
	row := cm.dbManager.QueryRow(ctx, "GetActiveCaddyConfig")
	var configJSON string
	var id, version int
	var patches *string
	var active bool
	var createdAt string
	
	err := row.Scan(&id, &configJSON, &patches, &version, &active, &createdAt)
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
	rows, err := cm.dbManager.Query(ctx, "ListStreamConfigs")
	if err != nil {
		return fmt.Errorf("failed to load Benthos configs: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var streamName, yamlConfig string
		var version int
		var createdAt, updatedAt string
		if err := rows.Scan(&streamName, &yamlConfig, &version, &createdAt, &updatedAt); err != nil {
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
	var patchesJSON []byte
	if cm.caddyConfig != nil {
		oldJSON, err := json.Marshal(cm.caddyConfig)
		if err != nil {
			// Handle error appropriately
			cm.logger.Errorf("Failed to marshal old Caddy config: %v", err)
			// Decide if you want to proceed without a patch or return the error
		} else {
			newCfgJSON, err := json.Marshal(newConfig) // Renamed to newCfgJSON to avoid conflict with newJSON var later
			if err != nil {
				// Handle error appropriately
				cm.logger.Errorf("Failed to marshal new Caddy config: %v", err)
			} else {
				patch, err := jsondiff.CompareJSON(oldJSON, newCfgJSON)
				if err != nil {
					// Handle error
					cm.logger.Errorf("Failed to compare JSON for Caddy config: %v", err)
				} else {
					patchesJSON, err = json.Marshal(patch) // Convert jsondiff.Patch to JSON bytes
					if err != nil {
						cm.logger.Errorf("Failed to marshal jsondiff.Patch to JSON: %v", err)
					}
					cm.logger.Debugf("Generated JSON patch: %s", string(patchesJSON))
				}
			}
		}
	}

	// Save to database using transaction
	newJSON, _ := json.Marshal(newConfig) // This is the full new configuration
	// patchesJSON is already defined above

	ctx := context.Background()
	
	// Get latest version and insert new config in a transaction-like manner
	// First deactivate current config
	_, err := cm.dbManager.Execute(ctx, "SetActiveCaddyConfig", 0) // Deactivate all by setting to version 0
	if err != nil {
		return fmt.Errorf("failed to deactivate current config: %w", err)
	}

	// Get latest version for new config
	latestVersionRow := cm.dbManager.QueryRow(ctx, "GetLatestCaddyConfigVersion")
	var latestVersion int
	if err := latestVersionRow.Scan(&latestVersion); err != nil {
		latestVersion = 0 // Default to 0 if no configs exist
	}
	newVersion := latestVersion + 1

	// Insert new config
	_, err = cm.dbManager.Execute(ctx, "InsertCaddyConfig", string(newJSON), string(patchesJSON), newVersion)
	if err != nil {
		return fmt.Errorf("failed to insert new config: %w", err)
	}

	// Set the new config as active
	_, err = cm.dbManager.Execute(ctx, "SetActiveCaddyConfig", newVersion)
	if err != nil {
		return fmt.Errorf("failed to activate new config: %w", err)
	}

	// Update in-memory config
	cm.caddyConfig = newConfig
	cm.caddyPatches = patchesJSON // Store the marshaled JSON patch

	cm.logger.Info("Caddy config updated successfully")
	return nil
}

// RollbackCaddyConfig rolls back to previous Caddy configuration
func (cm *ConfigManager) RollbackCaddyConfig() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// if len(cm.caddyPatches) == 0 { // This check might need adjustment if caddyPatches can be nil/empty for valid reasons
	// 	return fmt.Errorf("no rollback data available")
	// }

	cm.logger.Warn("RollbackCaddyConfig is currently non-functional pending a proper historical version fetching implementation.")
	return fmt.Errorf("rollback is temporarily disabled")

}

// UpdateBenthosStream updates a Benthos stream configuration (no JD, just reload)
func (cm *ConfigManager) UpdateBenthosStream(streamName string, yamlConfig string) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.logger.Debugf("Updating Benthos stream: %s", streamName)

	// Save to database using repository
	ctx := context.Background()
	_, err := cm.dbManager.Execute(ctx, "UpsertStreamConfig", streamName, yamlConfig)
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
	maps.Copy(configs, cm.benthosConfigs)

	return configs
}

// CompleteSetup marks the initial setup as complete.
// TODO: Implement actual setup completion logic if needed.
func (cm *ConfigManager) CompleteSetup(logger logrus.FieldLogger) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Here, you would typically set a flag in the database or in memory
	// to indicate that the setup has been completed.
	// For now, we just log it.
	logger.Info("ConfigManager: Setup marked as complete.")

	// Placeholder: In a real implementation, you might want to save this state.
	// For example, by setting a specific record in the database:
	// _, err := cm.db.Exec("INSERT OR REPLACE INTO system_flags (flag_name, flag_value) VALUES ('setup_complete', 'true')")
	// if err != nil {
	// 	logger.Errorf("Failed to mark setup as complete in DB: %v", err)
	// 	return fmt.Errorf("failed to save setup completion status: %w", err)
	// }

	return nil
}
