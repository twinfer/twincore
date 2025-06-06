package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/caddyserver/caddy/v2"
	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/database"
)

// LifecycleManager manages the configuration lifecycle of TwinCore
type LifecycleManager struct {
	configRepo       database.ConfigRepositoryInterface
	configManager    *ConfigManager
	defaultProvider  *DefaultConfigProvider
	logger           *logrus.Logger
	dataDir          string
	licenseValidator LicenseValidator
}

// LicenseValidator interface for license validation
type LicenseValidator interface {
	ValidateLicense(licenseData string) (map[string]any, error)
	GetFeatures() map[string]bool
	IsValid() bool
}

// NewLifecycleManager creates a new lifecycle manager
func NewLifecycleManager(configRepo database.ConfigRepositoryInterface, configManager *ConfigManager, licenseValidator LicenseValidator, dataDir string, logger *logrus.Logger) *LifecycleManager {
	return &LifecycleManager{
		configRepo:       configRepo,
		configManager:    configManager,
		defaultProvider:  NewDefaultConfigProvider(),
		logger:           logger,
		dataDir:          dataDir,
		licenseValidator: licenseValidator,
	}
}

// Initialize handles the startup configuration lifecycle
func (lm *LifecycleManager) Initialize() error {
	lm.logger.Info("Initializing configuration lifecycle")

	// Step 1: Check for existing configuration
	hasConfig, err := lm.hasExistingConfiguration()
	if err != nil {
		return fmt.Errorf("failed to check existing configuration: %w", err)
	}

	// Step 2: Check for license
	hasLicense, err := lm.hasValidLicense()
	if err != nil {
		lm.logger.WithError(err).Warn("Failed to check license, continuing with defaults")
		hasLicense = false
	}

	// Step 3: Update default provider with license features
	if hasLicense && lm.licenseValidator != nil {
		features := lm.licenseValidator.GetFeatures()
		lm.defaultProvider.SetLicenseFeatures(features)
		lm.logger.WithField("features", features).Info("License features loaded")
	}

	// Step 4: Load or create configuration
	if hasConfig {
		lm.logger.Info("Loading existing configuration from database")
		if err := lm.configManager.LoadFromDB(); err != nil {
			lm.logger.WithError(err).Error("Failed to load configuration from database")
			// Fall back to defaults
			return lm.applyDefaultConfiguration()
		}
		lm.logger.Info("Configuration loaded successfully")
	} else {
		lm.logger.Info("No existing configuration found, applying defaults")
		if err := lm.applyDefaultConfiguration(); err != nil {
			return fmt.Errorf("failed to apply default configuration: %w", err)
		}
	}

	// Step 5: Ensure required directories exist
	if err := lm.ensureDirectories(); err != nil {
		return fmt.Errorf("failed to create required directories: %w", err)
	}

	// Step 6: Mark system as initialized
	if err := lm.markInitialized(); err != nil {
		lm.logger.WithError(err).Warn("Failed to mark system as initialized")
	}

	return nil
}

// hasExistingConfiguration checks if there's existing configuration in the database
func (lm *LifecycleManager) hasExistingConfiguration() (bool, error) {
	ctx := context.Background()
	config, err := lm.configRepo.GetActiveCaddyConfig(ctx)
	if err != nil {
		return false, err
	}
	return config != nil, nil
}

// hasValidLicense checks if there's a valid license in the database
func (lm *LifecycleManager) hasValidLicense() (bool, error) {
	ctx := context.Background()
	licenseData, err := lm.configRepo.GetAppSetting(ctx, "system_license")
	if err != nil {
		// Check for license file
		licensePath := filepath.Join(lm.dataDir, "license.jwt")
		if data, err := os.ReadFile(licensePath); err == nil {
			// Validate and save license
			if _, err := lm.licenseValidator.ValidateLicense(string(data)); err == nil {
				// Save to database
				if err := lm.saveLicenseToDatabase(string(data)); err != nil {
					lm.logger.WithError(err).Warn("Failed to save license to database")
				}
				return true, nil
			}
		}
		return false, nil
	}

	// Validate the license
	if lm.licenseValidator != nil {
		_, err := lm.licenseValidator.ValidateLicense(licenseData)
		return err == nil, nil
	}

	return false, nil
}

// applyDefaultConfiguration applies default configuration
func (lm *LifecycleManager) applyDefaultConfiguration() error {
	lm.logger.Info("Applying default configuration")

	// Get default Caddy config
	defaultCaddyConfig := lm.defaultProvider.GetDefaultCaddyConfig()

	// Save to database
	if err := lm.configManager.UpdateCaddyConfig(defaultCaddyConfig); err != nil {
		return fmt.Errorf("failed to save default Caddy config: %w", err)
	}

	// Save default service configurations
	if err := lm.saveDefaultServiceConfigs(); err != nil {
		return fmt.Errorf("failed to save default service configs: %w", err)
	}

	return nil
}

// saveDefaultServiceConfigs saves default service configurations to database
func (lm *LifecycleManager) saveDefaultServiceConfigs() error {
	ctx := context.Background()
	
	// HTTP service config
	httpConfig := lm.defaultProvider.GetDefaultHTTPConfig()
	httpConfigJSON, err := json.Marshal(httpConfig)
	if err != nil {
		return err
	}

	if err := lm.configRepo.UpsertConfig(ctx, "http_service", "service_config", string(httpConfigJSON)); err != nil {
		return err
	}

	// Stream service config
	streamConfig := lm.defaultProvider.GetDefaultStreamConfig()
	streamConfigJSON, err := json.Marshal(streamConfig)
	if err != nil {
		return err
	}

	if err := lm.configRepo.UpsertConfig(ctx, "stream_service", "service_config", string(streamConfigJSON)); err != nil {
		return err
	}

	// Security config
	securityConfig := lm.defaultProvider.GetDefaultSystemSecurityConfig()
	securityConfigJSON, err := json.Marshal(securityConfig)
	if err != nil {
		return err
	}

	return lm.configRepo.UpsertConfig(ctx, "security", "service_config", string(securityConfigJSON))
}

// ensureDirectories creates required directories
func (lm *LifecycleManager) ensureDirectories() error {
	dirs := []string{
		lm.dataDir,
		filepath.Join(lm.dataDir, "parquet"),
		filepath.Join(lm.dataDir, "stream_configs"),
		filepath.Join(lm.dataDir, "backups"),
		"./portal/dist", // Portal static files
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// markInitialized marks the system as initialized
func (lm *LifecycleManager) markInitialized() error {
	ctx := context.Background()
	return lm.configRepo.UpsertConfig(ctx, "system_initialized", "system_flag", "true")
}

// IsInitialized checks if the system has been initialized
func (lm *LifecycleManager) IsInitialized() (bool, error) {
	ctx := context.Background()
	config, err := lm.configRepo.GetConfig(ctx, "system_initialized")
	if err != nil {
		return false, nil // Not initialized if config doesn't exist
	}

	return config.Data == "true", nil
}

// saveLicenseToDatabase saves license to database
func (lm *LifecycleManager) saveLicenseToDatabase(licenseData string) error {
	ctx := context.Background()
	return lm.configRepo.UpsertAppSetting(ctx, "system_license", licenseData)
}

// GetLicense retrieves the stored license
func (lm *LifecycleManager) GetLicense() (string, error) {
	ctx := context.Background()
	return lm.configRepo.GetAppSetting(ctx, "system_license")
}

// UpdateLicense updates the system license
func (lm *LifecycleManager) UpdateLicense(licenseData string) error {
	// Validate the new license
	if lm.licenseValidator != nil {
		if _, err := lm.licenseValidator.ValidateLicense(licenseData); err != nil {
			return fmt.Errorf("invalid license: %w", err)
		}
	}

	// Save to database
	if err := lm.saveLicenseToDatabase(licenseData); err != nil {
		return err
	}

	// Update default provider with new features
	if lm.licenseValidator != nil {
		features := lm.licenseValidator.GetFeatures()
		lm.defaultProvider.SetLicenseFeatures(features)
	}

	lm.logger.Info("License updated successfully")
	return nil
}

// ExportConfiguration exports the current configuration
func (lm *LifecycleManager) ExportConfiguration() (map[string]any, error) {
	ctx := context.Background()
	export := make(map[string]any)

	// Get Caddy config
	caddyConfig, err := lm.configManager.GetCaddyConfig()
	if err == nil {
		export["caddy"] = caddyConfig
	}

	// Get service configs
	configs, err := lm.configRepo.GetConfigsByType(ctx, "service_config")
	if err == nil {
		services := make(map[string]any)
		for _, cfg := range configs {
			var config any
			if err := json.Unmarshal([]byte(cfg.Data), &config); err == nil {
				services[cfg.ID] = config
			}
		}
		export["services"] = services
	}

	// Get Benthos configs
	benthosConfigs := lm.configManager.GetAllBenthosConfigs()
	if len(benthosConfigs) > 0 {
		export["streams"] = benthosConfigs
	}

	return export, nil
}

// ImportConfiguration imports a configuration
func (lm *LifecycleManager) ImportConfiguration(config map[string]any) error {
	// Import Caddy config
	if caddyRaw, ok := config["caddy"]; ok {
		caddyJSON, err := json.Marshal(caddyRaw)
		if err != nil {
			return fmt.Errorf("failed to marshal Caddy config: %w", err)
		}

		var caddyConfig caddy.Config
		if err := json.Unmarshal(caddyJSON, &caddyConfig); err != nil {
			return fmt.Errorf("failed to unmarshal Caddy config: %w", err)
		}

		if err := lm.configManager.UpdateCaddyConfig(&caddyConfig); err != nil {
			return fmt.Errorf("failed to update Caddy config: %w", err)
		}
	}

	// Import service configs
	if services, ok := config["services"].(map[string]any); ok {
		ctx := context.Background()
		for id, serviceConfig := range services {
			configJSON, err := json.Marshal(serviceConfig)
			if err != nil {
				continue
			}

			if err := lm.configRepo.UpsertConfig(ctx, id, "service_config", string(configJSON)); err != nil {
				lm.logger.WithError(err).Errorf("Failed to import service config: %s", id)
			}
		}
	}

	// Import stream configs
	if streams, ok := config["streams"].(map[string]any); ok {
		for name, streamConfig := range streams {
			if yamlStr, ok := streamConfig.(string); ok {
				if err := lm.configManager.UpdateBenthosStream(name, yamlStr); err != nil {
					lm.logger.WithError(err).Errorf("Failed to import stream: %s", name)
				}
			}
		}
	}

	return nil
}