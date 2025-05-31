package container

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/security"
)

// initSecurityWithOPA initializes security with OPA integration
func (c *Container) initSecurityWithOPA(cfg *Config) error {
	c.Logger.Debug("Initializing security components with OPA")

	// Create integrated license system
	integrationCfg := &security.IntegrationConfig{
		PolicyDir:     security.DefaultPolicyDir(),
		LicenseFile:   cfg.LicensePath,
		PublicKeyPath: cfg.PublicKey,
		Logger:        c.Logger,
	}

	licenseIntegration, err := security.NewLicenseIntegration(integrationCfg)
	if err != nil {
		return fmt.Errorf("failed to create license integration: %w", err)
	}

	// Store the integration for use by other components
	c.licenseIntegration = licenseIntegration

	// Validate license
	if err := licenseIntegration.ValidateLicense(context.Background()); err != nil {
		return fmt.Errorf("license validation failed: %w", err)
	}

	// Log license status
	info := licenseIntegration.GetLicenseInfo()
	c.Logger.WithFields(logrus.Fields{
		"has_license": info["has_license"],
	}).Info("License system initialized with OPA")

	// Get allowed features for logging
	if features, err := licenseIntegration.GetAllowedFeatures(); err == nil {
		c.Logger.WithField("features", features).Debug("Allowed features loaded")
	}

	return nil
}

// Helper methods for feature checking throughout the container

// IsFeatureEnabled checks if a feature is enabled
func (c *Container) IsFeatureEnabled(category, feature string) bool {
	if c.licenseIntegration == nil {
		return false
	}
	return c.licenseIntegration.IsFeatureEnabled(category, feature)
}

// CheckResourceLimit checks if a resource count is within licensed limits
func (c *Container) CheckResourceLimit(resource string, count int) bool {
	if c.licenseIntegration == nil {
		// No license system, allow default limits
		switch resource {
		case "max_things":
			return count <= 10
		case "max_streams":
			return count <= 5
		default:
			return true
		}
	}
	return c.licenseIntegration.CheckResourceLimit(resource, count)
}

// GetSecurityConfig generates security configuration based on license
func (c *Container) GetSecurityConfig() (map[string]interface{}, error) {
	if c.licenseIntegration == nil {
		// Return minimal security config
		return map[string]interface{}{
			"authentication": map[string]interface{}{
				"providers": []map[string]interface{}{
					{
						"type":       "basic",
						"users_file": "/etc/twincore/users.txt",
					},
				},
			},
		}, nil
	}

	// Get current config (could be from environment or config file)
	currentConfig := map[string]interface{}{
		"jwt_jwks_url":        c.Config.JWTJwksURL,
		"jwt_issuer":          c.Config.JWTIssuer,
		"oauth2_provider_url": c.Config.OAuth2ProviderURL,
		"oauth2_client_id":    c.Config.OAuth2ClientID,
	}

	return c.licenseIntegration.GetSecurityConfig(currentConfig)
}
