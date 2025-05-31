package security

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/types"
)

// LicenseIntegration bridges the existing license system with OPA
type LicenseIntegration struct {
	licenseManager types.LicenseManager
	deviceManager  *DeviceManager
	opaChecker     *LicenseCheckerOPA
	jwtValidator   *JWTLicenseValidator
	logger         logrus.FieldLogger
}

// NewLicenseIntegration creates a new integrated license system
func NewLicenseIntegration(cfg *IntegrationConfig) (*LicenseIntegration, error) {
	li := &LicenseIntegration{
		logger: cfg.Logger,
	}

	// Initialize JWT validator if public key provided
	if cfg.PublicKeyPath != "" {
		jwtValidator, err := NewJWTLicenseValidator(cfg.PublicKeyPath, cfg.PolicyDir, cfg.Logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create JWT validator: %w", err)
		}
		li.jwtValidator = jwtValidator
	}

	// Initialize OPA checker
	opaChecker, err := NewLicenseCheckerOPA(cfg.PolicyDir, cfg.LicenseFile, cfg.Logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create OPA checker: %w", err)
	}
	li.opaChecker = opaChecker

	// Initialize existing license manager for backward compatibility
	if cfg.PublicKeyPath != "" {
		// Read public key file
		publicKeyData, err := os.ReadFile(cfg.PublicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read public key: %w", err)
		}

		lm, err := NewLicenseManager(publicKeyData)
		if err != nil {
			return nil, fmt.Errorf("failed to create license manager: %w", err)
		}
		li.licenseManager = lm
	}

	// Initialize device manager if needed
	if cfg.LicenseFile != "" && cfg.PublicKeyPath != "" {
		// Read public key file
		publicKeyData, err := os.ReadFile(cfg.PublicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read public key: %w", err)
		}

		dm, err := NewDeviceManager(cfg.LicenseFile, publicKeyData)
		if err != nil {
			return nil, fmt.Errorf("failed to create device manager: %w", err)
		}
		li.deviceManager = dm
	}

	return li, nil
}

// IntegrationConfig holds configuration for the integrated license system
type IntegrationConfig struct {
	PolicyDir     string
	LicenseFile   string
	PublicKeyPath string
	Logger        logrus.FieldLogger
}

// IsFeatureEnabled checks if a feature is enabled using OPA
func (li *LicenseIntegration) IsFeatureEnabled(category, feature string) bool {
	enabled, err := li.opaChecker.IsFeatureEnabled(category, feature)
	if err != nil {
		li.logger.WithError(err).Errorf("Failed to check feature %s/%s", category, feature)
		return false
	}
	return enabled
}

// CheckResourceLimit checks if a resource count is within limits
func (li *LicenseIntegration) CheckResourceLimit(resource string, count int) bool {
	withinLimit, err := li.opaChecker.CheckLimit(resource, count)
	if err != nil {
		li.logger.WithError(err).Errorf("Failed to check limit for %s", resource)
		return false
	}
	return withinLimit
}

// GetAllowedFeatures returns all features allowed by the license
func (li *LicenseIntegration) GetAllowedFeatures() (map[string]interface{}, error) {
	return li.opaChecker.GetAllowedFeatures()
}

// GetSecurityConfig generates security configuration based on license
func (li *LicenseIntegration) GetSecurityConfig(config map[string]interface{}) (map[string]interface{}, error) {
	return li.opaChecker.GetSecurityConfig(config)
}

// ValidateLicense validates the license using both JWT and OPA
func (li *LicenseIntegration) ValidateLicense(ctx context.Context) error {
	// First try backward-compatible validation if device manager exists
	if li.deviceManager != nil {
		if err := li.deviceManager.InitializeLicense(ctx); err != nil {
			return fmt.Errorf("legacy license validation failed: %w", err)
		}
	}

	// OPA validation happens automatically based on loaded data
	if !li.opaChecker.HasLicense() {
		li.logger.Warn("No license loaded, using default features")
	}

	return nil
}

// GetLicenseInfo returns comprehensive license information
func (li *LicenseIntegration) GetLicenseInfo() map[string]interface{} {
	info := make(map[string]interface{})

	// Add OPA feature info
	if features, err := li.opaChecker.GetAllowedFeatures(); err == nil {
		info["features"] = features
	}

	// Add license status
	info["has_license"] = li.opaChecker.HasLicense()

	// Add legacy license info if available
	if li.deviceManager != nil {
		if claims, err := li.deviceManager.GetLicenseClaims(); err == nil {
			info["legacy_claims"] = claims
		}
	}

	return info
}

// DefaultPolicyDir returns the default OPA policy directory
func DefaultPolicyDir() string {
	return filepath.Join("internal", "opa", "policies")
}
