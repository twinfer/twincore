package config

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/license"
)

// SimpleLicenseValidatorAdapter adapts SimpleLicenseChecker to LicenseValidator interface
type SimpleLicenseValidatorAdapter struct {
	checker *license.SimpleLicenseChecker
	logger  *logrus.Logger
}

// NewSimpleLicenseValidatorAdapter creates a new adapter
func NewSimpleLicenseValidatorAdapter(checker *license.SimpleLicenseChecker, logger *logrus.Logger) *SimpleLicenseValidatorAdapter {
	return &SimpleLicenseValidatorAdapter{
		checker: checker,
		logger:  logger,
	}
}

// ValidateLicense validates a license string
func (a *SimpleLicenseValidatorAdapter) ValidateLicense(licenseData string) (map[string]any, error) {
	// For SimpleLicenseChecker, we need to recreate it with the new license data
	// This is a limitation of the current implementation
	// In a real implementation, you might want to enhance SimpleLicenseChecker to support this

	// For now, we'll just check if the current license is valid
	if a.checker == nil {
		return nil, fmt.Errorf("no license checker available")
	}

	// Get current features
	features, err := a.checker.GetAllowedFeatures()
	if err != nil {
		return nil, err
	}

	return features, nil
}

// GetFeatures returns the currently available features
func (a *SimpleLicenseValidatorAdapter) GetFeatures() map[string]bool {
	if a.checker == nil {
		return make(map[string]bool)
	}

	features, err := a.checker.GetAllowedFeatures()
	if err != nil {
		a.logger.WithError(err).Warn("Failed to get license features")
		return make(map[string]bool)
	}

	// Convert to bool map
	featureMap := make(map[string]bool)

	// Extract bindings
	if bindings, ok := features["bindings"].([]string); ok {
		for _, binding := range bindings {
			featureMap["binding_"+binding] = true
		}
	}

	// Extract processors
	if processors, ok := features["processors"].([]string); ok {
		for _, processor := range processors {
			featureMap["processor_"+processor] = true
		}
	}

	// Extract general features
	if hasLicense, ok := features["has_license"].(bool); ok {
		featureMap["has_license"] = hasLicense
	}

	// Add standard features based on license presence
	if featureMap["has_license"] {
		featureMap["jwt_auth"] = true
		featureMap["enterprise_streaming"] = true
		featureMap["advanced_processors"] = true
	}

	return featureMap
}

// IsValid checks if the current license is valid
func (a *SimpleLicenseValidatorAdapter) IsValid() bool {
	if a.checker == nil {
		return false
	}

	features, err := a.checker.GetAllowedFeatures()
	if err != nil {
		return false
	}

	hasLicense, ok := features["has_license"].(bool)
	return ok && hasLicense
}
