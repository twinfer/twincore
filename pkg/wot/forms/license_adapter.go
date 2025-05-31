package forms

import (
	"fmt"
	"github.com/sirupsen/logrus"
)

// SimpleLicenseChecker interface that matches our JWT implementation
type SimpleLicenseChecker interface {
	IsFeatureEnabled(category, feature string) (bool, error)
	CheckLimit(resource string, currentCount int) (bool, error)
	GetAllowedFeatures() (map[string]interface{}, error)
	IsFeatureAvailable(feature string) bool
	GetFeatureConfig(feature string) map[string]interface{}
}

// LicenseAdapter adapts SimpleLicenseChecker to LicenseChecker interface
type LicenseAdapter struct {
	checker SimpleLicenseChecker
	logger  logrus.FieldLogger
}

// NewLicenseAdapter creates an adapter for the simple license checker
func NewLicenseAdapter(checker SimpleLicenseChecker, logger logrus.FieldLogger) *LicenseAdapter {
	return &LicenseAdapter{
		checker: checker,
		logger:  logger,
	}
}

// Implement LicenseChecker interface

func (a *LicenseAdapter) IsFeatureEnabled(category, feature string) (bool, error) {
	return a.checker.IsFeatureEnabled(category, feature)
}

func (a *LicenseAdapter) CheckLimit(resource string, currentCount int) (bool, error) {
	return a.checker.CheckLimit(resource, currentCount)
}

func (a *LicenseAdapter) GetAllowedFeatures() (map[string]interface{}, error) {
	return a.checker.GetAllowedFeatures()
}

// Backward compatibility methods for existing BindingGenerator code
func (a *LicenseAdapter) IsFeatureAvailable(feature string) bool {
	return a.checker.IsFeatureAvailable(feature)
}

func (a *LicenseAdapter) GetFeatureConfig(feature string) map[string]interface{} {
	return a.checker.GetFeatureConfig(feature)
}

// Helper methods for enhanced license checking

// IsBindingAllowed checks if a specific binding protocol is allowed
func (a *LicenseAdapter) IsBindingAllowed(protocol string) bool {
	enabled, err := a.checker.IsFeatureEnabled("bindings", protocol)
	if err != nil {
		a.logger.WithError(err).WithField("protocol", protocol).Warn("Failed to check binding permission")
		return false
	}
	return enabled
}

// IsProcessorAllowed checks if a specific processor is allowed
func (a *LicenseAdapter) IsProcessorAllowed(processorType string) bool {
	enabled, err := a.checker.IsFeatureEnabled("processors", processorType)
	if err != nil {
		a.logger.WithError(err).WithField("processor", processorType).Warn("Failed to check processor permission")
		return false
	}
	return enabled
}

// IsStorageAllowed checks if a specific storage backend is allowed
func (a *LicenseAdapter) IsStorageAllowed(storageType string) bool {
	enabled, err := a.checker.IsFeatureEnabled("storage", storageType)
	if err != nil {
		a.logger.WithError(err).WithField("storage", storageType).Warn("Failed to check storage permission")
		return false
	}
	return enabled
}

// GetResourceLimit returns the limit for a specific resource
func (a *LicenseAdapter) GetResourceLimit(resource string) int {
	features, err := a.checker.GetAllowedFeatures()
	if err != nil {
		a.logger.WithError(err).Warn("Failed to get resource limits")
		return 0
	}

	capabilities, ok := features["capabilities"].(map[string]interface{})
	if !ok {
		return 0
	}

	switch resource {
	case "things":
		if limit, ok := capabilities["max_things"].(int); ok {
			return limit
		}
	case "streams":
		if limit, ok := capabilities["max_streams"].(int); ok {
			return limit
		}
	case "users":
		if limit, ok := capabilities["max_users"].(int); ok {
			return limit
		}
	}

	return 0
}

// ValidateFeatureUsage validates if a feature can be used based on current usage
func (a *LicenseAdapter) ValidateFeatureUsage(feature string, currentCount int) (bool, string) {
	// Check if feature is enabled
	if !a.IsFeatureAvailable(feature) {
		return false, "feature not enabled in license"
	}

	// Check resource limits for features that have them
	resourceMap := map[string]string{
		"property_streaming": "streams",
		"action_invocation":  "streams",
		"event_processing":   "streams",
	}

	if resource, hasLimit := resourceMap[feature]; hasLimit {
		withinLimit, err := a.CheckLimit(resource, currentCount)
		if err != nil {
			a.logger.WithError(err).WithFields(logrus.Fields{
				"feature":       feature,
				"resource":      resource,
				"current_count": currentCount,
			}).Warn("Failed to check resource limit")
			return false, "failed to check resource limit"
		}

		if !withinLimit {
			limit := a.GetResourceLimit(resource)
			return false, fmt.Sprintf("resource limit exceeded: %d/%d %s", currentCount, limit, resource)
		}
	}

	return true, ""
}
