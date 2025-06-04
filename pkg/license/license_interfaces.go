package license

// LicenseChecker defines the interface for license validation and feature checking
type LicenseChecker interface {
	// Feature checking
	IsFeatureEnabled(category, feature string) (bool, error)
	IsFeatureAvailable(feature string) bool
	GetFeatureConfig(feature string) map[string]any

	// Resource limits
	CheckLimit(resource string, currentCount int) (bool, error)
	GetLimit(resource string) int

	// Capabilities
	IsCapabilityEnabled(capability string) bool
	GetAllowedFeatures() (map[string]any, error)
}
