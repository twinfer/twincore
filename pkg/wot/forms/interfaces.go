package forms

import (
	"context"

	"github.com/twinfer/twincore/pkg/types"
)

// LicenseChecker interface for checking feature availability
type LicenseChecker interface {
	IsFeatureEnabled(category, feature string) (bool, error)
	CheckLimit(resource string, currentCount int) (bool, error)
	GetAllowedFeatures() (map[string]interface{}, error)
	IsFeatureAvailable(feature string) bool
	GetFeatureConfig(feature string) map[string]interface{}
}

// StreamManager interface defines the subset of BenthosStreamManager needed by forms package
type StreamManager interface {
	CreateStream(ctx context.Context, request types.StreamCreationRequest) (*types.StreamInfo, error)
}