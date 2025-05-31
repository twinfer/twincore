package binding

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/wot"
	"github.com/twinfer/twincore/pkg/wot/forms"
)

// Integration demonstrates how to use the centralized binding generation
type Integration struct {
	bindingGenerator *forms.BindingGenerator
	logger           logrus.FieldLogger
}

// SimpleLicenseChecker is a basic implementation for demonstration
type SimpleLicenseChecker struct {
	enabledFeatures map[string]bool
}

func NewSimpleLicenseChecker() *SimpleLicenseChecker {
	return &SimpleLicenseChecker{
		enabledFeatures: map[string]bool{
			"property_streaming": true,
			"property_commands":  true,
			"parquet_logging":   true,
			"action_invocation": true,
			"event_processing":  true,
		},
	}
}

func (lc *SimpleLicenseChecker) IsFeatureAvailable(feature string) bool {
	return lc.enabledFeatures[feature]
}

func (lc *SimpleLicenseChecker) GetFeatureConfig(feature string) map[string]interface{} {
	return map[string]interface{}{
		"enabled": lc.IsFeatureAvailable(feature),
	}
}

// NewIntegration creates a new binding integration
func NewIntegration(logger logrus.FieldLogger) *Integration {
	licenseChecker := NewSimpleLicenseChecker()
	bindingGenerator := forms.NewBindingGenerator(logger, licenseChecker)
	
	return &Integration{
		bindingGenerator: bindingGenerator,
		logger:           logger,
	}
}

// ProcessThingDescription demonstrates the complete flow from TD to bindings
func (bi *Integration) ProcessThingDescription(ctx context.Context, td *wot.ThingDescription) (*ProcessingResult, error) {
	bi.logger.WithField("thing_id", td.ID).Info("Processing Thing Description for binding generation")

	// Generate all bindings using centralized approach
	allBindings, err := bi.bindingGenerator.GenerateAllBindings(td)
	if err != nil {
		return nil, fmt.Errorf("failed to generate bindings: %w", err)
	}

	// Create processing result
	result := &ProcessingResult{
		ThingID:      td.ID,
		AllBindings:  allBindings,
		HTTPEndpoints: bi.extractHTTPEndpoints(allBindings),
		StreamConfigs: bi.extractStreamConfigs(allBindings),
		Summary:      bi.generateSummary(allBindings),
	}

	bi.logger.WithFields(logrus.Fields{
		"thing_id":       td.ID,
		"http_endpoints": len(result.HTTPEndpoints),
		"stream_configs": len(result.StreamConfigs),
		"total_processors": result.Summary.TotalProcessors,
	}).Info("Successfully processed Thing Description")

	return result, nil
}

// ProcessingResult contains the complete binding generation results
type ProcessingResult struct {
	ThingID       string                    `json:"thing_id"`
	AllBindings   *forms.AllBindings        `json:"all_bindings"`
	HTTPEndpoints []HTTPEndpointConfig      `json:"http_endpoints"`
	StreamConfigs []StreamDeploymentConfig  `json:"stream_configs"`
	Summary       ProcessingSummary         `json:"summary"`
}

// HTTPEndpointConfig represents a deployable HTTP endpoint
type HTTPEndpointConfig struct {
	ID          string            `json:"id"`
	Path        string            `json:"path"`
	Method      string            `json:"method"`
	ContentType string            `json:"content_type"`
	Headers     map[string]string `json:"headers,omitempty"`
	Security    []string          `json:"security,omitempty"`
	Interaction InteractionInfo   `json:"interaction"`
}

// StreamDeploymentConfig represents a deployable Benthos stream
type StreamDeploymentConfig struct {
	ID           string                `json:"id"`
	Name         string                `json:"name"`
	Type         string                `json:"type"`
	Direction    string                `json:"direction"`
	YAML         string                `json:"yaml"`
	Interaction  InteractionInfo       `json:"interaction"`
	ProcessorCount int                 `json:"processor_count"`
}

// InteractionInfo provides context about the WoT interaction
type InteractionInfo struct {
	Type string `json:"type"` // "property", "action", "event"
	Name string `json:"name"`
	Purpose string `json:"purpose"` // "observation", "command", "logging", etc.
}

// ProcessingSummary provides high-level statistics
type ProcessingSummary struct {
	TotalHTTPEndpoints int `json:"total_http_endpoints"`
	TotalStreams       int `json:"total_streams"`
	TotalProcessors    int `json:"total_processors"`
	FeatureBreakdown   map[string]int `json:"feature_breakdown"`
}

// Helper methods to extract deployable configurations

func (bi *Integration) extractHTTPEndpoints(bindings *forms.AllBindings) []HTTPEndpointConfig {
	var endpoints []HTTPEndpointConfig
	
	for routeID, route := range bindings.HTTPRoutes {
		// Parse interaction info from route ID
		interaction := bi.parseInteractionFromRouteID(routeID)
		
		endpoint := HTTPEndpointConfig{
			ID:          routeID,
			Path:        route.Path,
			Method:      route.Method,
			ContentType: route.ContentType,
			Headers:     route.Headers,
			Security:    route.Security,
			Interaction: interaction,
		}
		
		endpoints = append(endpoints, endpoint)
	}
	
	return endpoints
}

func (bi *Integration) extractStreamConfigs(bindings *forms.AllBindings) []StreamDeploymentConfig {
	var configs []StreamDeploymentConfig
	
	for streamID, stream := range bindings.Streams {
		// Parse interaction info from stream ID
		interaction := bi.parseInteractionFromStreamID(streamID)
		
		config := StreamDeploymentConfig{
			ID:             streamID,
			Name:           streamID,
			Type:           string(stream.Type),
			Direction:      string(stream.Direction),
			YAML:           stream.YAML,
			Interaction:    interaction,
			ProcessorCount: len(stream.ProcessorChain.Processors),
		}
		
		configs = append(configs, config)
	}
	
	return configs
}

func (bi *Integration) generateSummary(bindings *forms.AllBindings) ProcessingSummary {
	totalProcessors := 0
	featureBreakdown := make(map[string]int)
	
	// Count processors and categorize by purpose
	for _, stream := range bindings.Streams {
		totalProcessors += len(stream.ProcessorChain.Processors)
		
		// Categorize stream purpose
		purpose := bi.categorizeStreamPurpose(string(stream.Type))
		featureBreakdown[purpose]++
	}
	
	return ProcessingSummary{
		TotalHTTPEndpoints: len(bindings.HTTPRoutes),
		TotalStreams:       len(bindings.Streams),
		TotalProcessors:    totalProcessors,
		FeatureBreakdown:   featureBreakdown,
	}
}

// Helper methods for parsing and categorization

func (bi *Integration) parseInteractionFromRouteID(routeID string) InteractionInfo {
	// Parse routeID format: {thingID}_{type}_{name}_form_{index}
	// Example: "sensor1_property_temperature_form_0"
	
	// Simple parsing - in production, use more robust parsing
	if contains(routeID, "_property_") {
		return InteractionInfo{Type: "property", Name: "parsed_name", Purpose: "endpoint"}
	} else if contains(routeID, "_action_") {
		return InteractionInfo{Type: "action", Name: "parsed_name", Purpose: "endpoint"}
	} else if contains(routeID, "_event_") {
		return InteractionInfo{Type: "event", Name: "parsed_name", Purpose: "endpoint"}
	}
	
	return InteractionInfo{Type: "unknown", Name: "unknown", Purpose: "endpoint"}
}

func (bi *Integration) parseInteractionFromStreamID(streamID string) InteractionInfo {
	// Parse streamID format: {thingID}_{type}_{name}_{purpose}
	// Example: "sensor1_property_temperature_logging"
	
	if contains(streamID, "_property_") {
		if contains(streamID, "_logging") {
			return InteractionInfo{Type: "property", Name: "parsed_name", Purpose: "logging"}
		} else if contains(streamID, "_observation") {
			return InteractionInfo{Type: "property", Name: "parsed_name", Purpose: "observation"}
		} else if contains(streamID, "_commands") {
			return InteractionInfo{Type: "property", Name: "parsed_name", Purpose: "command"}
		}
	}
	
	return InteractionInfo{Type: "unknown", Name: "unknown", Purpose: "unknown"}
}

func (bi *Integration) categorizeStreamPurpose(streamType string) string {
	switch streamType {
	case "property_logger", "action_logger", "event_logger":
		return "logging"
	case "property_input", "action_input", "event_input":
		return "ingestion"
	case "property_output", "action_output", "event_output":
		return "command"
	default:
		return "other"
	}
}

// Simple helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && 
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || 
		 findInString(s, substr))))
}

func findInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}