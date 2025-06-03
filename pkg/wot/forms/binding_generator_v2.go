package forms

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
)

// BindingGeneratorV2 is a simplified version that uses the unified stream generator
type BindingGeneratorV2 struct {
	logger          logrus.FieldLogger
	streamGenerator *StreamGeneratorV2
}

// NewBindingGeneratorV2 creates a new binding generator using the unified system
func NewBindingGeneratorV2(logger logrus.FieldLogger, licenseChecker LicenseChecker, streamManager StreamManager) *BindingGeneratorV2 {
	return &BindingGeneratorV2{
		logger:          logger,
		streamGenerator: NewStreamGeneratorV2(logger, licenseChecker, streamManager),
	}
}

// SetPersistenceConfig configures data persistence
func (bg *BindingGeneratorV2) SetPersistenceConfig(config PersistenceConfig) {
	bg.streamGenerator.SetPersistenceConfig(config)
}

// GenerateAllBindings generates all bindings from a Thing Description
func (bg *BindingGeneratorV2) GenerateAllBindings(ctx context.Context, td *wot.ThingDescription) (*types.AllBindings, error) {
	bindings := &types.AllBindings{
		ThingID:     td.ID,
		HTTPRoutes:  make(map[string]types.BindingHTTPRoute),
		Streams:     make(map[string]types.BenthosStreamConfig),
		Processors:  make(map[string]types.ProcessorChain),
		GeneratedAt: time.Now(),
	}

	// Generate HTTP routes
	if err := bg.generateHTTPRoutes(td, bindings); err != nil {
		return nil, fmt.Errorf("failed to generate HTTP routes: %w", err)
	}

	// Generate streams using the unified generator
	streams, err := bg.streamGenerator.GenerateAllStreamsForThing(ctx, td)
	if err != nil {
		return nil, fmt.Errorf("failed to generate streams: %w", err)
	}

	// Convert streams to binding format
	for _, stream := range streams {
		streamConfig := bg.convertStreamToBindingFormat(stream)
		bindings.Streams[stream.ID] = streamConfig
	}

	// Generate processors (if needed separately)
	if err := bg.generateProcessors(td, bindings); err != nil {
		return nil, fmt.Errorf("failed to generate processors: %w", err)
	}

	return bindings, nil
}

// generateHTTPRoutes generates HTTP routes for all interactions
func (bg *BindingGeneratorV2) generateHTTPRoutes(td *wot.ThingDescription, bindings *types.AllBindings) error {
	// Properties
	if td.Properties != nil {
		for propName, prop := range td.Properties {
			for _, form := range prop.Forms {
				if bg.isHTTPForm(form) {
					route := bg.generateHTTPRoute(form, nil) // Properties don't have Security field
					routeKey := fmt.Sprintf("properties_%s", propName)
					bindings.HTTPRoutes[routeKey] = route
				}
			}
		}
	}

	// Actions
	if td.Actions != nil {
		for actionName, action := range td.Actions {
			for _, form := range action.Forms {
				if bg.isHTTPForm(form) {
					route := bg.generateHTTPRoute(form, nil) // Actions don't have Security field
					routeKey := fmt.Sprintf("actions_%s", actionName)
					bindings.HTTPRoutes[routeKey] = route
				}
			}
		}
	}

	// Events
	if td.Events != nil {
		for eventName, event := range td.Events {
			for _, form := range event.Forms {
				if bg.isHTTPForm(form) {
					route := bg.generateHTTPRoute(form, nil) // Events don't have Security field
					routeKey := fmt.Sprintf("events_%s", eventName)
					bindings.HTTPRoutes[routeKey] = route
				}
			}
		}
	}

	return nil
}

// generateHTTPRoute creates an HTTP route from a form
func (bg *BindingGeneratorV2) generateHTTPRoute(form wot.Form, security []string) types.BindingHTTPRoute {
	route := types.BindingHTTPRoute{
		Path:        form.GetHref(),
		ContentType: form.GetContentType(),
		Security:    security,
		Headers:     make(map[string]string),
	}

	// Extract method from operations
	op := form.GetOp()
	if op != nil && len(op) > 0 {
		route.Method = op[0]
	} else {
		route.Method = "GET" // Default
	}

	return route
}

// generateProcessors generates processor chains
func (bg *BindingGeneratorV2) generateProcessors(td *wot.ThingDescription, bindings *types.AllBindings) error {
	// This is simplified - in practice, processors might be generated
	// based on specific requirements or transformations needed

	// Example: Create a default processor chain for property updates
	bindings.Processors["property_updates"] = types.ProcessorChain{
		ID:   fmt.Sprintf("property_updates_%s", td.ID),
		Name: "Property Update Processor",
		Processors: []types.ProcessorConfigItem{
			{
				Type:  types.BenthosProcessorType("bloblang"),
				Label: "add_metadata",
				Config: map[string]interface{}{
					"bloblang": `root = this
root.processed_at = timestamp_unix_nano()
root.processor_version = "1.0"`,
				},
			},
		},
		Metadata: map[string]interface{}{
			"generated_for": td.ID,
		},
	}

	return nil
}

// convertStreamToBindingFormat converts a stream info to binding format
func (bg *BindingGeneratorV2) convertStreamToBindingFormat(stream types.StreamInfo) types.BenthosStreamConfig {
	// Extract stream type from metadata or derive it
	streamType := types.BenthosStreamType("property_logger") // Default
	if st, ok := stream.Metadata["stream_type"].(string); ok {
		streamType = types.BenthosStreamType(st)
	}

	// Extract direction
	direction := types.StreamDirectionInternal // Default
	switch stream.Direction {
	case "input":
		direction = types.StreamDirectionInbound
	case "output":
		direction = types.StreamDirectionOutbound
	case "internal":
		direction = types.StreamDirectionInternal
	}

	// Convert endpoints
	inputEndpoint := types.StreamEndpoint{
		Protocol: types.StreamProtocol(stream.Input.Type),
		Config:   stream.Input.Config,
	}

	outputEndpoint := types.StreamEndpoint{
		Protocol: types.StreamProtocol(stream.Output.Type),
		Config:   stream.Output.Config,
	}

	// Convert processor chain
	processorChain := types.ProcessorChain{
		ID:         stream.ID + "_processors",
		Name:       fmt.Sprintf("Processors for %s", stream.ID),
		Processors: bg.convertProcessors(stream.ProcessorChain),
	}

	return types.BenthosStreamConfig{
		ID:             stream.ID,
		Type:           streamType,
		Direction:      direction,
		Input:          inputEndpoint,
		Output:         outputEndpoint,
		ProcessorChain: processorChain,
		YAML:           "", // Would be generated if needed
	}
}

// convertProcessors converts processor configs to binding format
func (bg *BindingGeneratorV2) convertProcessors(processors []types.ProcessorConfig) []types.ProcessorConfigItem {
	items := make([]types.ProcessorConfigItem, 0, len(processors))

	for _, p := range processors {
		items = append(items, types.ProcessorConfigItem{
			Type:   types.BenthosProcessorType(p.Type),
			Label:  fmt.Sprintf("processor_%d", len(items)),
			Config: p.Config,
		})
	}

	return items
}

// isHTTPForm checks if a form uses HTTP protocol
func (bg *BindingGeneratorV2) isHTTPForm(form wot.Form) bool {
	// Check by protocol method if available
	if form.GetProtocol() == "http" {
		return true
	}

	// Infer from href
	href := form.GetHref()
	if href == "" || href[0] == '/' {
		return true // Relative URLs are HTTP
	}

	return (len(href) > 7 && (href[:7] == "http://" || (len(href) > 8 && href[:8] == "https://")))
}
