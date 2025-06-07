package forms

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
)

// StreamGeneratorV2 provides a unified interface for generating streams from WoT interactions
type StreamGeneratorV2 struct {
	logger             logrus.FieldLogger
	configBuilder      *StreamConfigBuilder
	licenseChecker     LicenseChecker
	streamManager      StreamManager
	persistenceEnabled bool
	persistenceConfig  PersistenceConfig
}

// PersistenceConfig holds configuration for data persistence
type PersistenceConfig struct {
	Enabled    bool
	Format     string // "parquet", "json", "csv"
	BasePath   string
	Partitions []string // e.g., ["year", "month", "day"]
}

// NewStreamGeneratorV2 creates a new unified stream generator
func NewStreamGeneratorV2(logger logrus.FieldLogger, licenseChecker LicenseChecker, streamManager StreamManager) *StreamGeneratorV2 {
	return &StreamGeneratorV2{
		logger:         logger,
		configBuilder:  NewStreamConfigBuilder(logger),
		licenseChecker: licenseChecker,
		streamManager:  streamManager,
	}
}

// SetPersistenceConfig configures data persistence for generated streams
func (g *StreamGeneratorV2) SetPersistenceConfig(config PersistenceConfig) {
	g.persistenceEnabled = config.Enabled
	g.persistenceConfig = config
}

// GeneratePropertyObservationStream creates a stream for property observations
func (g *StreamGeneratorV2) GeneratePropertyObservationStream(
	ctx context.Context,
	thingID string,
	property *wot.PropertyAffordance,
	propertyName string,
	form wot.Form,
) (*types.StreamInfo, error) {
	// Check license for stream feature
	if !g.licenseChecker.IsFeatureAvailable("streams") {
		return nil, fmt.Errorf("streams feature not available in license")
	}

	// Build form configuration
	formConfig := g.extractFormConfig(form, nil) // Properties don't have direct security

	// Create processor configuration
	processors := []ProcessorConfig{
		{
			Type:  "mapping",
			Label: "property_observation_mapping",
			Parameters: map[string]any{
				"ValuePath": "value",
			},
		},
	}

	// Add persistence if enabled
	if g.persistenceEnabled {
		processors = append(processors, ProcessorConfig{
			Type:  "mapping",
			Label: "property_persistence_mapping",
		})
	}

	// Build stream configuration
	config := StreamBuildConfig{
		ThingID:         thingID,
		InteractionType: "property",
		InteractionName: propertyName,
		Purpose:         PurposeObservation,
		Direction:       DirectionInput,
		StreamType:      types.StreamTypePropertyInput,
		InputConfig: StreamEndpointParams{
			Type:       g.getProtocolType(form),
			FormConfig: formConfig,
		},
		OutputConfig: StreamEndpointParams{
			Type: "stream_bridge",
			Config: map[string]any{
				"stream": fmt.Sprintf("property_updates_%s", thingID),
			},
		},
		Processors: processors,
		Metadata: map[string]any{
			"affordance_type": "property",
			"property_type":   property.Type,
			"read_only":       property.ReadOnly,
			"observable":      property.Observable,
		},
	}

	// Generate stream request
	request, err := g.configBuilder.BuildStream(config)
	if err != nil {
		return nil, fmt.Errorf("failed to build stream: %w", err)
	}

	// Register with stream manager
	return g.streamManager.CreateStream(ctx, *request)
}

// GenerateActionCommandStream creates a stream for action commands
func (g *StreamGeneratorV2) GenerateActionCommandStream(
	ctx context.Context,
	thingID string,
	action *wot.ActionAffordance,
	actionName string,
	form wot.Form,
) (*types.StreamInfo, error) {
	// Check license
	if !g.licenseChecker.IsFeatureAvailable("streams") {
		return nil, fmt.Errorf("streams feature not available in license")
	}

	formConfig := g.extractFormConfig(form, nil) // Actions don't have direct security

	processors := []ProcessorConfig{
		{
			Type:  "mapping",
			Label: "action_command_mapping",
			Parameters: map[string]any{
				"ParamsPath": "params",
			},
		},
	}

	config := StreamBuildConfig{
		ThingID:         thingID,
		InteractionType: "action",
		InteractionName: actionName,
		Purpose:         PurposeCommand,
		Direction:       DirectionOutput,
		StreamType:      types.StreamTypeActionOutput,
		InputConfig: StreamEndpointParams{
			Type: "stream_bridge",
			Config: map[string]any{
				"stream": fmt.Sprintf("action_commands_%s", thingID),
			},
		},
		OutputConfig: StreamEndpointParams{
			Type:       g.getProtocolType(form),
			FormConfig: formConfig,
		},
		Processors: processors,
		Metadata: map[string]any{
			"affordance_type": "action",
			"synchronous":     action.Synchronous,
			"safe":            action.Safe,
			"idempotent":      action.Idempotent,
		},
	}

	request, err := g.configBuilder.BuildStream(config)
	if err != nil {
		return nil, fmt.Errorf("failed to build stream: %w", err)
	}

	return g.streamManager.CreateStream(ctx, *request)
}

// GenerateEventNotificationStream creates a stream for event notifications
func (g *StreamGeneratorV2) GenerateEventNotificationStream(
	ctx context.Context,
	thingID string,
	event *wot.EventAffordance,
	eventName string,
	form wot.Form,
) (*types.StreamInfo, error) {
	// Check license
	if !g.licenseChecker.IsFeatureAvailable("streams") {
		return nil, fmt.Errorf("streams feature not available in license")
	}

	formConfig := g.extractFormConfig(form, nil) // Events don't have direct security

	processors := []ProcessorConfig{
		{
			Type:  "mapping",
			Label: "event_notification_mapping",
			Parameters: map[string]any{
				"DataPath": "data",
			},
		},
	}

	config := StreamBuildConfig{
		ThingID:         thingID,
		InteractionType: "event",
		InteractionName: eventName,
		Purpose:         PurposeNotification,
		Direction:       DirectionInput,
		StreamType:      types.StreamTypeEventInput,
		InputConfig: StreamEndpointParams{
			Type:       g.getProtocolType(form),
			FormConfig: formConfig,
		},
		OutputConfig: StreamEndpointParams{
			Type: "stream_bridge",
			Config: map[string]any{
				"stream": fmt.Sprintf("event_notifications_%s", thingID),
			},
		},
		Processors: processors,
		Metadata: map[string]any{
			"affordance_type": "event",
		},
	}

	request, err := g.configBuilder.BuildStream(config)
	if err != nil {
		return nil, fmt.Errorf("failed to build stream: %w", err)
	}

	return g.streamManager.CreateStream(ctx, *request)
}

// GeneratePersistenceStream creates a stream for data persistence
func (g *StreamGeneratorV2) GeneratePersistenceStream(
	ctx context.Context,
	thingID string,
	interactionType string,
	interactionName string,
) (*types.StreamInfo, error) {
	if !g.persistenceEnabled {
		return nil, fmt.Errorf("persistence not enabled")
	}

	// Get schema for the interaction type
	schema := g.configBuilder.schemaRegistry.GetParquetSchema(interactionType)

	// Build output configuration for persistence
	outputConfig, err := g.configBuilder.outputFactory.GeneratePersistenceOutput(
		g.persistenceConfig.Format,
		g.persistenceConfig.BasePath,
		thingID,
		interactionType,
		interactionName,
		schema,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate persistence output: %w", err)
	}

	processors := []ProcessorConfig{
		{
			Type:  "mapping",
			Label: fmt.Sprintf("%s_persistence_mapping", interactionType),
		},
	}

	config := StreamBuildConfig{
		ThingID:         thingID,
		InteractionType: interactionType,
		InteractionName: interactionName,
		Purpose:         PurposePersistence,
		Direction:       DirectionInternal,
		StreamType:      types.BenthosStreamType(fmt.Sprintf("%s_logger", interactionType)),
		InputConfig: StreamEndpointParams{
			Type: "stream_bridge",
			Config: map[string]any{
				"stream": fmt.Sprintf("%s_updates_%s", interactionType, thingID),
			},
		},
		OutputConfig: StreamEndpointParams{
			Type:   outputConfig.Type,
			Config: outputConfig.Config,
		},
		Processors: processors,
		Metadata: map[string]any{
			"purpose":          "persistence",
			"persistence_type": g.persistenceConfig.Format,
		},
	}

	request, err := g.configBuilder.BuildStream(config)
	if err != nil {
		return nil, fmt.Errorf("failed to build stream: %w", err)
	}

	return g.streamManager.CreateStream(ctx, *request)
}

// GenerateAllStreamsForThing generates all streams for a Thing Description
func (g *StreamGeneratorV2) GenerateAllStreamsForThing(
	ctx context.Context,
	td *wot.ThingDescription,
) ([]types.StreamInfo, error) {
	var streams []types.StreamInfo
	thingID := td.ID

	// Generate property streams
	if td.Properties != nil {
		for propName, prop := range td.Properties {
			for _, form := range prop.Forms {
				stream, err := g.GeneratePropertyObservationStream(ctx, thingID, prop, propName, form)
				if err != nil {
					g.logger.WithError(err).Errorf("Failed to generate property stream for %s", propName)
					continue
				}
				streams = append(streams, *stream)
			}

			// Generate persistence stream if enabled
			if g.persistenceEnabled {
				stream, err := g.GeneratePersistenceStream(ctx, thingID, "property", propName)
				if err != nil {
					g.logger.WithError(err).Errorf("Failed to generate persistence stream for property %s", propName)
				} else {
					streams = append(streams, *stream)
				}
			}
		}
	}

	// Generate action streams
	if td.Actions != nil {
		for actionName, action := range td.Actions {
			for _, form := range action.Forms {
				stream, err := g.GenerateActionCommandStream(ctx, thingID, action, actionName, form)
				if err != nil {
					g.logger.WithError(err).Errorf("Failed to generate action stream for %s", actionName)
					continue
				}
				streams = append(streams, *stream)
			}

			// Generate persistence stream if enabled
			if g.persistenceEnabled {
				stream, err := g.GeneratePersistenceStream(ctx, thingID, "action", actionName)
				if err != nil {
					g.logger.WithError(err).Errorf("Failed to generate persistence stream for action %s", actionName)
				} else {
					streams = append(streams, *stream)
				}
			}
		}
	}

	// Generate event streams
	if td.Events != nil {
		for eventName, event := range td.Events {
			for _, form := range event.Forms {
				stream, err := g.GenerateEventNotificationStream(ctx, thingID, event, eventName, form)
				if err != nil {
					g.logger.WithError(err).Errorf("Failed to generate event stream for %s", eventName)
					continue
				}
				streams = append(streams, *stream)
			}

			// Generate persistence stream if enabled
			if g.persistenceEnabled {
				stream, err := g.GeneratePersistenceStream(ctx, thingID, "event", eventName)
				if err != nil {
					g.logger.WithError(err).Errorf("Failed to generate persistence stream for event %s", eventName)
				} else {
					streams = append(streams, *stream)
				}
			}
		}
	}

	return streams, nil
}

// extractFormConfig extracts configuration from a WoT form
func (g *StreamGeneratorV2) extractFormConfig(form wot.Form, security []string) FormConfiguration {
	config := FormConfiguration{
		Href:        form.GetHref(),
		ContentType: form.GetContentType(),
		Security:    security,
		Subprotocol: form.GetSubprotocol(),
		Metadata:    make(map[string]any),
	}
	
	// Store subprotocol in metadata for protocol-specific handling
	if config.Subprotocol != "" {
		config.Metadata["subprotocol"] = config.Subprotocol
	}

	// Type assert to protocol-specific forms for additional fields
	switch f := form.(type) {
	case *wot.HTTPForm:
		// Use htv:methodName if available
		if f.MethodName != "" {
			config.Method = f.MethodName
		}
		// Extract HTTP headers
		if len(f.Headers) > 0 {
			config.Headers = make(map[string]string)
			for _, header := range f.Headers {
				config.Headers[header.FieldName] = header.FieldValue
			}
		}
		// Extract expected status code
		if f.StatusCodeNumber != nil {
			config.StatusCode = f.StatusCodeNumber
		}
	case *wot.MQTTForm:
		// Validate control packet compatibility with operation
		if err := f.ValidateControlPacket(); err != nil {
			g.logger.Warnf("MQTT form validation failed: %v", err)
			// Continue processing but log the warning
		}
		
		// Extract MQTT-specific fields
		if f.Topic != "" {
			config.Topic = f.Topic
		} else if f.Filter != "" {
			config.Topic = f.Filter
		}
		// Convert QoS string to int
		switch f.QoS {
		case "1":
			config.QoS = 1
		case "2":
			config.QoS = 2
		default:
			config.QoS = 0
		}
		// Extract retain flag
		config.Retain = f.Retain
		// Store control packet for validation and future use
		if f.ControlPacket != "" {
			config.Metadata["mqv:controlPacket"] = f.ControlPacket
		}
	case *wot.KafkaForm:
		// Extract Kafka-specific fields
		config.Topic = f.Topic
		
	case *wot.WebSocketForm:
		// Validate WebSocket subprotocol
		if err := f.ValidateSubprotocol(); err != nil {
			g.logger.Warnf("WebSocket form validation failed: %v", err)
		}
		
		// Store WebSocket-specific configuration in metadata
		if f.KeepAlive != nil {
			config.Metadata["ws:keepAlive"] = *f.KeepAlive
		}
		if f.PingInterval != nil {
			config.Metadata["ws:pingInterval"] = *f.PingInterval
		}
		if f.MaxMessageSize != nil {
			config.Metadata["ws:maxMessageSize"] = *f.MaxMessageSize
		}
		
		// Store NATS-specific fields for future implementation
		if f.NATSSubject != "" {
			config.Metadata["nats:subject"] = f.NATSSubject
		}
		if f.NATSQueue != "" {
			config.Metadata["nats:queue"] = f.NATSQueue
		}
	}

	// Fallback: infer HTTP method from operation if not set
	if config.Method == "" && len(form.GetOp()) > 0 {
		config.Method = g.inferHTTPMethod(form.GetOp()[0])
	}

	return config
}

// inferHTTPMethod infers HTTP method from WoT operation type
func (g *StreamGeneratorV2) inferHTTPMethod(operation string) string {
	switch operation {
	case "readproperty":
		return "GET"
	case "writeproperty":
		return "PUT"
	case "invokeaction":
		return "POST"
	case "queryaction":
		return "GET"
	case "cancelaction":
		return "DELETE"
	case "subscribeevent", "unsubscribeevent":
		return "GET"
	default:
		return "GET"
	}
}

// getProtocolType determines the protocol type from a form
func (g *StreamGeneratorV2) getProtocolType(form wot.Form) string {
	// Use the form's GetProtocol method if available
	protocol := form.GetProtocol()
	if protocol != "" {
		return protocol
	}

	// Fallback: Infer from href
	href := form.GetHref()
	switch {
	case href == "" || href[0] == '/':
		return "http"
	case len(href) > 7 && href[:7] == "http://":
		return "http"
	case len(href) > 8 && href[:8] == "https://":
		return "http"
	case len(href) > 7 && href[:7] == "mqtt://":
		return "mqtt"
	case len(href) > 8 && href[:8] == "mqtts://":
		return "mqtt"
	case len(href) > 8 && href[:8] == "kafka://":
		return "kafka"
	default:
		return "http" // Default to HTTP
	}
}
