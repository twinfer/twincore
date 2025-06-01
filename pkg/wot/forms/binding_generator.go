package forms

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
)

// BindingGenerator centralizes all protocol binding generation from Thing Descriptions
type BindingGenerator struct {
	logger         logrus.FieldLogger
	parquetConfig  types.ParquetConfig
	kafkaConfig    types.KafkaConfig
	mqttConfig     types.MQTTConfig
	licenseChecker LicenseChecker
	streamManager  types.BenthosStreamManager // Connect to existing stream manager
}

// LicenseChecker interface for checking feature availability
// Updated to match the simplified JWT checker interface
type LicenseChecker interface {
	IsFeatureEnabled(category, feature string) (bool, error)
	CheckLimit(resource string, currentCount int) (bool, error)
	GetAllowedFeatures() (map[string]interface{}, error)
	// Backward compatibility method for simple feature checks
	IsFeatureAvailable(feature string) bool
	GetFeatureConfig(feature string) map[string]interface{}
}

// NewBindingGenerator creates a new binding generator with existing dependencies
func NewBindingGenerator(
	logger logrus.FieldLogger,
	licenseChecker LicenseChecker,
	streamManager types.BenthosStreamManager,
	parquetConfig types.ParquetConfig,
	kafkaConfig types.KafkaConfig,
	mqttConfig types.MQTTConfig,
) *BindingGenerator {
	return &BindingGenerator{
		logger:         logger,
		licenseChecker: licenseChecker,
		streamManager:  streamManager,
		parquetConfig:  parquetConfig,
		kafkaConfig:    kafkaConfig,
		mqttConfig:     mqttConfig,
	}
}

// GenerateAllBindings generates all bindings (HTTP routes + Benthos streams) from a Thing Description
func (bg *BindingGenerator) GenerateAllBindings(logger logrus.FieldLogger, td *wot.ThingDescription) (*AllBindings, error) {
	methodLogger := logger.WithFields(logrus.Fields{
		"component": "BindingGenerator",
		"thing_id":  td.ID,
	})
	methodLogger.Info("Starting binding generation for Thing Description")
	bindings := &AllBindings{
		ThingID:     td.ID,
		HTTPRoutes:  make(map[string]HTTPRoute),
		Streams:     make(map[string]StreamConfig),
		Processors:  make(map[string]ProcessorChain),
		GeneratedAt: time.Now(),
	}

	// Generate property bindings
	for propName, prop := range td.Properties {
		if err := bg.generatePropertyBindings(methodLogger, td.ID, propName, prop, bindings); err != nil {
			// generatePropertyBindings will log its own errors with the passed methodLogger
			return nil, fmt.Errorf("failed to generate property bindings for %s: %w", propName, err)
		}
	}

	// Generate action bindings
	for actionName, action := range td.Actions {
		if err := bg.generateActionBindings(methodLogger, td.ID, actionName, action, bindings); err != nil {
			// generateActionBindings will log its own errors
			return nil, fmt.Errorf("failed to generate action bindings for %s: %w", actionName, err)
		}
	}

	// Generate event bindings
	for eventName, event := range td.Events {
		if err := bg.generateEventBindings(methodLogger, td.ID, eventName, event, bindings); err != nil {
			// generateEventBindings will log its own errors
			return nil, fmt.Errorf("failed to generate event bindings for %s: %w", eventName, err)
		}
	}

	methodLogger.WithFields(logrus.Fields{
		"thing_id":    td.ID,
		"http_routes": len(bindings.HTTPRoutes),
		"streams":     len(bindings.Streams),
		"processors":  len(bindings.Processors),
	}).Info("Generated all bindings for Thing Description")

	return bindings, nil
}

// AllBindings contains all generated bindings for a Thing Description
type AllBindings struct {
	ThingID     string                    `json:"thing_id"`
	HTTPRoutes  map[string]HTTPRoute      `json:"http_routes"`
	Streams     map[string]StreamConfig   `json:"streams"`
	Processors  map[string]ProcessorChain `json:"processors"`
	GeneratedAt time.Time                 `json:"generated_at"`
}

// HTTPRoute represents an HTTP endpoint configuration
type HTTPRoute struct {
	Path        string            `json:"path"`
	Method      string            `json:"method"`
	ContentType string            `json:"content_type"`
	Headers     map[string]string `json:"headers,omitempty"`
	Security    []string          `json:"security,omitempty"`
}

// StreamConfig represents a complete Benthos stream configuration
type StreamConfig struct {
	ID             string                  `json:"id"`
	Type           types.BenthosStreamType `json:"type"`
	Direction      types.StreamDirection   `json:"direction"`
	Input          StreamEndpoint          `json:"input"`
	Output         StreamEndpoint          `json:"output"`
	ProcessorChain ProcessorChain          `json:"processor_chain"`
	YAML           string                  `json:"yaml"`
}

// StreamEndpoint represents input/output configuration for streams
type StreamEndpoint struct {
	Protocol types.StreamProtocol   `json:"protocol"`
	Config   map[string]interface{} `json:"config"`
}

// ProcessorChain represents a sequence of Benthos processors
type ProcessorChain struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Processors []ProcessorConfig      `json:"processors"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// ProcessorConfig represents a single Benthos processor configuration
type ProcessorConfig struct {
	Type        types.BenthosProcessorType `json:"type"`
	Label       string                     `json:"label"`
	Config      map[string]interface{}     `json:"config"`
	Description string                     `json:"description,omitempty"`
}

// generatePropertyBindings creates all bindings for a property affordance
func (bg *BindingGenerator) generatePropertyBindings(logger logrus.FieldLogger, thingID, propName string, prop *wot.PropertyAffordance, bindings *AllBindings) error {
	opLogger := logger.WithFields(logrus.Fields{"property_name": propName, "operation": "generatePropertyBindings"})
	opLogger.Debug("Generating bindings for property")
	// Generate HTTP routes from forms
	for i, form := range prop.Forms {
		routeID := fmt.Sprintf("%s_property_%s_form_%d", thingID, propName, i)
		route := HTTPRoute{
			Path:        strings.Replace(form.GetHref(), "{thingId}", thingID, -1),
			Method:      bg.getHTTPMethod(form.GetOp()),
			ContentType: form.GetContentType(),
		}
		bindings.HTTPRoutes[routeID] = route
	}

	// Generate streams for observable properties
	if prop.IsObservable() && bg.licenseChecker.IsFeatureAvailable("property_streaming") {
		if err := generatePropertyObservationStream(opLogger, bg, thingID, propName, prop); err != nil { // Pass opLogger
			// Error already logged by generatePropertyObservationStream if it's significant internally
			return err
		}
	}

	// Generate streams for writable properties
	if !prop.IsReadOnly() && bg.licenseChecker.IsFeatureAvailable("property_commands") {
		if err := generatePropertyCommandStream(opLogger, bg, thingID, propName, prop); err != nil { // Pass opLogger
			return err
		}
	}

	// Generate persistence stream if data persistence is enabled
	if bg.licenseChecker.IsFeatureAvailable("data_persistence") {
		if err := generatePropertyLoggingStream(opLogger, bg, thingID, propName, prop); err != nil { // Pass opLogger
			return err
		}
	}

	return nil
}

// generateActionBindings creates all bindings for an action affordance
func (bg *BindingGenerator) generateActionBindings(logger logrus.FieldLogger, thingID, actionName string, action *wot.ActionAffordance, bindings *AllBindings) error {
	opLogger := logger.WithFields(logrus.Fields{"action_name": actionName, "operation": "generateActionBindings"})
	opLogger.Debug("Generating bindings for action")
	// Generate HTTP routes from forms
	for i, form := range action.Forms {
		routeID := fmt.Sprintf("%s_action_%s_form_%d", thingID, actionName, i)
		route := HTTPRoute{
			Path:        strings.Replace(form.GetHref(), "{thingId}", thingID, -1),
			Method:      "POST", // Actions are typically POST
			ContentType: form.GetContentType(),
		}
		bindings.HTTPRoutes[routeID] = route
	}

	// Generate action invocation stream
	if bg.licenseChecker.IsFeatureAvailable("action_invocation") {
		if err := generateActionInvocationStream(opLogger, bg, thingID, actionName, action); err != nil { // Pass opLogger
			return err
		}
	}

	// Generate action persistence stream
	if bg.licenseChecker.IsFeatureAvailable("data_persistence") {
		if err := generateActionLoggingStream(opLogger, bg, thingID, actionName, action); err != nil { // Pass opLogger
			return err
		}
	}

	return nil
}

// generateEventBindings creates all bindings for an event affordance
func (bg *BindingGenerator) generateEventBindings(logger logrus.FieldLogger, thingID, eventName string, event *wot.EventAffordance, bindings *AllBindings) error {
	opLogger := logger.WithFields(logrus.Fields{"event_name": eventName, "operation": "generateEventBindings"})
	opLogger.Debug("Generating bindings for event")
	// Generate HTTP routes from forms (typically SSE endpoints)
	for i, form := range event.Forms {
		routeID := fmt.Sprintf("%s_event_%s_form_%d", thingID, eventName, i)
		route := HTTPRoute{
			Path:        strings.Replace(form.GetHref(), "{thingId}", thingID, -1),
			Method:      "GET", // Events are typically GET for SSE
			ContentType: "text/event-stream",
		}
		bindings.HTTPRoutes[routeID] = route
	}

	// Generate event processing stream
	if bg.licenseChecker.IsFeatureAvailable("event_processing") {
		if err := generateEventProcessingStream(opLogger, bg, thingID, eventName, event); err != nil { // Pass opLogger
			return err
		}
	}

	// Generate event persistence stream
	if bg.licenseChecker.IsFeatureAvailable("data_persistence") {
		if err := generateEventLoggingStream(opLogger, bg, thingID, eventName, event); err != nil { // Pass opLogger
			return err
		}
	}

	return nil
}

// Helper methods for HTTP operations
func (bg *BindingGenerator) getHTTPMethod(ops []string) string {
	for _, op := range ops {
		switch op {
		case "readproperty", "observeproperty", "subscribeevent":
			return "GET"
		case "writeproperty":
			return "PUT"
		case "invokeaction":
			return "POST"
		}
	}
	return "GET" // Default
}

// Placeholder methods for action and event stream generation
// These will be refactored in subsequent steps. For now, they are copied as is.
// Calls to bg.generate[Type]Mapping, bg.generate[Type]ParquetSchema, and bg.convertDataSchemaToJSONSchema
// will be updated in step 5.

func (bg *BindingGenerator) generatePropertyObservationStream(thingID, propName string, prop *wot.PropertyAffordance, bindings *AllBindings) error {
	// License validation at app level
	if !bg.licenseChecker.IsFeatureAvailable("property_streaming") {
		bg.logger.WithField("feature", "property_streaming").Debug("Property streaming not available in license")
		return nil
	}

	streamID := fmt.Sprintf("%s_property_%s_observation", thingID, propName)
	topic := fmt.Sprintf("things.%s.properties.%s", thingID, propName)

	bg.logger.WithFields(logrus.Fields{
		"stream_id": streamID,
		"thing_id":  thingID,
		"property":  propName,
		"topic":     topic,
	}).Debug("Generating property observation stream")

	// Create processor chain for property observation
	processorChainID := fmt.Sprintf("%s_observation_processors", streamID)
	processors := []ProcessorConfig{
		{
			Type:  types.ProcessorBloblangWoTProperty,
			Label: "property_observation_mapping",
			Config: map[string]interface{}{
				"mapping": generatePropertyObservationMapping(thingID, propName),
			},
			Description: "Map property data for observation clients",
		},
	}

	// Add schema validation if property has a schema
	if prop.Type != "" {
		jsonSchema := convertDataSchemaToJSONSchema(prop.DataSchemaCore)
		processors = append(processors, ProcessorConfig{
			Type:  types.ProcessorJSONSchema,
			Label: "property_schema_validation",
			Config: map[string]interface{}{
				"schema": jsonSchema,
			},
			Description: "Validate property data against Thing Description schema",
		})
	}

	// Store processor chain
	bindings.Processors[processorChainID] = ProcessorChain{
		ID:         processorChainID,
		Name:       fmt.Sprintf("Property %s observation processors", propName),
		Processors: processors,
		Metadata: map[string]interface{}{
			"thing_id":         thingID,
			"property_name":    propName,
			"interaction_type": "property",
			"purpose":          "observation",
		},
	}

	observationConfig := bg.licenseChecker.GetFeatureConfig("property_streaming")
	outputConfig, err := bg.generateObservationOutputConfig(thingID, propName, observationConfig)
	if err != nil {
		return fmt.Errorf("failed to generate observation output config: %w", err)
	}

	request := types.StreamCreationRequest{
		ThingID:         thingID,
		InteractionType: "properties",
		InteractionName: propName,
		Direction:       "output",
		Input: types.StreamEndpointConfig{
			Type: "kafka",
			Config: map[string]interface{}{
				"addresses":      bg.kafkaConfig.Brokers,
				"topics":         []string{topic},
				"consumer_group": fmt.Sprintf("twincore-property-observation-%s", thingID),
			},
		},
		Output:         outputConfig,
		ProcessorChain: bg.convertToTypesProcessorConfig(processors),
		Metadata: map[string]interface{}{
			"generated_by": "centralized_binding_generator",
			"purpose":      "property_observation",
			"created_at":   time.Now().UTC().Format(time.RFC3339),
		},
	}

	yamlConfig, err := bg.generateStreamRequestYAML(request)
	if err != nil {
		return fmt.Errorf("failed to generate YAML for property observation stream %s: %w", streamID, err)
	}

	request.Metadata["yaml_config"] = yamlConfig

	streamInfo, err := bg.streamManager.CreateStream(context.Background(), request)
	if err != nil {
		return fmt.Errorf("failed to create property observation stream %s: %w", streamID, err)
	}

	streamConfig := StreamConfig{
		ID:        streamInfo.ID,
		Type:      types.StreamTypePropertyOutput,
		Direction: types.StreamDirectionOutbound,
		Input: StreamEndpoint{
			Protocol: types.ProtocolKafka,
			Config:   request.Input.Config,
		},
		Output: StreamEndpoint{
			Protocol: types.StreamProtocol(outputConfig.Type),
			Config:   outputConfig.Config,
		},
		ProcessorChain: bindings.Processors[processorChainID],
		YAML:           "",
	}

	bindings.Streams[streamID] = streamConfig

	bg.logger.WithFields(logrus.Fields{
		"stream_id":       streamInfo.ID,
		"stream_status":   streamInfo.Status,
		"processor_count": len(processors),
		"output_type":     outputConfig.Type,
	}).Info("Property observation stream created successfully")

	return nil
}

func (bg *BindingGenerator) generatePropertyCommandStream(thingID, propName string, prop *wot.PropertyAffordance, bindings *AllBindings) error {
	if !bg.licenseChecker.IsFeatureAvailable("property_commands") {
		bg.logger.WithField("feature", "property_commands").Debug("Property commands not available in license")
		return nil
	}

	streamID := fmt.Sprintf("%s_property_%s_command", thingID, propName)
	topic := fmt.Sprintf("things.%s.properties.%s.commands", thingID, propName)

	bg.logger.WithFields(logrus.Fields{
		"stream_id": streamID,
		"thing_id":  thingID,
		"property":  propName,
		"topic":     topic,
	}).Debug("Generating property command stream")

	processorChainID := fmt.Sprintf("%s_command_processors", streamID)
	processors := []ProcessorConfig{
		{
			Type:  types.ProcessorBloblangWoTProperty,
			Label: "property_command_mapping",
			Config: map[string]interface{}{
				"mapping": generatePropertyCommandMapping(thingID, propName),
			},
			Description: "Map property command data for device execution",
		},
	}

	if prop.Type != "" {
		jsonSchema := convertDataSchemaToJSONSchema(prop.DataSchemaCore)
		processors = append(processors, ProcessorConfig{
			Type:  types.ProcessorJSONSchema,
			Label: "property_command_validation",
			Config: map[string]interface{}{
				"schema": jsonSchema,
			},
			Description: "Validate property command against Thing Description schema",
		})
	}

	processors = append(processors, ProcessorConfig{
		Type:  types.ProcessorBloblangWoTProperty,
		Label: "device_command_transform",
		Config: map[string]interface{}{
			"mapping": generateDeviceCommandMapping(thingID, propName),
		},
		Description: "Transform command for device-specific protocol",
	})

	bindings.Processors[processorChainID] = ProcessorChain{
		ID:         processorChainID,
		Name:       fmt.Sprintf("Property %s command processors", propName),
		Processors: processors,
		Metadata: map[string]interface{}{
			"thing_id":         thingID,
			"property_name":    propName,
			"interaction_type": "property",
			"purpose":          "command",
		},
	}

	commandConfig := bg.licenseChecker.GetFeatureConfig("property_commands")
	outputConfig, err := bg.generateCommandOutputConfig(thingID, propName, commandConfig)
	if err != nil {
		return fmt.Errorf("failed to generate command output config: %w", err)
	}

	request := types.StreamCreationRequest{
		ThingID:         thingID,
		InteractionType: "properties",
		InteractionName: propName,
		Direction:       "input",
		Input: types.StreamEndpointConfig{
			Type: "http_server",
			Config: map[string]interface{}{
				"address":       "${HTTP_ADDRESS:0.0.0.0:8080}",
				"path":          fmt.Sprintf("/things/%s/properties/%s", thingID, propName),
				"allowed_verbs": []string{"PUT", "PATCH"},
				"timeout":       "30s",
			},
		},
		Output:         outputConfig,
		ProcessorChain: bg.convertToTypesProcessorConfig(processors),
		Metadata: map[string]interface{}{
			"generated_by": "centralized_binding_generator",
			"purpose":      "property_command",
			"created_at":   time.Now().UTC().Format(time.RFC3339),
		},
	}

	yamlConfig, err := bg.generateStreamRequestYAML(request)
	if err != nil {
		return fmt.Errorf("failed to generate YAML for property command stream %s: %w", streamID, err)
	}

	request.Metadata["yaml_config"] = yamlConfig

	streamInfo, err := bg.streamManager.CreateStream(context.Background(), request)
	if err != nil {
		return fmt.Errorf("failed to create property command stream %s: %w", streamID, err)
	}

	streamConfig := StreamConfig{
		ID:        streamInfo.ID,
		Type:      types.StreamTypePropertyInput,
		Direction: types.StreamDirectionInbound,
		Input: StreamEndpoint{
			Protocol: types.ProtocolHTTP,
			Config:   request.Input.Config,
		},
		Output: StreamEndpoint{
			Protocol: types.StreamProtocol(outputConfig.Type),
			Config:   outputConfig.Config,
		},
		ProcessorChain: bindings.Processors[processorChainID],
		YAML:           "",
	}

	bindings.Streams[streamID] = streamConfig

	bg.logger.WithFields(logrus.Fields{
		"stream_id":       streamInfo.ID,
		"stream_status":   streamInfo.Status,
		"processor_count": len(processors),
		"output_type":     outputConfig.Type,
	}).Info("Property command stream created successfully")

	return nil
}

func (bg *BindingGenerator) generatePropertyLoggingStream(thingID, propName string, prop *wot.PropertyAffordance, bindings *AllBindings) error {
	if !bg.licenseChecker.IsFeatureAvailable("data_persistence") {
		bg.logger.WithField("feature", "data_persistence").Debug("Persistence feature not available in license")
		return nil
	}

	streamID := fmt.Sprintf("%s_property_%s_persistence", thingID, propName)
	topic := fmt.Sprintf("things.%s.properties.%s", thingID, propName)

	bg.logger.WithFields(logrus.Fields{
		"stream_id": streamID,
		"thing_id":  thingID,
		"property":  propName,
		"topic":     topic,
	}).Debug("Generating property persistence stream")

	persistenceConfig := bg.licenseChecker.GetFeatureConfig("data_persistence")

	processorChainID := fmt.Sprintf("%s_persistence_processors", streamID)
	processors := []ProcessorConfig{
		{
			Type:  types.ProcessorBloblangWoTProperty,
			Label: "property_normalization",
			Config: map[string]interface{}{
				"mapping": generatePropertyPersistenceMapping(thingID, propName),
			},
			Description: "Normalize property data for persistence",
		},
	}

	if format, ok := persistenceConfig["format"].(string); ok {
		switch format {
		case "parquet":
			processors = append(processors, ProcessorConfig{
				Type:  types.ProcessorParquetEncode,
				Label: "parquet_encoding",
				Config: map[string]interface{}{
					"schema": generatePropertyParquetSchema(),
				},
				Description: "Encode property data to Parquet format",
			})
		case "json":
			processors = append(processors, ProcessorConfig{
				Type:  types.ProcessorJSONEncode,
				Label: "json_encoding",
				Config: map[string]interface{}{},
				Description: "Encode property data to JSON format",
			})
		}
	}

	bindings.Processors[processorChainID] = ProcessorChain{
		ID:         processorChainID,
		Name:       fmt.Sprintf("Property %s persistence processors", propName),
		Processors: processors,
		Metadata: map[string]interface{}{
			"thing_id":         thingID,
			"property_name":    propName,
			"interaction_type": "property",
			"purpose":          "persistence",
		},
	}

	outputConfig, err := bg.generatePersistenceOutputConfig(thingID, propName, persistenceConfig)
	if err != nil {
		return fmt.Errorf("failed to generate persistence output config: %w", err)
	}

	request := types.StreamCreationRequest{
		ThingID:         thingID,
		InteractionType: "properties",
		InteractionName: propName,
		Direction:       "input",
		Input: types.StreamEndpointConfig{
			Type: "kafka",
			Config: map[string]interface{}{
				"addresses":      bg.kafkaConfig.Brokers,
				"topics":         []string{topic},
				"consumer_group": fmt.Sprintf("twincore-property-persistence-%s", thingID),
			},
		},
		Output: outputConfig,
		ProcessorChain: bg.convertToTypesProcessorConfig(processors),
		Metadata: map[string]interface{}{
			"generated_by": "centralized_binding_generator",
			"purpose":      "property_persistence",
			"created_at":   time.Now().UTC().Format(time.RFC3339),
		},
	}

	yamlConfig, err := bg.generateStreamRequestYAML(request)
	if err != nil {
		return fmt.Errorf("failed to generate YAML for property logging stream %s: %w", streamID, err)
	}

	request.Metadata["yaml_config"] = yamlConfig

	streamInfo, err := bg.streamManager.CreateStream(context.Background(), request)
	if err != nil {
		return fmt.Errorf("failed to create property logging stream %s: %w", streamID, err)
	}

	streamConfig := StreamConfig{
		ID:        streamInfo.ID,
		Type:      types.StreamTypePropertyLogger,
		Direction: types.StreamDirectionInternal,
		Input: StreamEndpoint{
			Protocol: types.ProtocolKafka,
			Config:   request.Input.Config,
		},
		Output: StreamEndpoint{
			Protocol: types.ProtocolFile,
			Config:   request.Output.Config,
		},
		ProcessorChain: bindings.Processors[processorChainID],
		YAML:           "",
	}

	bindings.Streams[streamID] = streamConfig

	bg.logger.WithFields(logrus.Fields{
		"stream_id":       streamInfo.ID,
		"stream_status":   streamInfo.Status,
		"processor_count": len(processors),
	}).Info("Property logging stream created successfully")

	return nil
}

func (bg *BindingGenerator) generateActionInvocationStream(thingID, actionName string, action *wot.ActionAffordance, bindings *AllBindings) error {
	if !bg.licenseChecker.IsFeatureAvailable("action_invocation") {
		bg.logger.WithField("feature", "action_invocation").Debug("Action invocation not available in license")
		return nil
	}

	streamID := fmt.Sprintf("%s_action_%s_invocation", thingID, actionName)
	topic := fmt.Sprintf("things.%s.actions.%s", thingID, actionName)

	bg.logger.WithFields(logrus.Fields{
		"stream_id": streamID,
		"thing_id":  thingID,
		"action":    actionName,
		"topic":     topic,
	}).Debug("Generating action invocation stream")

	processorChainID := fmt.Sprintf("%s_invocation_processors", streamID)
	processors := []ProcessorConfig{
		{
			Type:  types.ProcessorBloblangWoTAction,
			Label: "action_invocation_mapping",
			Config: map[string]interface{}{
				"mapping": generateActionInvocationMapping(thingID, actionName),
			},
			Description: "Map action invocation data for device execution",
		},
	}

	if action.Input != nil && action.Input.Type != "" {
		jsonSchema := convertDataSchemaToJSONSchema(action.Input.DataSchemaCore)
		processors = append(processors, ProcessorConfig{
			Type:  types.ProcessorJSONSchema,
			Label: "action_input_validation",
			Config: map[string]interface{}{
				"schema": jsonSchema,
			},
			Description: "Validate action input against Thing Description schema",
		})
	}

	processors = append(processors, ProcessorConfig{
		Type:  types.ProcessorBloblangWoTAction,
		Label: "device_action_transform",
		Config: map[string]interface{}{
			"mapping": generateDeviceActionMapping(thingID, actionName),
		},
		Description: "Transform action for device-specific protocol",
	})

	bindings.Processors[processorChainID] = ProcessorChain{
		ID:         processorChainID,
		Name:       fmt.Sprintf("Action %s invocation processors", actionName),
		Processors: processors,
		Metadata: map[string]interface{}{
			"thing_id":         thingID,
			"action_name":      actionName,
			"interaction_type": "action",
			"purpose":          "invocation",
		},
	}

	invocationConfig := bg.licenseChecker.GetFeatureConfig("action_invocation")
	outputConfig, err := bg.generateActionOutputConfig(thingID, actionName, invocationConfig)
	if err != nil {
		return fmt.Errorf("failed to generate action output config: %w", err)
	}

	request := types.StreamCreationRequest{
		ThingID:         thingID,
		InteractionType: "actions",
		InteractionName: actionName,
		Direction:       "input",
		Input: types.StreamEndpointConfig{
			Type: "http_server",
			Config: map[string]interface{}{
				"address":       "${HTTP_ADDRESS:0.0.0.0:8080}",
				"path":          fmt.Sprintf("/things/%s/actions/%s", thingID, actionName),
				"allowed_verbs": []string{"POST"},
				"timeout":       "30s",
			},
		},
		Output:         outputConfig,
		ProcessorChain: bg.convertToTypesProcessorConfig(processors),
		Metadata: map[string]interface{}{
			"generated_by": "centralized_binding_generator",
			"purpose":      "action_invocation",
			"created_at":   time.Now().UTC().Format(time.RFC3339),
		},
	}

	yamlConfig, err := bg.generateStreamRequestYAML(request)
	if err != nil {
		return fmt.Errorf("failed to generate YAML for action invocation stream %s: %w", streamID, err)
	}

	request.Metadata["yaml_config"] = yamlConfig

	streamInfo, err := bg.streamManager.CreateStream(context.Background(), request)
	if err != nil {
		return fmt.Errorf("failed to create action invocation stream %s: %w", streamID, err)
	}

	streamConfig := StreamConfig{
		ID:        streamInfo.ID,
		Type:      types.StreamTypeActionInput,
		Direction: types.StreamDirectionInbound,
		Input: StreamEndpoint{
			Protocol: types.ProtocolHTTP,
			Config:   request.Input.Config,
		},
		Output: StreamEndpoint{
			Protocol: types.StreamProtocol(outputConfig.Type),
			Config:   outputConfig.Config,
		},
		ProcessorChain: bindings.Processors[processorChainID],
		YAML:           "",
	}

	bindings.Streams[streamID] = streamConfig

	bg.logger.WithFields(logrus.Fields{
		"stream_id":       streamInfo.ID,
		"stream_status":   streamInfo.Status,
		"processor_count": len(processors),
		"output_type":     outputConfig.Type,
	}).Info("Action invocation stream created successfully")

	return nil
}

func (bg *BindingGenerator) generateActionLoggingStream(thingID, actionName string, action *wot.ActionAffordance, bindings *AllBindings) error {
	if !bg.licenseChecker.IsFeatureAvailable("data_persistence") {
		bg.logger.WithField("feature", "data_persistence").Debug("Persistence feature not available in license")
		return nil
	}

	streamID := fmt.Sprintf("%s_action_%s_persistence", thingID, actionName)
	topic := fmt.Sprintf("things.%s.actions.%s", thingID, actionName)

	bg.logger.WithFields(logrus.Fields{
		"stream_id": streamID,
		"thing_id":  thingID,
		"action":    actionName,
		"topic":     topic,
	}).Debug("Generating action persistence stream")

	persistenceConfig := bg.licenseChecker.GetFeatureConfig("data_persistence")

	processorChainID := fmt.Sprintf("%s_persistence_processors", streamID)
	processors := []ProcessorConfig{
		{
			Type:  types.ProcessorBloblangWoTAction,
			Label: "action_normalization",
			Config: map[string]interface{}{
				"mapping": generateActionPersistenceMapping(thingID, actionName),
			},
			Description: "Normalize action data for persistence",
		},
	}

	if format, ok := persistenceConfig["format"].(string); ok {
		switch format {
		case "parquet":
			processors = append(processors, ProcessorConfig{
				Type:  types.ProcessorParquetEncode,
				Label: "parquet_encoding",
				Config: map[string]interface{}{
					"schema": generateActionParquetSchema(),
				},
				Description: "Encode action data to Parquet format",
			})
		case "json":
			processors = append(processors, ProcessorConfig{
				Type:  types.ProcessorJSONEncode,
				Label: "json_encoding",
				Config: map[string]interface{}{},
				Description: "Encode action data to JSON format",
			})
		}
	}

	bindings.Processors[processorChainID] = ProcessorChain{
		ID:         processorChainID,
		Name:       fmt.Sprintf("Action %s persistence processors", actionName),
		Processors: processors,
		Metadata: map[string]interface{}{
			"thing_id":         thingID,
			"action_name":      actionName,
			"interaction_type": "action",
			"purpose":          "persistence",
		},
	}

	outputConfig, err := bg.generateActionPersistenceOutputConfig(thingID, actionName, persistenceConfig)
	if err != nil {
		return fmt.Errorf("failed to generate action persistence output config: %w", err)
	}

	request := types.StreamCreationRequest{
		ThingID:         thingID,
		InteractionType: "actions",
		InteractionName: actionName,
		Direction:       "input",
		Input: types.StreamEndpointConfig{
			Type: "kafka",
			Config: map[string]interface{}{
				"addresses":      bg.kafkaConfig.Brokers,
				"topics":         []string{topic},
				"consumer_group": fmt.Sprintf("twincore-action-persistence-%s", thingID),
			},
		},
		Output: outputConfig,
		ProcessorChain: bg.convertToTypesProcessorConfig(processors),
		Metadata: map[string]interface{}{
			"generated_by": "centralized_binding_generator",
			"purpose":      "action_persistence",
			"created_at":   time.Now().UTC().Format(time.RFC3339),
		},
	}

	yamlConfig, err := bg.generateStreamRequestYAML(request)
	if err != nil {
		return fmt.Errorf("failed to generate YAML for action logging stream %s: %w", streamID, err)
	}

	request.Metadata["yaml_config"] = yamlConfig

	streamInfo, err := bg.streamManager.CreateStream(context.Background(), request)
	if err != nil {
		return fmt.Errorf("failed to create action logging stream %s: %w", streamID, err)
	}

	streamConfig := StreamConfig{
		ID:        streamInfo.ID,
		Type:      types.StreamTypeActionLogger,
		Direction: types.StreamDirectionInternal,
		Input: StreamEndpoint{
			Protocol: types.ProtocolKafka,
			Config:   request.Input.Config,
		},
		Output: StreamEndpoint{
			Protocol: types.ProtocolFile,
			Config:   request.Output.Config,
		},
		ProcessorChain: bindings.Processors[processorChainID],
		YAML:           "",
	}

	bindings.Streams[streamID] = streamConfig

	bg.logger.WithFields(logrus.Fields{
		"stream_id":       streamInfo.ID,
		"stream_status":   streamInfo.Status,
		"processor_count": len(processors),
	}).Info("Action logging stream created successfully")

	return nil
}

func (bg *BindingGenerator) generateEventProcessingStream(thingID, eventName string, event *wot.EventAffordance, bindings *AllBindings) error {
	if !bg.licenseChecker.IsFeatureAvailable("event_processing") {
		bg.logger.WithField("feature", "event_processing").Debug("Event processing not available in license")
		return nil
	}

	streamID := fmt.Sprintf("%s_event_%s_processing", thingID, eventName)
	topic := fmt.Sprintf("things.%s.events.%s", thingID, eventName)

	bg.logger.WithFields(logrus.Fields{
		"stream_id": streamID,
		"thing_id":  thingID,
		"event":     eventName,
		"topic":     topic,
	}).Debug("Generating event processing stream")

	processorChainID := fmt.Sprintf("%s_processing_processors", streamID)
	processors := []ProcessorConfig{
		{
			Type:  types.ProcessorBloblangWoTEvent,
			Label: "event_processing_mapping",
			Config: map[string]interface{}{
				"mapping": generateEventProcessingMapping(thingID, eventName),
			},
			Description: "Map event data for client distribution",
		},
	}

	if event.Data != nil && event.Data.Type != "" {
		jsonSchema := convertDataSchemaToJSONSchema(event.Data.DataSchemaCore)
		processors = append(processors, ProcessorConfig{
			Type:  types.ProcessorJSONSchema,
			Label: "event_data_validation",
			Config: map[string]interface{}{
				"schema": jsonSchema,
			},
			Description: "Validate event data against Thing Description schema",
		})
	}

	processors = append(processors, ProcessorConfig{
		Type:  types.ProcessorBloblangWoTEvent,
		Label: "event_enrichment",
		Config: map[string]interface{}{
			"mapping": generateEventEnrichmentMapping(thingID, eventName),
		},
		Description: "Enrich event data for client consumption",
	})

	bindings.Processors[processorChainID] = ProcessorChain{
		ID:         processorChainID,
		Name:       fmt.Sprintf("Event %s processing processors", eventName),
		Processors: processors,
		Metadata: map[string]interface{}{
			"thing_id":         thingID,
			"event_name":       eventName,
			"interaction_type": "event",
			"purpose":          "processing",
		},
	}

	processingConfig := bg.licenseChecker.GetFeatureConfig("event_processing")
	outputConfig, err := bg.generateEventOutputConfig(thingID, eventName, processingConfig)
	if err != nil {
		return fmt.Errorf("failed to generate event output config: %w", err)
	}

	request := types.StreamCreationRequest{
		ThingID:         thingID,
		InteractionType: "events",
		InteractionName: eventName,
		Direction:       "output",
		Input: types.StreamEndpointConfig{
			Type: "kafka",
			Config: map[string]interface{}{
				"addresses":      bg.kafkaConfig.Brokers,
				"topics":         []string{topic},
				"consumer_group": fmt.Sprintf("twincore-event-processing-%s", thingID),
			},
		},
		Output:         outputConfig,
		ProcessorChain: bg.convertToTypesProcessorConfig(processors),
		Metadata: map[string]interface{}{
			"generated_by": "centralized_binding_generator",
			"purpose":      "event_processing",
			"created_at":   time.Now().UTC().Format(time.RFC3339),
		},
	}

	yamlConfig, err := bg.generateStreamRequestYAML(request)
	if err != nil {
		return fmt.Errorf("failed to generate YAML for event processing stream %s: %w", streamID, err)
	}

	request.Metadata["yaml_config"] = yamlConfig

	streamInfo, err := bg.streamManager.CreateStream(context.Background(), request)
	if err != nil {
		return fmt.Errorf("failed to create event processing stream %s: %w", streamID, err)
	}

	streamConfig := StreamConfig{
		ID:        streamInfo.ID,
		Type:      types.StreamTypeEventOutput,
		Direction: types.StreamDirectionOutbound,
		Input: StreamEndpoint{
			Protocol: types.ProtocolKafka,
			Config:   request.Input.Config,
		},
		Output: StreamEndpoint{
			Protocol: types.StreamProtocol(outputConfig.Type),
			Config:   outputConfig.Config,
		},
		ProcessorChain: bindings.Processors[processorChainID],
		YAML:           "",
	}

	bindings.Streams[streamID] = streamConfig

	bg.logger.WithFields(logrus.Fields{
		"stream_id":       streamInfo.ID,
		"stream_status":   streamInfo.Status,
		"processor_count": len(processors),
		"output_type":     outputConfig.Type,
	}).Info("Event processing stream created successfully")

	return nil
}

func (bg *BindingGenerator) generateEventLoggingStream(thingID, eventName string, event *wot.EventAffordance, bindings *AllBindings) error {
	if !bg.licenseChecker.IsFeatureAvailable("data_persistence") {
		bg.logger.WithField("feature", "data_persistence").Debug("Persistence feature not available in license")
		return nil
	}

	streamID := fmt.Sprintf("%s_event_%s_persistence", thingID, eventName)
	topic := fmt.Sprintf("things.%s.events.%s", thingID, eventName)

	bg.logger.WithFields(logrus.Fields{
		"stream_id": streamID,
		"thing_id":  thingID,
		"event":     eventName,
		"topic":     topic,
	}).Debug("Generating event persistence stream")

	persistenceConfig := bg.licenseChecker.GetFeatureConfig("data_persistence")

	processorChainID := fmt.Sprintf("%s_persistence_processors", streamID)
	processors := []ProcessorConfig{
		{
			Type:  types.ProcessorBloblangWoTEvent,
			Label: "event_normalization",
			Config: map[string]interface{}{
				"mapping": generateEventPersistenceMapping(thingID, eventName),
			},
			Description: "Normalize event data for persistence",
		},
	}

	if format, ok := persistenceConfig["format"].(string); ok {
		switch format {
		case "parquet":
			processors = append(processors, ProcessorConfig{
				Type:  types.ProcessorParquetEncode,
				Label: "parquet_encoding",
				Config: map[string]interface{}{
					"schema": generateEventParquetSchema(),
				},
				Description: "Encode event data to Parquet format",
			})
		case "json":
			processors = append(processors, ProcessorConfig{
				Type:  types.ProcessorJSONEncode,
				Label: "json_encoding",
				Config: map[string]interface{}{},
				Description: "Encode event data to JSON format",
			})
		}
	}

	bindings.Processors[processorChainID] = ProcessorChain{
		ID:         processorChainID,
		Name:       fmt.Sprintf("Event %s persistence processors", eventName),
		Processors: processors,
		Metadata: map[string]interface{}{
			"thing_id":         thingID,
			"event_name":       eventName,
			"interaction_type": "event",
			"purpose":          "persistence",
		},
	}

	outputConfig, err := bg.generateEventPersistenceOutputConfig(thingID, eventName, persistenceConfig)
	if err != nil {
		return fmt.Errorf("failed to generate event persistence output config: %w", err)
	}

	request := types.StreamCreationRequest{
		ThingID:         thingID,
		InteractionType: "events",
		InteractionName: eventName,
		Direction:       "input",
		Input: types.StreamEndpointConfig{
			Type: "kafka",
			Config: map[string]interface{}{
				"addresses":      bg.kafkaConfig.Brokers,
				"topics":         []string{topic},
				"consumer_group": fmt.Sprintf("twincore-event-persistence-%s", thingID),
			},
		},
		Output: outputConfig,
		ProcessorChain: bg.convertToTypesProcessorConfig(processors),
		Metadata: map[string]interface{}{
			"generated_by": "centralized_binding_generator",
			"purpose":      "event_persistence",
			"created_at":   time.Now().UTC().Format(time.RFC3339),
		},
	}

	yamlConfig, err := bg.generateStreamRequestYAML(request)
	if err != nil {
		return fmt.Errorf("failed to generate YAML for event logging stream %s: %w", streamID, err)
	}

	request.Metadata["yaml_config"] = yamlConfig

	streamInfo, err := bg.streamManager.CreateStream(context.Background(), request)
	if err != nil {
		return fmt.Errorf("failed to create event logging stream %s: %w", streamID, err)
	}

	streamConfig := StreamConfig{
		ID:        streamInfo.ID,
		Type:      types.StreamTypeEventLogger,
		Direction: types.StreamDirectionInternal,
		Input: StreamEndpoint{
			Protocol: types.ProtocolKafka,
			Config:   request.Input.Config,
		},
		Output: StreamEndpoint{
			Protocol: types.ProtocolFile,
			Config:   request.Output.Config,
		},
		ProcessorChain: bindings.Processors[processorChainID],
		YAML:           "",
	}

	bindings.Streams[streamID] = streamConfig

	bg.logger.WithFields(logrus.Fields{
		"stream_id":       streamInfo.ID,
		"stream_status":   streamInfo.Status,
		"processor_count": len(processors),
	}).Info("Event logging stream created successfully")

	return nil
}

// generatePersistenceOutputConfig, generateLocalFileOutput, generateS3Output, etc.
// These methods are complex and involve external dependencies or significant logic.
// They will be moved and refactored in a subsequent subtask.
// For now, they remain as methods on BindingGenerator.
// TODO: Move these to a separate file or refactor them as part of stream generation logic.

func (bg *BindingGenerator) generateStreamRequestYAML(request types.StreamCreationRequest) (string, error) {
	// Generate input YAML
	inputYAML := bg.generateInputYAML(request.Input)

	// Generate processor chain YAML
	processorYAML := bg.generateProcessorChainYAML(request.ProcessorChain)

	// Generate output YAML
	outputYAML := bg.generateOutputYAML(request.Output)

	// Combine into complete YAML
	yaml := fmt.Sprintf(`input:
%s

pipeline:
  processors:
%s

output:
%s
`, inputYAML, processorYAML, outputYAML)

	return yaml, nil
}

func (bg *BindingGenerator) generateInputYAML(input types.StreamEndpointConfig) string {
	switch input.Type {
	case "kafka":
		addresses := input.Config["addresses"].([]string)
		topics := input.Config["topics"].([]string)
		consumerGroup := input.Config["consumer_group"].(string)
		return fmt.Sprintf(`  kafka:
    addresses: [%s]
    topics: [%s]
    consumer_group: "%s"
    auto_replay_nacks: true`,
			quoteAndJoin(addresses),
			quoteAndJoin(topics),
			consumerGroup)

	case "mqtt":
		urls := []string{bg.mqttConfig.Broker}
		topics := input.Config["topics"].([]string)
		clientID := input.Config["client_id"].(string)
		qos := input.Config["qos"]
		return fmt.Sprintf(`  mqtt:
    urls: [%s]
    topics: [%s]
    client_id: "%s"
    qos: %v`,
			quoteAndJoin(urls),
			quoteAndJoin(topics),
			clientID,
			qos)

	case "http_server":
		path := input.Config["path"].(string)
		return fmt.Sprintf(`  http_server:
    address: "${HTTP_ADDRESS:0.0.0.0:8080}"
    path: "%s"
    allowed_verbs: ["POST", "PUT"]
    timeout: "30s"`, path)

	default:
		return fmt.Sprintf(`  # Unsupported input type: %s`, input.Type)
	}
}

func (bg *BindingGenerator) generateProcessorChainYAML(processors []types.ProcessorConfig) string {
	var lines []string

	for _, proc := range processors {
		switch proc.Type {
		case string(types.ProcessorBloblangWoTProperty):
			mapping := proc.Config["mapping"].(string)
			lines = append(lines, fmt.Sprintf(`    - label: "format_wot_property"
      mapping: |%s`, indentString(mapping, "        ")))

		case string(types.ProcessorBloblangWoTAction):
			mapping := proc.Config["mapping"].(string)
			lines = append(lines, fmt.Sprintf(`    - label: "format_wot_action"
      mapping: |%s`, indentString(mapping, "        ")))

		case string(types.ProcessorBloblangWoTEvent):
			mapping := proc.Config["mapping"].(string)
			lines = append(lines, fmt.Sprintf(`    - label: "format_wot_event"
      mapping: |%s`, indentString(mapping, "        ")))

		case string(types.ProcessorJSONEncode):
			lines = append(lines, `    - label: "json_encode"
      encode:
        json: {}`)

		case string(types.ProcessorParquetEncode):
			schema := proc.Config["schema"].([]map[string]interface{})
			schemaYAML := bg.generateParquetSchemaYAML(schema)
			lines = append(lines, fmt.Sprintf(`    - label: "encode_parquet"
      parquet_encode:
        schema:
%s`, schemaYAML))

		case string(types.ProcessorJSONSchema):
			if schema, ok := proc.Config["schema"]; ok {
				lines = append(lines, fmt.Sprintf(`    - label: "json_schema_validation"
      json_schema:
        schema: %v`, schema))
			}

		default:
			lines = append(lines, fmt.Sprintf(`    - label: "%s_processor"
      %s: {}`, proc.Type, proc.Type))
		}
	}

	return strings.Join(lines, "\n")
}

func (bg *BindingGenerator) generateOutputYAML(output types.StreamEndpointConfig) string {
	switch output.Type {
	case "kafka":
		addresses := bg.kafkaConfig.Brokers
		topic := output.Config["topic"].(string)
		return fmt.Sprintf(`  kafka:
    addresses: [%s]
    topic: "%s"
    key: "${! this.thing_id }"`,
			quoteAndJoin(addresses),
			topic)

	case "mqtt":
		urls := []string{bg.mqttConfig.Broker}
		topic := output.Config["topic"].(string)
		clientID := output.Config["client_id"].(string)
		qos := output.Config["qos"]
		return fmt.Sprintf(`  mqtt:
    urls: [%s]
    topic: "%s"
    client_id: "%s"
    qos: %v`,
			quoteAndJoin(urls),
			topic,
			clientID,
			qos)

	case "file", "parquet":
		path := output.Config["path"].(string)
		return fmt.Sprintf(`  file:
    path: "%s"
    codec: none`, path)

	default:
		return fmt.Sprintf(`  # Unsupported output type: %s`, output.Type)
	}
}

func (bg *BindingGenerator) generateParquetSchemaYAML(schema []map[string]interface{}) string {
	var lines []string
	for _, field := range schema {
		lines = append(lines, fmt.Sprintf(`          - name: "%s"
            type: "%s"
            converted_type: "%s"`,
			field["name"],
			field["type"],
			field["converted_type"]))
	}
	return strings.Join(lines, "\n")
}

// Helper functions
func quoteAndJoin(items []string) string {
	quoted := make([]string, len(items))
	for i, item := range items {
		quoted[i] = fmt.Sprintf(`"%s"`, item)
	}
	return strings.Join(quoted, ", ")
}

func indentString(s string, indent string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = indent + line
		}
	}
	return "\n" + strings.Join(lines, "\n")
}

func (bg *BindingGenerator) convertToTypesProcessorConfig(processors []ProcessorConfig) []types.ProcessorConfig {
	result := make([]types.ProcessorConfig, len(processors))
	for i, proc := range processors {
		result[i] = types.ProcessorConfig{
			Type:   string(proc.Type),
			Config: proc.Config,
		}
	}
	return result
}

func (bg *BindingGenerator) generateObservationOutputConfig(thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	outputType := "websocket"
	if ot, ok := config["output_type"].(string); ok {
		outputType = ot
	}

	switch outputType {
	case "websocket":
		return bg.generateWebSocketObservationOutput(thingID, propName, config)
	case "sse", "server_sent_events":
		return bg.generateSSEObservationOutput(thingID, propName, config)
	case "mqtt":
		return bg.generateMQTTObservationOutput(thingID, propName, config)
	case "kafka":
		return bg.generateKafkaObservationOutput(thingID, propName, config)
	case "http_server":
		return bg.generateHTTPServerObservationOutput(thingID, propName, config)
	default:
		return types.StreamEndpointConfig{}, fmt.Errorf("unsupported observation output type: %s", outputType)
	}
}

func (bg *BindingGenerator) generateWebSocketObservationOutput(thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	path := fmt.Sprintf("/things/%s/properties/%s/observe", thingID, propName)
	if customPath, ok := config["websocket_path"].(string); ok {
		path = customPath
	}

	address := "${WEBSOCKET_ADDRESS:0.0.0.0:8080}"
	if addr, ok := config["websocket_address"].(string); ok {
		address = addr
	}

	return types.StreamEndpointConfig{
		Type: "websocket",
		Config: map[string]interface{}{
			"address": address,
			"path":    path,
			"timeout": "30s",
		},
	}, nil
}

func (bg *BindingGenerator) generateSSEObservationOutput(thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	path := fmt.Sprintf("/things/%s/properties/%s/events", thingID, propName)
	if customPath, ok := config["sse_path"].(string); ok {
		path = customPath
	}

	return types.StreamEndpointConfig{
		Type: "http_server",
		Config: map[string]interface{}{
			"address":           "${HTTP_ADDRESS:0.0.0.0:8080}",
			"path":              path,
			"allowed_verbs":     []string{"GET"},
			"timeout":           "0",
			"stream_response":   true,
			"content_type":      "text/event-stream",
			"response_headers": map[string]string{
				"Cache-Control": "no-cache",
				"Connection":    "keep-alive",
			},
		},
	}, nil
}

func (bg *BindingGenerator) generateMQTTObservationOutput(thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	topic := fmt.Sprintf("things/%s/properties/%s/observe", thingID, propName)
	if customTopic, ok := config["mqtt_topic"].(string); ok {
		topic = customTopic
	}

	return types.StreamEndpointConfig{
		Type: "mqtt",
		Config: map[string]interface{}{
			"urls":      []string{bg.mqttConfig.Broker},
			"topic":     topic,
			"client_id": fmt.Sprintf("twincore-observer-%s-%s", thingID, propName),
			"qos":       1,
		},
	}, nil
}

func (bg *BindingGenerator) generateKafkaObservationOutput(thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	topic := fmt.Sprintf("twincore.observations.%s.%s", thingID, propName)
	if customTopic, ok := config["kafka_topic"].(string); ok {
		topic = customTopic
	}

	return types.StreamEndpointConfig{
		Type: "kafka",
		Config: map[string]interface{}{
			"addresses": bg.kafkaConfig.Brokers,
			"topic":     topic,
			"key":       fmt.Sprintf("${! this.thing_id }-%s", propName),
		},
	}, nil
}

func (bg *BindingGenerator) generateHTTPServerObservationOutput(thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	path := fmt.Sprintf("/things/%s/properties/%s/latest", thingID, propName)
	if customPath, ok := config["http_path"].(string); ok {
		path = customPath
	}

	return types.StreamEndpointConfig{
		Type: "http_server",
		Config: map[string]interface{}{
			"address":       "${HTTP_ADDRESS:0.0.0.0:8080}",
			"path":          path,
			"allowed_verbs": []string{"GET"},
			"timeout":       "10s",
		},
	}, nil
}

func (bg *BindingGenerator) generateCommandOutputConfig(thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	outputType := "kafka"
	if ot, ok := config["output_type"].(string); ok {
		outputType = ot
	}

	switch outputType {
	case "kafka":
		return bg.generateKafkaCommandOutput(thingID, propName, config)
	case "mqtt":
		return bg.generateMQTTCommandOutput(thingID, propName, config)
	case "http_client":
		return bg.generateHTTPClientCommandOutput(thingID, propName, config)
	case "websocket":
		return bg.generateWebSocketCommandOutput(thingID, propName, config)
	default:
		return types.StreamEndpointConfig{}, fmt.Errorf("unsupported command output type: %s", outputType)
	}
}

func (bg *BindingGenerator) generateKafkaCommandOutput(thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	topic := fmt.Sprintf("twincore.commands.%s", thingID)
	if customTopic, ok := config["kafka_topic"].(string); ok {
		topic = customTopic
	}

	return types.StreamEndpointConfig{
		Type: "kafka",
		Config: map[string]interface{}{
			"addresses": bg.kafkaConfig.Brokers,
			"topic":     topic,
			"key":       fmt.Sprintf("${! this.device_id }"),
		},
	}, nil
}

func (bg *BindingGenerator) generateMQTTCommandOutput(thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	topic := fmt.Sprintf("devices/%s/commands", thingID)
	if customTopic, ok := config["mqtt_topic"].(string); ok {
		topic = customTopic
	}

	return types.StreamEndpointConfig{
		Type: "mqtt",
		Config: map[string]interface{}{
			"urls":      []string{bg.mqttConfig.Broker},
			"topic":     topic,
			"client_id": fmt.Sprintf("twincore-commands-%s", thingID),
			"qos":       1,
		},
	}, nil
}

func (bg *BindingGenerator) generateHTTPClientCommandOutput(thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	url := fmt.Sprintf("${DEVICE_API_URL}/%s/properties/%s", thingID, propName)
	if customURL, ok := config["device_url"].(string); ok {
		url = customURL
	}

	return types.StreamEndpointConfig{
		Type: "http_client",
		Config: map[string]interface{}{
			"url":     url,
			"verb":    "PUT",
			"headers": map[string]string{
				"Content-Type":    "application/json",
				"X-Command-ID":    "${! this.command_id }",
				"X-Correlation-ID": "${! this.correlation_id }",
			},
			"timeout": "10s",
		},
	}, nil
}

func (bg *BindingGenerator) generateWebSocketCommandOutput(thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	url := fmt.Sprintf("${DEVICE_WS_URL}/%s/commands", thingID)
	if customURL, ok := config["websocket_url"].(string); ok {
		url = customURL
	}

	return types.StreamEndpointConfig{
		Type: "websocket",
		Config: map[string]interface{}{
			"url":     url,
			"timeout": "30s",
		},
	}, nil
}

func (bg *BindingGenerator) generateActionOutputConfig(thingID, actionName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	outputType := "kafka"
	if ot, ok := config["output_type"].(string); ok {
		outputType = ot
	}

	switch outputType {
	case "kafka":
		return bg.generateKafkaActionOutput(thingID, actionName, config)
	case "mqtt":
		return bg.generateMQTTActionOutput(thingID, actionName, config)
	case "http_client":
		return bg.generateHTTPClientActionOutput(thingID, actionName, config)
	case "websocket":
		return bg.generateWebSocketActionOutput(thingID, actionName, config)
	default:
		return types.StreamEndpointConfig{}, fmt.Errorf("unsupported action output type: %s", outputType)
	}
}

func (bg *BindingGenerator) generateKafkaActionOutput(thingID, actionName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	topic := fmt.Sprintf("twincore.actions.%s", thingID)
	if customTopic, ok := config["kafka_topic"].(string); ok {
		topic = customTopic
	}

	return types.StreamEndpointConfig{
		Type: "kafka",
		Config: map[string]interface{}{
			"addresses": bg.kafkaConfig.Brokers,
			"topic":     topic,
			"key":       fmt.Sprintf("${! this.device_id }"),
		},
	}, nil
}

func (bg *BindingGenerator) generateMQTTActionOutput(thingID, actionName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	topic := fmt.Sprintf("devices/%s/actions", thingID)
	if customTopic, ok := config["mqtt_topic"].(string); ok {
		topic = customTopic
	}

	return types.StreamEndpointConfig{
		Type: "mqtt",
		Config: map[string]interface{}{
			"urls":      []string{bg.mqttConfig.Broker},
			"topic":     topic,
			"client_id": fmt.Sprintf("twincore-actions-%s", thingID),
			"qos":       1,
		},
	}, nil
}

func (bg *BindingGenerator) generateHTTPClientActionOutput(thingID, actionName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	url := fmt.Sprintf("${DEVICE_API_URL}/%s/actions/%s", thingID, actionName)
	if customURL, ok := config["device_url"].(string); ok {
		url = customURL
	}

	return types.StreamEndpointConfig{
		Type: "http_client",
		Config: map[string]interface{}{
			"url":  url,
			"verb": "POST",
			"headers": map[string]string{
				"Content-Type":     "application/json",
				"X-Action-ID":      "${! this.action_id }",
				"X-Correlation-ID": "${! this.correlation_id }",
			},
			"timeout": "30s",
		},
	}, nil
}

func (bg *BindingGenerator) generateWebSocketActionOutput(thingID, actionName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	url := fmt.Sprintf("${DEVICE_WS_URL}/%s/actions", thingID)
	if customURL, ok := config["websocket_url"].(string); ok {
		url = customURL
	}

	return types.StreamEndpointConfig{
		Type: "websocket",
		Config: map[string]interface{}{
			"url":     url,
			"timeout": "30s",
		},
	}, nil
}

func (bg *BindingGenerator) generateActionPersistenceOutputConfig(thingID, actionName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	sinkType := "file"
	if st, ok := config["sink_type"].(string); ok {
		sinkType = st
	}

	format := "json"
	if f, ok := config["format"].(string); ok {
		format = f
	}

	switch sinkType {
	case "file", "local":
		return bg.generateLocalActionFileOutput(thingID, actionName, format)
	case "s3":
		return bg.generateS3ActionOutput(thingID, actionName, format, config)
	case "kafka":
		return bg.generateKafkaActionPersistenceOutput(thingID, actionName, config)
	case "noop":
		return types.StreamEndpointConfig{
			Type:   "drop",
			Config: map[string]interface{}{},
		}, nil
	default:
		return types.StreamEndpointConfig{}, fmt.Errorf("unsupported action persistence sink type: %s", sinkType)
	}
}

func (bg *BindingGenerator) generateLocalActionFileOutput(thingID, actionName, format string) (types.StreamEndpointConfig, error) {
	var extension string
	switch format {
	case "parquet":
		extension = "parquet"
	case "json":
		extension = "jsonl"
	case "csv":
		extension = "csv"
	default:
		extension = "txt"
	}

	basePath := bg.parquetConfig.BasePath
	if basePath == "" {
		basePath = "./twincore_data"
	}

	filePath := fmt.Sprintf("%s/actions/%s_%s_${!timestamp_unix():yyyy-MM-dd}.%s",
		basePath, thingID, actionName, extension)

	return types.StreamEndpointConfig{
		Type: "file",
		Config: map[string]interface{}{
			"path":  filePath,
			"codec": "none",
		},
	}, nil
}

func (bg *BindingGenerator) generateS3ActionOutput(thingID, actionName, format string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	bucket, ok := config["s3_bucket"].(string)
	if !ok {
		return types.StreamEndpointConfig{}, fmt.Errorf("s3_bucket is required for S3 sink")
	}

	var extension string
	switch format {
	case "parquet":
		extension = "parquet"
	case "json":
		extension = "jsonl"
	default:
		extension = "txt"
	}

	s3Config := map[string]interface{}{
		"bucket": bucket,
		"path":   fmt.Sprintf("twincore/actions/%s/%s/${!timestamp_unix():yyyy/MM/dd}/%s_${!uuid_v4()}.%s", thingID, actionName, actionName, extension),
		"region": "${AWS_REGION:us-east-1}",
		"credentials": map[string]interface{}{
			"id":     "${AWS_ACCESS_KEY_ID}",
			"secret": "${AWS_SECRET_ACCESS_KEY}",
			"token":  "${AWS_SESSION_TOKEN:}",
		},
	}

	if region, ok := config["s3_region"].(string); ok {
		s3Config["region"] = region
	}

	return types.StreamEndpointConfig{
		Type:   "aws_s3",
		Config: s3Config,
	}, nil
}

func (bg *BindingGenerator) generateKafkaActionPersistenceOutput(thingID, actionName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	persistenceTopic := fmt.Sprintf("twincore.persistence.%s.%s", thingID, actionName)
	if topic, ok := config["persistence_topic"].(string); ok {
		persistenceTopic = topic
	}

	return types.StreamEndpointConfig{
		Type: "kafka",
		Config: map[string]interface{}{
			"addresses": bg.kafkaConfig.Brokers,
			"topic":     persistenceTopic,
			"key":       fmt.Sprintf("${! this.thing_id }-%s", actionName),
		},
	}, nil
}

func (bg *BindingGenerator) generateEventOutputConfig(thingID, eventName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	outputType := "sse"
	if ot, ok := config["output_type"].(string); ok {
		outputType = ot
	}

	switch outputType {
	case "sse", "server_sent_events":
		return bg.generateSSEEventOutput(thingID, eventName, config)
	case "websocket":
		return bg.generateWebSocketEventOutput(thingID, eventName, config)
	case "mqtt":
		return bg.generateMQTTEventOutput(thingID, eventName, config)
	case "kafka":
		return bg.generateKafkaEventOutput(thingID, eventName, config)
	case "http_server":
		return bg.generateHTTPServerEventOutput(thingID, eventName, config)
	default:
		return types.StreamEndpointConfig{}, fmt.Errorf("unsupported event output type: %s", outputType)
	}
}

func (bg *BindingGenerator) generateSSEEventOutput(thingID, eventName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	path := fmt.Sprintf("/things/%s/events/%s", thingID, eventName)
	if customPath, ok := config["sse_path"].(string); ok {
		path = customPath
	}

	return types.StreamEndpointConfig{
		Type: "http_server",
		Config: map[string]interface{}{
			"address":           "${HTTP_ADDRESS:0.0.0.0:8080}",
			"path":              path,
			"allowed_verbs":     []string{"GET"},
			"timeout":           "0",
			"stream_response":   true,
			"content_type":      "text/event-stream",
			"response_headers": map[string]string{
				"Cache-Control":                "no-cache",
				"Connection":                   "keep-alive",
				"Access-Control-Allow-Origin":  "*",
				"Access-Control-Allow-Headers": "Cache-Control",
			},
		},
	}, nil
}

func (bg *BindingGenerator) generateWebSocketEventOutput(thingID, eventName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	path := fmt.Sprintf("/things/%s/events/%s/ws", thingID, eventName)
	if customPath, ok := config["websocket_path"].(string); ok {
		path = customPath
	}

	address := "${WEBSOCKET_ADDRESS:0.0.0.0:8080}"
	if addr, ok := config["websocket_address"].(string); ok {
		address = addr
	}

	return types.StreamEndpointConfig{
		Type: "websocket",
		Config: map[string]interface{}{
			"address": address,
			"path":    path,
			"timeout": "300s",
		},
	}, nil
}

func (bg *BindingGenerator) generateMQTTEventOutput(thingID, eventName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	topic := fmt.Sprintf("things/%s/events/%s", thingID, eventName)
	if customTopic, ok := config["mqtt_topic"].(string); ok {
		topic = customTopic
	}

	return types.StreamEndpointConfig{
		Type: "mqtt",
		Config: map[string]interface{}{
			"urls":      []string{bg.mqttConfig.Broker},
			"topic":     topic,
			"client_id": fmt.Sprintf("twincore-events-%s-%s", thingID, eventName),
			"qos":       1,
		},
	}, nil
}

func (bg *BindingGenerator) generateKafkaEventOutput(thingID, eventName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	topic := fmt.Sprintf("twincore.events.%s.%s", thingID, eventName)
	if customTopic, ok := config["kafka_topic"].(string); ok {
		topic = customTopic
	}

	return types.StreamEndpointConfig{
		Type: "kafka",
		Config: map[string]interface{}{
			"addresses": bg.kafkaConfig.Brokers,
			"topic":     topic,
			"key":       fmt.Sprintf("${! this.thing_id }-%s", eventName),
		},
	}, nil
}

func (bg *BindingGenerator) generateHTTPServerEventOutput(thingID, eventName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	path := fmt.Sprintf("/things/%s/events/%s/latest", thingID, eventName)
	if customPath, ok := config["http_path"].(string); ok {
		path = customPath
	}

	return types.StreamEndpointConfig{
		Type: "http_server",
		Config: map[string]interface{}{
			"address":       "${HTTP_ADDRESS:0.0.0.0:8080}",
			"path":          path,
			"allowed_verbs": []string{"GET"},
			"timeout":       "10s",
		},
	}, nil
}

func (bg *BindingGenerator) generateEventPersistenceOutputConfig(thingID, eventName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	sinkType := "file"
	if st, ok := config["sink_type"].(string); ok {
		sinkType = st
	}

	format := "json"
	if f, ok := config["format"].(string); ok {
		format = f
	}

	switch sinkType {
	case "file", "local":
		return bg.generateLocalEventFileOutput(thingID, eventName, format)
	case "s3":
		return bg.generateS3EventOutput(thingID, eventName, format, config)
	case "kafka":
		return bg.generateKafkaEventPersistenceOutput(thingID, eventName, config)
	case "noop":
		return types.StreamEndpointConfig{
			Type:   "drop",
			Config: map[string]interface{}{},
		}, nil
	default:
		return types.StreamEndpointConfig{}, fmt.Errorf("unsupported event persistence sink type: %s", sinkType)
	}
}

func (bg *BindingGenerator) generateLocalEventFileOutput(thingID, eventName, format string) (types.StreamEndpointConfig, error) {
	var extension string
	switch format {
	case "parquet":
		extension = "parquet"
	case "json":
		extension = "jsonl"
	case "csv":
		extension = "csv"
	default:
		extension = "txt"
	}

	basePath := bg.parquetConfig.BasePath
	if basePath == "" {
		basePath = "./twincore_data"
	}

	filePath := fmt.Sprintf("%s/events/%s_%s_${!timestamp_unix():yyyy-MM-dd}.%s",
		basePath, thingID, eventName, extension)

	return types.StreamEndpointConfig{
		Type: "file",
		Config: map[string]interface{}{
			"path":  filePath,
			"codec": "none",
		},
	}, nil
}

func (bg *BindingGenerator) generateS3EventOutput(thingID, eventName, format string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	bucket, ok := config["s3_bucket"].(string)
	if !ok {
		return types.StreamEndpointConfig{}, fmt.Errorf("s3_bucket is required for S3 sink")
	}

	var extension string
	switch format {
	case "parquet":
		extension = "parquet"
	case "json":
		extension = "jsonl"
	default:
		extension = "txt"
	}

	s3Config := map[string]interface{}{
		"bucket": bucket,
		"path":   fmt.Sprintf("twincore/events/%s/%s/${!timestamp_unix():yyyy/MM/dd}/%s_${!uuid_v4()}.%s", thingID, eventName, eventName, extension),
		"region": "${AWS_REGION:us-east-1}",
		"credentials": map[string]interface{}{
			"id":     "${AWS_ACCESS_KEY_ID}",
			"secret": "${AWS_SECRET_ACCESS_KEY}",
			"token":  "${AWS_SESSION_TOKEN:}",
		},
	}

	if region, ok := config["s3_region"].(string); ok {
		s3Config["region"] = region
	}

	return types.StreamEndpointConfig{
		Type:   "aws_s3",
		Config: s3Config,
	}, nil
}

func (bg *BindingGenerator) generateKafkaEventPersistenceOutput(thingID, eventName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	persistenceTopic := fmt.Sprintf("twincore.persistence.%s.%s", thingID, eventName)
	if topic, ok := config["persistence_topic"].(string); ok {
		persistenceTopic = topic
	}

	return types.StreamEndpointConfig{
		Type: "kafka",
		Config: map[string]interface{}{
			"addresses": bg.kafkaConfig.Brokers,
			"topic":     persistenceTopic,
			"key":       fmt.Sprintf("${! this.thing_id }-%s", eventName),
		},
	}, nil
}

// generatePropertyMapping, generatePropertyPersistenceMapping, etc. are Bloblang mapping methods.
// These were moved to processors.go and are now called as top-level functions.

// Schema generation methods
// These were moved to schemas.go and are now called as top-level functions.

// convertDataSchemaToJSONSchema was moved to schemas.go and is now called as a top-level function.
