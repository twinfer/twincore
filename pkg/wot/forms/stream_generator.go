package forms

import (
	"context"
	"fmt"
	"strings"
	"time"

	"bytes"
	"text/template"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
)

const (
	benthosMainTemplate = `input:
{{ .InputYAML }}
pipeline:
  processors:
{{ .ProcessorYAML }}
output:
{{ .OutputYAML }}
`
	// More granular templates can be added here if needed, e.g., for specific input/output types
)

// executeGoTemplate executes a given Go template with provided data
func executeGoTemplate(name, tmplStr string, data interface{}) (string, error) {
	// This is a general utility, may not need specific contextual logger from caller.
	// If it were to log, it would ideally use a base logger or be passed one if errors are critical.
	tmpl, err := template.New(name).Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse template %s: %w", name, err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template %s: %w", name, err)
	}
	return buf.String(), nil
}

// logStreamGeneration is a helper function for standardized logging.
// It already accepts a logger.
func logStreamGeneration(logger logrus.FieldLogger, streamIDBase, thingID, interactionType, interactionName, topic, purpose string) {
	logger.WithFields(logrus.Fields{
		"stream_id_base":   streamIDBase, // This is more of a derived name/prefix
		"thing_id":         thingID,
		"interaction_type": interactionType,
		"interaction_name": interactionName,
		"topic":            topic,
		"purpose":          purpose,
	}).Debugf("Generating %s stream for %s %s", purpose, interactionType, interactionName)
}

// buildProcessorChain creates and stores a processor chain.
// Note: ProcessorConfig type here refers to the one defined in binding_generator.go (part of AllBindings).
// types.ProcessorConfig is used for the StreamCreationRequest.
func buildProcessorChain(logger logrus.FieldLogger, bg *BindingGenerator, namePrefix, chainDisplayName, interactionType, purpose, thingID, interactionName string, dataSchema *wot.DataSchemaCore, customMappings ...ProcessorConfig) (ProcessorChain, error) {
	opLogger := logger.WithFields(logrus.Fields{"chain_id_prefix": namePrefix, "purpose": purpose, "thing_id": thingID, "interaction_name": interactionName, "operation": "buildProcessorChain"})
	opLogger.Debug("Building processor chain")

	actualChainID := fmt.Sprintf("%s_processors", namePrefix)
	chain := ProcessorChain{
		ID:         actualChainID,
		Name:       chainDisplayName,
		Processors: []ProcessorConfig{},
		Metadata: map[string]interface{}{
			"thing_id":         thingID,
			"interaction_name": interactionName,
			"interaction_type": interactionType,
			"purpose":          purpose,
			"generated_by":     "binding_helper",
		},
	}

	// Add custom mappings first, as they are usually the primary transformation.
	chain.Processors = append(chain.Processors, customMappings...)

	// Add schema validation if dataSchema is provided.
	if dataSchema != nil && dataSchema.Type != "" { // Ensure there's a type to validate.
		jsonSchema := convertDataSchemaToJSONSchema(*dataSchema) // convertDataSchemaToJSONSchema is in schemas.go
		schemaValidationProcessor := ProcessorConfig{
			Type:  types.ProcessorJSONSchema,
			Label: fmt.Sprintf("%s_schema_validation", purpose),
			Config: map[string]interface{}{
				"schema": jsonSchema,
			},
			Description: fmt.Sprintf("Validate %s data against Thing Description schema", purpose),
		}
		chain.Processors = append(chain.Processors, schemaValidationProcessor)
		opLogger.WithFields(logrus.Fields{"chain_id": actualChainID, "processor_type": string(schemaValidationProcessor.Type), "processor_label": schemaValidationProcessor.Label}).Debug("Added schema validation processor to chain")
	}

	for _, proc := range customMappings { // Log custom mappings added
		opLogger.WithFields(logrus.Fields{"chain_id": actualChainID, "processor_type": string(proc.Type), "processor_label": proc.Label}).Debug("Added custom mapping processor to chain")
	}

	// Example: Add a common final processor if any (none for now)
	// This line assumes bg.bindings is accessible and meant to be mutated here.
	// This pattern of direct mutation of bg.bindings from stream_generator.go might be revisited for clarity.
	bg.bindings.Processors[actualChainID] = chain
	return chain, nil
}

// createStreamRequest constructs the StreamCreationRequest object and generates YAML.
func createStreamRequest(logger logrus.FieldLogger, bg *BindingGenerator, thingID, interactionType, interactionName, direction string, inputConfig types.StreamEndpointConfig, outputConfig types.StreamEndpointConfig, processorChainConfigs []types.ProcessorConfig, purpose string) (types.StreamCreationRequest, error) {
	opLogger := logger.WithFields(logrus.Fields{"thing_id": thingID, "interaction_name": interactionName, "purpose": purpose, "operation": "createStreamRequest"})
	opLogger.Debug("Creating stream request")
	request := types.StreamCreationRequest{
		ThingID:         thingID,
		InteractionType: interactionType,
		InteractionName: interactionName,
		Direction:       direction,
		Input:           inputConfig,
		Output:          outputConfig,
		ProcessorChain:  processorChainConfigs, // This should be []types.ProcessorConfig
		Metadata: map[string]interface{}{
			"generated_by": "binding_helper",
			"purpose":      purpose,
			"created_at":   time.Now().UTC().Format(time.RFC3339),
		},
	}

	yamlConfig, err := generateStreamRequestYAML(opLogger, bg, request) // Pass opLogger
	if err != nil {
		// Error already logged by generateStreamRequestYAML
		return types.StreamCreationRequest{}, fmt.Errorf("failed to generate YAML for stream request: %w", err)
	}
	request.Metadata["yaml_config"] = yamlConfig
	opLogger.Debug("Stream request YAML generated and added to metadata")
	return request, nil
}

// registerStreamWithManager creates the stream via streamManager and stores its config.
func registerStreamWithManager(logger logrus.FieldLogger, bg *BindingGenerator, request types.StreamCreationRequest, streamType types.BenthosStreamType, streamDirection types.StreamDirection, processorChain ProcessorChain) (StreamConfig, error) {
	opLogger := logger.WithFields(logrus.Fields{
		"thing_id": request.ThingID,
		"interaction_name": request.InteractionName,
		"purpose": request.Metadata["purpose"],
		"operation": "registerStreamWithManager",
	})
	opLogger.Debug("Registering stream with manager")

	streamInfo, err := bg.streamManager.CreateStream(context.Background(), request) // BenthosStreamManager.CreateStream does not take a logger
	if err != nil {
		opLogger.WithError(err).Error("Failed to create stream with BenthosStreamManager")
		// The error from streamManager.CreateStream should be one of the custom errors.
		return StreamConfig{}, err // Return the original error
	}

	createdStreamConfig := StreamConfig{
		ID:        streamInfo.ID,
		Type:      streamType,
		Direction: streamDirection,
		Input: StreamEndpoint{
			Protocol: types.StreamProtocol(request.Input.Type), // Assuming type is protocol string
			Config:   request.Input.Config,
		},
		Output: StreamEndpoint{
			Protocol: types.StreamProtocol(request.Output.Type), // Assuming type is protocol string
			Config:   request.Output.Config,
		},
		ProcessorChain: processorChain, // The one from buildProcessorChain
		YAML:           request.Metadata["yaml_config"].(string),
	}

	bg.bindings.Streams[streamInfo.ID] = createdStreamConfig

	opLogger.WithFields(logrus.Fields{
		"stream_id":       streamInfo.ID, // This is the actual ID from stream manager
		"benthos_id":      streamInfo.BenthosID, // Assuming StreamInfo has BenthosID
		"status":          streamInfo.Status,
		"processor_count": len(processorChain.Processors),
	}).Info("Stream registered successfully with manager")

	return createdStreamConfig, nil
}


// generatePropertyObservationStream, generatePropertyCommandStream, etc.
// These functions now take a logger as the first argument.

func generatePropertyObservationStream(logger logrus.FieldLogger, bg *BindingGenerator, thingID, propName string, prop *wot.PropertyAffordance) error {
	opLogger := logger.WithFields(logrus.Fields{"thing_id": thingID, "property_name": propName, "operation": "generatePropertyObservationStream"})
	if !bg.licenseChecker.IsFeatureAvailable("property_streaming") {
		opLogger.WithField("feature", "property_streaming").Debug("Property streaming not available in license")
		return nil
	}

	streamIDBase := fmt.Sprintf("%s_property_%s_observation", thingID, propName)
	topic := fmt.Sprintf("things.%s.properties.%s", thingID, propName)
	purpose := "property_observation"

	logStreamGeneration(opLogger, streamIDBase, thingID, "property", propName, topic, purpose)

	observationMapping := ProcessorConfig{
		Type:  types.ProcessorBloblangWoTProperty, // This is internal forms.ProcessorConfig
		Label: "property_observation_mapping",
		Config: map[string]interface{}{
			"mapping": generatePropertyObservationMapping(thingID, propName),
		},
		Description: "Map property data for observation clients",
	}

	var dataSchemaCore *wot.DataSchemaCore
	if prop.Type != "" {
		dataSchemaCore = &prop.DataSchemaCore
	}

	processorChain, err := buildProcessorChain(opLogger, bg, streamIDBase, // Pass opLogger
		fmt.Sprintf("Property %s observation processors", propName),
		"property", purpose, thingID, propName, dataSchemaCore, observationMapping)
	if err != nil {
		return fmt.Errorf("failed to build processor chain for %s: %w", streamIDBase, err)
	}

	outputConfig, err := generateObservationOutputConfig(opLogger, bg, thingID, propName, bg.licenseChecker.GetFeatureConfig("property_streaming")) // Pass opLogger
	if err != nil {
		return fmt.Errorf("failed to generate observation output config for %s: %w", streamIDBase, err)
	}

	inputConfig := types.StreamEndpointConfig{
		Type: "kafka",
		Config: map[string]interface{}{
			"addresses":      bg.kafkaConfig.Brokers,
			"topics":         []string{topic},
			"consumer_group": fmt.Sprintf("twincore-property-observation-%s-%s", thingID, propName),
		},
	}

	typedProcessorConfigs := bg.convertToTypesProcessorConfig(processorChain.Processors)

	request, err := createStreamRequest(opLogger, bg, thingID, "properties", propName, "output", // Pass opLogger
		inputConfig, outputConfig, typedProcessorConfigs, purpose)
	if err != nil {
		return fmt.Errorf("failed to create stream request for %s: %w", streamIDBase, err)
	}

	_, err = registerStreamWithManager(opLogger, bg, request, types.StreamTypePropertyOutput, types.StreamDirectionOutbound, processorChain) // Pass opLogger
	if err != nil {
		// Error already logged by registerStreamWithManager
		return err
	}

	opLogger.Info("Property observation stream processing complete")
	return nil
}

func generatePropertyCommandStream(logger logrus.FieldLogger, bg *BindingGenerator, thingID, propName string, prop *wot.PropertyAffordance) error {
	opLogger := logger.WithFields(logrus.Fields{"thing_id": thingID, "property_name": propName, "operation": "generatePropertyCommandStream"})
	if !bg.licenseChecker.IsFeatureAvailable("property_commands") {
		opLogger.WithField("feature", "property_commands").Debug("Property commands not available in license")
		return nil
	}

	streamIDBase := fmt.Sprintf("%s_property_%s_command", thingID, propName)
	purpose := "property_command"

	logStreamGeneration(opLogger, streamIDBase, thingID, "property", propName, "", purpose)

	commandMapping := ProcessorConfig{
		Type:  types.ProcessorBloblangWoTProperty,
		Label: "property_command_mapping",
		Config: map[string]interface{}{
			"mapping": generatePropertyCommandMapping(thingID, propName),
		},
		Description: "Map property command data for device execution",
	}
	deviceTransformMapping := ProcessorConfig{
		Type:  types.ProcessorBloblangWoTProperty,
		Label: "device_command_transform",
		Config: map[string]interface{}{
			"mapping": generateDeviceCommandMapping(thingID, propName),
		},
		Description: "Transform command for device-specific protocol",
	}

	var dataSchemaCore *wot.DataSchemaCore
	if prop.Type != "" {
		dataSchemaCore = &prop.DataSchemaCore
	}

	processorChain, err := buildProcessorChain(bg, streamIDBase,
		fmt.Sprintf("Property %s command processors", propName),
		"property", purpose, thingID, propName, dataSchemaCore, commandMapping, deviceTransformMapping)
	if err != nil {
		return fmt.Errorf("failed to build processor chain for %s: %w", streamIDBase, err)
	}

	outputConfig, err := generateCommandOutputConfig(bg, thingID, propName, bg.licenseChecker.GetFeatureConfig("property_commands"))
	if err != nil {
		return fmt.Errorf("failed to generate command output config for %s: %w", streamIDBase, err)
	}

	inputConfig := types.StreamEndpointConfig{
		Type: "http_server",
		Config: map[string]interface{}{
			"address":       "${HTTP_ADDRESS:0.0.0.0:8080}",
			"path":          fmt.Sprintf("/things/%s/properties/%s", thingID, propName),
			"allowed_verbs": []string{"PUT", "PATCH"},
			"timeout":       "30s",
		},
	}

	typedProcessorConfigs := bg.convertToTypesProcessorConfig(processorChain.Processors)

	request, err := createStreamRequest(bg, thingID, "properties", propName, "input",
		inputConfig, outputConfig, typedProcessorConfigs, purpose)
	if err != nil {
		return fmt.Errorf("failed to create stream request for %s: %w", streamIDBase, err)
	}

	_, err = registerStreamWithManager(bg, request, types.StreamTypePropertyInput, types.StreamDirectionInbound, processorChain)
	if err != nil {
		bg.logger.WithError(err).WithFields(logrus.Fields{"thing_id": thingID, "property_name": propName, "stream_purpose": purpose}).Error("Failed during property command stream generation (registering)")
		return err
	}

	bg.logger.WithField("stream_id_base", streamIDBase).Info("Property command stream processing complete")
	return nil
}

func generatePropertyLoggingStream(bg *BindingGenerator, thingID, propName string, prop *wot.PropertyAffordance) error {
	if !bg.licenseChecker.IsFeatureAvailable("data_persistence") {
		bg.logger.WithField("feature", "data_persistence").Debug("Persistence feature not available in license")
		return nil
	}

	streamIDBase := fmt.Sprintf("%s_property_%s_persistence", thingID, propName)
	topic := fmt.Sprintf("things.%s.properties.%s", thingID, propName) // Input topic for persistence
	purpose := "property_persistence"

	logStreamGeneration(bg.logger, streamIDBase, thingID, "property", propName, topic, purpose)

	persistenceMapping := ProcessorConfig{
		Type:  types.ProcessorBloblangWoTProperty,
		Label: "property_normalization",
		Config: map[string]interface{}{
			"mapping": generatePropertyPersistenceMapping(thingID, propName),
		},
		Description: "Normalize property data for persistence",
	}

	// Determine additional processors based on persistence config (e.g., Parquet encoding)
	var additionalProcessors []ProcessorConfig
	persistenceCfg := bg.licenseChecker.GetFeatureConfig("data_persistence")
	if format, ok := persistenceCfg["format"].(string); ok {
		if format == "parquet" {
			additionalProcessors = append(additionalProcessors, ProcessorConfig{
				Type:  types.ProcessorParquetEncode,
				Label: "parquet_encoding",
				Config: map[string]interface{}{
					"schema": generatePropertyParquetSchema(), // from schemas.go
				},
				Description: "Encode property data to Parquet format",
			})
		} else if format == "json" {
			additionalProcessors = append(additionalProcessors, ProcessorConfig{
				Type: types.ProcessorJSONEncode,
				Label: "json_encoding",
				Config: map[string]interface{}{},
				Description: "Encode property data to JSON format",
			})
		}
	}

	allMappings := append([]ProcessorConfig{persistenceMapping}, additionalProcessors...)

	processorChain, err := buildProcessorChain(bg, streamIDBase,
		fmt.Sprintf("Property %s persistence processors", propName),
		"property", purpose, thingID, propName, nil, allMappings...) // No data schema for validation, only for encoding if any
	if err != nil {
		return fmt.Errorf("failed to build processor chain for %s: %w", streamIDBase, err)
	}

	outputConfig, err := generatePersistenceOutputConfig(bg, thingID, propName, persistenceCfg)
	if err != nil {
		return fmt.Errorf("failed to generate persistence output config for %s: %w", streamIDBase, err)
	}

	inputConfig := types.StreamEndpointConfig{
		Type: "kafka",
		Config: map[string]interface{}{
			"addresses":      bg.kafkaConfig.Brokers,
			"topics":         []string{topic},
			"consumer_group": fmt.Sprintf("twincore-property-persistence-%s-%s", thingID, propName),
		},
	}

	typedProcessorConfigs := bg.convertToTypesProcessorConfig(processorChain.Processors)

	request, err := createStreamRequest(bg, thingID, "properties", propName, "input", // Direction "input" as it consumes from internal topic
		inputConfig, outputConfig, typedProcessorConfigs, purpose)
	if err != nil {
		return fmt.Errorf("failed to create stream request for %s: %w", streamIDBase, err)
	}

	_, err = registerStreamWithManager(bg, request, types.StreamTypePropertyLogger, types.StreamDirectionInternal, processorChain)
	if err != nil {
		bg.logger.WithError(err).WithFields(logrus.Fields{"thing_id": thingID, "property_name": propName, "stream_purpose": purpose}).Error("Failed during property logging stream generation (registering)")
		return err
	}

	bg.logger.WithField("stream_id_base", streamIDBase).Info("Property logging stream processing complete")
	return nil
}

func generateActionInvocationStream(bg *BindingGenerator, thingID, actionName string, action *wot.ActionAffordance) error {
	if !bg.licenseChecker.IsFeatureAvailable("action_invocation") {
		bg.logger.WithField("feature", "action_invocation").Debug("Action invocation not available in license")
		return nil
	}

	streamIDBase := fmt.Sprintf("%s_action_%s_invocation", thingID, actionName)
	purpose := "action_invocation"

	logStreamGeneration(bg.logger, streamIDBase, thingID, "action", actionName, "", purpose)

	invocationMapping := ProcessorConfig{
		Type:  types.ProcessorBloblangWoTAction,
		Label: "action_invocation_mapping",
		Config: map[string]interface{}{
			"mapping": generateActionInvocationMapping(thingID, actionName),
		},
		Description: "Map action invocation data for device execution",
	}
	deviceActionMapping := ProcessorConfig{
		Type:  types.ProcessorBloblangWoTAction,
		Label: "device_action_transform",
		Config: map[string]interface{}{
			"mapping": generateDeviceActionMapping(thingID, actionName),
		},
		Description: "Transform action for device-specific protocol",
	}

	var dataSchemaCore *wot.DataSchemaCore
	if action.Input != nil && action.Input.Type != "" {
		dataSchemaCore = &action.Input.DataSchemaCore
	}

	processorChain, err := buildProcessorChain(bg, streamIDBase,
		fmt.Sprintf("Action %s invocation processors", actionName),
		"action", purpose, thingID, actionName, dataSchemaCore, invocationMapping, deviceActionMapping)
	if err != nil {
		return fmt.Errorf("failed to build processor chain for %s: %w", streamIDBase, err)
	}

	outputConfig, err := generateActionOutputConfig(bg, thingID, actionName, bg.licenseChecker.GetFeatureConfig("action_invocation"))
	if err != nil {
		return fmt.Errorf("failed to generate action output config for %s: %w", streamIDBase, err)
	}

	inputConfig := types.StreamEndpointConfig{
		Type: "http_server",
		Config: map[string]interface{}{
			"address":       "${HTTP_ADDRESS:0.0.0.0:8080}",
			"path":          fmt.Sprintf("/things/%s/actions/%s", thingID, actionName),
			"allowed_verbs": []string{"POST"},
			"timeout":       "30s",
		},
	}

	typedProcessorConfigs := bg.convertToTypesProcessorConfig(processorChain.Processors)

	request, err := createStreamRequest(bg, thingID, "actions", actionName, "input",
		inputConfig, outputConfig, typedProcessorConfigs, purpose)
	if err != nil {
		return fmt.Errorf("failed to create stream request for %s: %w", streamIDBase, err)
	}

	_, err = registerStreamWithManager(bg, request, types.StreamTypeActionInput, types.StreamDirectionInbound, processorChain)
	if err != nil {
		bg.logger.WithError(err).WithFields(logrus.Fields{"thing_id": thingID, "action_name": actionName, "stream_purpose": purpose}).Error("Failed during action invocation stream generation (registering)")
		return err
	}

	bg.logger.WithField("stream_id_base", streamIDBase).Info("Action invocation stream processing complete")
	return nil
}

func generateActionLoggingStream(bg *BindingGenerator, thingID, actionName string, action *wot.ActionAffordance) error {
	if !bg.licenseChecker.IsFeatureAvailable("data_persistence") {
		bg.logger.WithField("feature", "data_persistence").Debug("Persistence feature not available in license")
		return nil
	}

	streamIDBase := fmt.Sprintf("%s_action_%s_persistence", thingID, actionName)
	topic := fmt.Sprintf("things.%s.actions.%s", thingID, actionName) // Input topic for persistence
	purpose := "action_persistence"

	logStreamGeneration(bg.logger, streamIDBase, thingID, "action", actionName, topic, purpose)

	persistenceMapping := ProcessorConfig{
		Type:  types.ProcessorBloblangWoTAction,
		Label: "action_normalization",
		Config: map[string]interface{}{
			"mapping": generateActionPersistenceMapping(thingID, actionName),
		},
		Description: "Normalize action data for persistence",
	}

	var additionalProcessors []ProcessorConfig
	persistenceCfg := bg.licenseChecker.GetFeatureConfig("data_persistence")
	if format, ok := persistenceCfg["format"].(string); ok {
		if format == "parquet" {
			additionalProcessors = append(additionalProcessors, ProcessorConfig{
				Type:  types.ProcessorParquetEncode,
				Label: "parquet_encoding",
				Config: map[string]interface{}{
					"schema": generateActionParquetSchema(), // from schemas.go
				},
				Description: "Encode action data to Parquet format",
			})
		} else if format == "json" {
				additionalProcessors = append(additionalProcessors, ProcessorConfig{
				Type: types.ProcessorJSONEncode,
				Label: "json_encoding",
				Config: map[string]interface{}{},
				Description: "Encode action data to JSON format",
			})
		}
	}
	allMappings := append([]ProcessorConfig{persistenceMapping}, additionalProcessors...)

	processorChain, err := buildProcessorChain(bg, streamIDBase,
		fmt.Sprintf("Action %s persistence processors", actionName),
		"action", purpose, thingID, actionName, nil, allMappings...)
	if err != nil {
		return fmt.Errorf("failed to build processor chain for %s: %w", streamIDBase, err)
	}

	outputConfig, err := generateActionPersistenceOutputConfig(bg, thingID, actionName, persistenceCfg)
	if err != nil {
		return fmt.Errorf("failed to generate action persistence output config for %s: %w", streamIDBase, err)
	}

	inputConfig := types.StreamEndpointConfig{
		Type: "kafka",
		Config: map[string]interface{}{
			"addresses":      bg.kafkaConfig.Brokers,
			"topics":         []string{topic},
			"consumer_group": fmt.Sprintf("twincore-action-persistence-%s-%s", thingID, actionName),
		},
	}

	typedProcessorConfigs := bg.convertToTypesProcessorConfig(processorChain.Processors)

	request, err := createStreamRequest(bg, thingID, "actions", actionName, "input",
		inputConfig, outputConfig, typedProcessorConfigs, purpose)
	if err != nil {
		return fmt.Errorf("failed to create stream request for %s: %w", streamIDBase, err)
	}

	_, err = registerStreamWithManager(bg, request, types.StreamTypeActionLogger, types.StreamDirectionInternal, processorChain)
	if err != nil {
		bg.logger.WithError(err).WithFields(logrus.Fields{"thing_id": thingID, "action_name": actionName, "stream_purpose": purpose}).Error("Failed during action logging stream generation (registering)")
		return err
	}

	bg.logger.WithField("stream_id_base", streamIDBase).Info("Action logging stream processing complete")
	return nil
}

func generateEventProcessingStream(bg *BindingGenerator, thingID, eventName string, event *wot.EventAffordance) error {
	if !bg.licenseChecker.IsFeatureAvailable("event_processing") {
		bg.logger.WithField("feature", "event_processing").Debug("Event processing not available in license")
		return nil
	}

	streamIDBase := fmt.Sprintf("%s_event_%s_processing", thingID, eventName)
	topic := fmt.Sprintf("things.%s.events.%s", thingID, eventName)
	purpose := "event_processing"

	logStreamGeneration(bg.logger, streamIDBase, thingID, "event", eventName, topic, purpose)

	processingMapping := ProcessorConfig{
		Type:  types.ProcessorBloblangWoTEvent,
		Label: "event_processing_mapping",
		Config: map[string]interface{}{
			"mapping": generateEventProcessingMapping(thingID, eventName),
		},
		Description: "Map event data for client distribution",
	}
	enrichmentMapping := ProcessorConfig{
		Type:  types.ProcessorBloblangWoTEvent,
		Label: "event_enrichment",
		Config: map[string]interface{}{
			"mapping": generateEventEnrichmentMapping(thingID, eventName),
		},
		Description: "Enrich event data for client consumption",
	}

	var dataSchemaCore *wot.DataSchemaCore
	if event.Data != nil && event.Data.Type != "" {
		dataSchemaCore = &event.Data.DataSchemaCore
	}

	processorChain, err := buildProcessorChain(bg, streamIDBase,
		fmt.Sprintf("Event %s processing processors", eventName),
		"event", purpose, thingID, eventName, dataSchemaCore, processingMapping, enrichmentMapping)
	if err != nil {
		return fmt.Errorf("failed to build processor chain for %s: %w", streamIDBase, err)
	}

	outputConfig, err := generateEventOutputConfig(bg, thingID, eventName, bg.licenseChecker.GetFeatureConfig("event_processing"))
	if err != nil {
		return fmt.Errorf("failed to generate event output config for %s: %w", streamIDBase, err)
	}

	inputConfig := types.StreamEndpointConfig{
		Type: "kafka",
		Config: map[string]interface{}{
			"addresses":      bg.kafkaConfig.Brokers,
			"topics":         []string{topic},
			"consumer_group": fmt.Sprintf("twincore-event-processing-%s-%s", thingID, eventName),
		},
	}

	typedProcessorConfigs := bg.convertToTypesProcessorConfig(processorChain.Processors)

	request, err := createStreamRequest(bg, thingID, "events", eventName, "output",
		inputConfig, outputConfig, typedProcessorConfigs, purpose)
	if err != nil {
		return fmt.Errorf("failed to create stream request for %s: %w", streamIDBase, err)
	}

	_, err = registerStreamWithManager(bg, request, types.StreamTypeEventOutput, types.StreamDirectionOutbound, processorChain)
	if err != nil {
		bg.logger.WithError(err).WithFields(logrus.Fields{"thing_id": thingID, "event_name": eventName, "stream_purpose": purpose}).Error("Failed during event processing stream generation (registering)")
		return err
	}

	bg.logger.WithField("stream_id_base", streamIDBase).Info("Event processing stream processing complete")
	return nil
}

func generateEventLoggingStream(bg *BindingGenerator, thingID, eventName string, event *wot.EventAffordance) error {
	if !bg.licenseChecker.IsFeatureAvailable("data_persistence") {
		bg.logger.WithField("feature", "data_persistence").Debug("Persistence feature not available in license")
		return nil
	}

	streamIDBase := fmt.Sprintf("%s_event_%s_persistence", thingID, eventName)
	topic := fmt.Sprintf("things.%s.events.%s", thingID, eventName) // Input topic for persistence
	purpose := "event_persistence"

	logStreamGeneration(bg.logger, streamIDBase, thingID, "event", eventName, topic, purpose)

	persistenceMapping := ProcessorConfig{
		Type:  types.ProcessorBloblangWoTEvent,
		Label: "event_normalization",
		Config: map[string]interface{}{
			"mapping": generateEventPersistenceMapping(thingID, eventName),
		},
		Description: "Normalize event data for persistence",
	}

	var additionalProcessors []ProcessorConfig
	persistenceCfg := bg.licenseChecker.GetFeatureConfig("data_persistence")
	if format, ok := persistenceCfg["format"].(string); ok {
		if format == "parquet" {
			additionalProcessors = append(additionalProcessors, ProcessorConfig{
				Type:  types.ProcessorParquetEncode,
				Label: "parquet_encoding",
				Config: map[string]interface{}{
					"schema": generateEventParquetSchema(), // from schemas.go
				},
				Description: "Encode event data to Parquet format",
			})
		} else if format == "json" {
			additionalProcessors = append(additionalProcessors, ProcessorConfig{
				Type: types.ProcessorJSONEncode,
				Label: "json_encoding",
				Config: map[string]interface{}{},
				Description: "Encode event data to JSON format",
			})
		}
	}
	allMappings := append([]ProcessorConfig{persistenceMapping}, additionalProcessors...)

	// For event logging/persistence, the schema being validated (if any) would be event.Data.DataSchemaCore
	var dataSchemaCore *wot.DataSchemaCore
	if event.Data != nil && event.Data.Type != "" {
		dataSchemaCore = &event.Data.DataSchemaCore
	}


	processorChain, err := buildProcessorChain(bg, streamIDBase,
		fmt.Sprintf("Event %s persistence processors", eventName),
		"event", purpose, thingID, eventName, dataSchemaCore, allMappings...)
	if err != nil {
		return fmt.Errorf("failed to build processor chain for %s: %w", streamIDBase, err)
	}

	outputConfig, err := generateEventPersistenceOutputConfig(bg, thingID, eventName, persistenceCfg)
	if err != nil {
		return fmt.Errorf("failed to generate event persistence output config for %s: %w", streamIDBase, err)
	}

	inputConfig := types.StreamEndpointConfig{
		Type: "kafka",
		Config: map[string]interface{}{
			"addresses":      bg.kafkaConfig.Brokers,
			"topics":         []string{topic},
			"consumer_group": fmt.Sprintf("twincore-event-persistence-%s-%s", thingID, eventName),
		},
	}

	typedProcessorConfigs := bg.convertToTypesProcessorConfig(processorChain.Processors)

	request, err := createStreamRequest(bg, thingID, "events", eventName, "input",
		inputConfig, outputConfig, typedProcessorConfigs, purpose)
	if err != nil {
		return fmt.Errorf("failed to create stream request for %s: %w", streamIDBase, err)
	}

	_, err = registerStreamWithManager(bg, request, types.StreamTypeEventLogger, types.StreamDirectionInternal, processorChain)
	if err != nil {
		bg.logger.WithError(err).WithFields(logrus.Fields{"thing_id": thingID, "event_name": eventName, "stream_purpose": purpose}).Error("Failed during event logging stream generation (registering)")
		return err
	}

	bg.logger.WithField("stream_id_base", streamIDBase).Info("Event logging stream processing complete")
	return nil
}

// generateStreamRequestYAML generates complete YAML configuration for a stream request
func generateStreamRequestYAML(bg *BindingGenerator, request types.StreamCreationRequest) (string, error) {
	inputYAML, err := generateInputYAML(bg, request.Input)
	if err != nil {
		return "", fmt.Errorf("failed to generate input YAML: %w", err)
	}

	processorYAML, err := generateProcessorChainYAML(bg, request.ProcessorChain)
	if err != nil {
		return "", fmt.Errorf("failed to generate processor YAML: %w", err)
	}

	outputYAML, err := generateOutputYAML(bg, request.Output)
	if err != nil {
		return "", fmt.Errorf("failed to generate output YAML: %w", err)
	}

	templateData := map[string]string{
		"InputYAML":     indentString(inputYAML, "  "), // Indent to fit into the main template
		"ProcessorYAML": indentString(processorYAML, "    "), // Indent further for processors
		"OutputYAML":    indentString(outputYAML, "  "),
	}

	return executeGoTemplate("benthosMain", benthosMainTemplate, templateData)
}

// generateInputYAML now returns a YAML string snippet for the input part
func generateInputYAML(bg *BindingGenerator, input types.StreamEndpointConfig) (string, error) {
	// Simple example: directly use the existing logic but ensure it returns a string.
	// More complex scenarios might involve creating a map/struct for templating.
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
			consumerGroup), nil

	case "mqtt":
		urls := []string{bg.mqttConfig.Broker}
		topics := input.Config["topics"].([]string)
		clientID := input.Config["client_id"].(string)
		qos := input.Config["qos"]
		return fmt.Sprintf(`%s:
    urls: [%s]
    topics: [%s]
    client_id: "%s"
    qos: %v`,
			input.Type, // Use input.Type as the key
			quoteAndJoin(urls),
			quoteAndJoin(topics),
			clientID,
			qos), nil

	case "http_server":
		path := input.Config["path"].(string)
		return fmt.Sprintf(`%s:
    address: "${HTTP_ADDRESS:0.0.0.0:8080}"
    path: "%s"
    allowed_verbs: ["POST", "PUT"]
    timeout: "30s"`, input.Type, path), nil

	default:
		return "", fmt.Errorf("unsupported input type: %s", input.Type)
	}
}

// generateProcessorChainYAML now returns a YAML string snippet for the processor chain
func generateProcessorChainYAML(bg *BindingGenerator, processors []types.ProcessorConfig) (string, error) {
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
			schemaYAML, err := generateParquetSchemaYAML(bg, schema)
			if err != nil {
				return "", fmt.Errorf("failed to generate parquet schema YAML: %w", err)
			}
			lines = append(lines, fmt.Sprintf(`- label: "encode_parquet"
      parquet_encode:
        schema:
%s`, indentString(schemaYAML, "          "))) // Indent schema under schema key

		case string(types.ProcessorJSONSchema):
			if schema, ok := proc.Config["schema"]; ok {
				lines = append(lines, fmt.Sprintf(`    - label: "json_schema_validation"
      json_schema:
        schema: %v`, schema))
			}

		default:
			lines = append(lines, fmt.Sprintf(`- label: "%s_processor"
      %s: {}`, proc.Type, proc.Type))
		}
	}
	// Each processor starts with "- " which is the correct YAML list format
	return strings.Join(lines, "\n"), nil
}

// generateOutputYAML now returns a YAML string snippet for the output part
func generateOutputYAML(bg *BindingGenerator, output types.StreamEndpointConfig) (string, error) {
	switch output.Type {
	case "kafka":
		addresses := bg.kafkaConfig.Brokers // Assuming bg is accessible or passed
		topic := output.Config["topic"].(string)
		return fmt.Sprintf(`  kafka:
    addresses: [%s]
    topic: "%s"
    key: "${! this.thing_id }"`,
			output.Type, // Use output.Type as the key
			quoteAndJoin(addresses),
			topic), nil

	case "mqtt":
		urls := []string{bg.mqttConfig.Broker}
		// topic is a single string for output, not a list like input
		topic, ok := output.Config["topic"].(string)
		if !ok {
			return "", fmt.Errorf("mqtt output topic is not a string or missing")
		}
		clientID := output.Config["client_id"].(string)
		qos := output.Config["qos"]
		return fmt.Sprintf(`%s:
    urls: [%s]
    topic: "%s"
    client_id: "%s"
    qos: %v`,
			output.Type,
			quoteAndJoin(urls),
			topic, // Use the single topic string
			clientID,
			qos), nil

	case "file", "parquet":
		path := output.Config["path"].(string)
		return fmt.Sprintf(`%s:
    path: "%s"
    codec: none`, output.Type, path), nil // Assuming output.Type is "file" or "parquet" if logic routes here.

	default:
		return "", fmt.Errorf("unsupported output type: %s", output.Type)
	}
}

// generateParquetSchemaYAML now returns a YAML string snippet for the parquet schema
func generateParquetSchemaYAML(bg *BindingGenerator, schema []map[string]interface{}) (string, error) {
	var lines []string
	for _, field := range schema {
		lines = append(lines, fmt.Sprintf(`- name: "%s"
  type: "%s"
  converted_type: "%s"`, // No leading spaces here, handled by indentString later
			field["name"],
			field["type"],
			field["converted_type"]))
	}
	return strings.Join(lines, "\n"), nil
}

// Helper to convert internal ProcessorConfig to types.ProcessorConfig
// This might be specific to BindingGenerator logic or could be a general utility
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

// quoteAndJoin and indentString could be moved here if primarily used by YAML generation.
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

// Deprecated YAML generation functions (generateStreamYAML, generateEndpointYAML) are removed.
