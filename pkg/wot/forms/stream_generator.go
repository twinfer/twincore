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
func logStreamGeneration(logger logrus.FieldLogger, streamIDBase, thingID, interactionType, interactionName, topic, purpose string) {
	logger.WithFields(logrus.Fields{
		"stream_id_base":   streamIDBase,
		"thing_id":         thingID,
		"interaction_type": interactionType,
		"interaction_name": interactionName,
		"topic":            topic,
		"purpose":          purpose,
	}).Debugf("Generating %s stream for %s %s", purpose, interactionType, interactionName)
}

// buildProcessorChain creates and stores a processor chain.
func buildProcessorChain(logger logrus.FieldLogger, bg *BindingGenerator, namePrefix, chainDisplayName, interactionType, purpose, thingID, interactionName string, dataSchema *wot.DataSchemaCore, bindings *AllBindings, customMappings ...ProcessorConfig) (ProcessorChain, error) {
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

	chain.Processors = append(chain.Processors, customMappings...)

	if dataSchema != nil && dataSchema.Type != "" {
		jsonSchema := convertDataSchemaToJSONSchema(*dataSchema)
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

	for _, proc := range customMappings {
		opLogger.WithFields(logrus.Fields{"chain_id": actualChainID, "processor_type": string(proc.Type), "processor_label": proc.Label}).Debug("Added custom mapping processor to chain")
	}

	bindings.Processors[actualChainID] = chain
	return chain, nil
}

// createStreamRequest constructs the StreamCreationRequest object and generates YAML.
func createStreamRequest(logger logrus.FieldLogger, bg *BindingGenerator, thingID, interactionType, interactionName, direction string, inputConfig types.StreamEndpointConfig, outputConfig types.StreamEndpointConfig, processorChainConfigs []types.ProcessorConfig, purpose string, bindings *AllBindings) (types.StreamCreationRequest, error) {
	opLogger := logger.WithFields(logrus.Fields{"thing_id": thingID, "interaction_name": interactionName, "purpose": purpose, "operation": "createStreamRequest"})
	opLogger.Debug("Creating stream request")
	request := types.StreamCreationRequest{
		ThingID:         thingID,
		InteractionType: interactionType,
		InteractionName: interactionName,
		Direction:       direction,
		Input:           inputConfig,
		Output:          outputConfig,
		ProcessorChain:  processorChainConfigs,
		Metadata: map[string]interface{}{
			"generated_by": "binding_helper",
			"purpose":      purpose,
			"created_at":   time.Now().UTC().Format(time.RFC3339),
		},
	}

	yamlConfig, err := generateStreamRequestYAML(opLogger, bg, request)
	if err != nil {
		return types.StreamCreationRequest{}, fmt.Errorf("failed to generate YAML for stream request: %w", err)
	}
	request.Metadata["yaml_config"] = yamlConfig
	opLogger.Debug("Stream request YAML generated and added to metadata")
	return request, nil
}

// registerStreamWithManager creates the stream via streamManager and stores its config.
func registerStreamWithManager(logger logrus.FieldLogger, bg *BindingGenerator, request types.StreamCreationRequest, streamType types.BenthosStreamType, streamDirection types.StreamDirection, processorChain ProcessorChain, bindings *AllBindings) (StreamConfig, error) {
	opLogger := logger.WithFields(logrus.Fields{
		"thing_id":         request.ThingID,
		"interaction_name": request.InteractionName,
		"purpose":          request.Metadata["purpose"],
		"operation":        "registerStreamWithManager",
	})
	opLogger.Debug("Registering stream with manager")

	streamInfo, err := bg.streamManager.CreateStream(context.Background(), request)
	if err != nil {
		opLogger.WithError(err).Error("Failed to create stream with BenthosStreamManager")
		return StreamConfig{}, err
	}

	createdStreamConfig := StreamConfig{
		ID:        streamInfo.ID,
		Type:      streamType,
		Direction: streamDirection,
		Input: StreamEndpoint{
			Protocol: types.StreamProtocol(request.Input.Type),
			Config:   request.Input.Config,
		},
		Output: StreamEndpoint{
			Protocol: types.StreamProtocol(request.Output.Type),
			Config:   request.Output.Config,
		},
		ProcessorChain: processorChain,
		YAML:           request.Metadata["yaml_config"].(string),
	}

	bindings.Streams[streamInfo.ID] = createdStreamConfig

	opLogger.WithFields(logrus.Fields{
		"stream_id":       streamInfo.ID,
		"status":          streamInfo.Status,
		"processor_count": len(processorChain.Processors),
	}).Info("Stream registered successfully with manager")

	return createdStreamConfig, nil
}

func generatePropertyObservationStream(logger logrus.FieldLogger, bg *BindingGenerator, thingID, propName string, prop *wot.PropertyAffordance, bindings *AllBindings) error {
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
		Type:  types.ProcessorBloblangWoTProperty,
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

	processorChain, err := buildProcessorChain(opLogger, bg, streamIDBase,
		fmt.Sprintf("Property %s observation processors", propName),
		"property", purpose, thingID, propName, dataSchemaCore, bindings, observationMapping)
	if err != nil {
		return fmt.Errorf("failed to build processor chain for %s: %w", streamIDBase, err)
	}

	outputConfig, err := bg.generateObservationOutputConfig(thingID, propName, bg.licenseChecker.GetFeatureConfig("property_streaming"))
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

	request, err := createStreamRequest(opLogger, bg, thingID, "properties", propName, "output",
		inputConfig, outputConfig, typedProcessorConfigs, purpose, bindings)
	if err != nil {
		return fmt.Errorf("failed to create stream request for %s: %w", streamIDBase, err)
	}

	_, err = registerStreamWithManager(opLogger, bg, request, types.StreamTypePropertyOutput, types.StreamDirectionOutbound, processorChain, bindings)
	if err != nil {
		return err
	}

	opLogger.Info("Property observation stream processing complete")
	return nil
}

func generatePropertyCommandStream(logger logrus.FieldLogger, bg *BindingGenerator, thingID, propName string, prop *wot.PropertyAffordance, bindings *AllBindings) error {
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

	processorChain, err := buildProcessorChain(opLogger, bg, streamIDBase,
		fmt.Sprintf("Property %s command processors", propName),
		"property", purpose, thingID, propName, dataSchemaCore, bindings, commandMapping, deviceTransformMapping)
	if err != nil {
		return fmt.Errorf("failed to build processor chain for %s: %w", streamIDBase, err)
	}

	outputConfig, err := bg.generateCommandOutputConfig(thingID, propName, bg.licenseChecker.GetFeatureConfig("property_commands"))
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

	request, err := createStreamRequest(opLogger, bg, thingID, "properties", propName, "input",
		inputConfig, outputConfig, typedProcessorConfigs, purpose, bindings)
	if err != nil {
		return fmt.Errorf("failed to create stream request for %s: %w", streamIDBase, err)
	}

	_, err = registerStreamWithManager(opLogger, bg, request, types.StreamTypePropertyInput, types.StreamDirectionInbound, processorChain, bindings)
	if err != nil {
		bg.logger.WithError(err).WithFields(logrus.Fields{"thing_id": thingID, "property_name": propName, "stream_purpose": purpose}).Error("Failed during property command stream generation (registering)")
		return err
	}

	bg.logger.WithField("stream_id_base", streamIDBase).Info("Property command stream processing complete")
	return nil
}

func generatePropertyLoggingStream(logger logrus.FieldLogger, bg *BindingGenerator, thingID, propName string, prop *wot.PropertyAffordance, bindings *AllBindings) error {
	opLogger := logger.WithFields(logrus.Fields{"thing_id": thingID, "property_name": propName, "operation": "generatePropertyLoggingStream"})
	if !bg.licenseChecker.IsFeatureAvailable("data_persistence") {
		opLogger.WithField("feature", "data_persistence").Debug("Persistence feature not available in license")
		return nil
	}

	streamIDBase := fmt.Sprintf("%s_property_%s_persistence", thingID, propName)
	topic := fmt.Sprintf("things.%s.properties.%s", thingID, propName)
	purpose := "property_persistence"

	logStreamGeneration(opLogger, streamIDBase, thingID, "property", propName, topic, purpose)

	persistenceMapping := ProcessorConfig{
		Type:  types.ProcessorBloblangWoTProperty,
		Label: "property_normalization",
		Config: map[string]interface{}{
			"mapping": generatePropertyPersistenceMapping(thingID, propName),
		},
		Description: "Normalize property data for persistence",
	}

	var additionalProcessors []ProcessorConfig
	persistenceCfg := bg.licenseChecker.GetFeatureConfig("data_persistence")
	if format, ok := persistenceCfg["format"].(string); ok {
		if format == "parquet" {
			additionalProcessors = append(additionalProcessors, ProcessorConfig{
				Type:  types.ProcessorParquetEncode,
				Label: "parquet_encoding",
				Config: map[string]interface{}{
					"schema": generatePropertyParquetSchema(),
				},
				Description: "Encode property data to Parquet format",
			})
		} else if format == "json" {
			additionalProcessors = append(additionalProcessors, ProcessorConfig{
				Type:        types.ProcessorJSONEncode,
				Label:       "json_encoding",
				Config:      map[string]interface{}{},
				Description: "Encode property data to JSON format",
			})
		}
	}

	allMappings := append([]ProcessorConfig{persistenceMapping}, additionalProcessors...)

	processorChain, err := buildProcessorChain(opLogger, bg, streamIDBase,
		fmt.Sprintf("Property %s persistence processors", propName),
		"property", purpose, thingID, propName, nil, bindings, allMappings...)
	if err != nil {
		return fmt.Errorf("failed to build processor chain for %s: %w", streamIDBase, err)
	}

	outputConfig, err := bg.generatePersistenceOutputConfig(thingID, propName, persistenceCfg)
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

	request, err := createStreamRequest(opLogger, bg, thingID, "properties", propName, "input",
		inputConfig, outputConfig, typedProcessorConfigs, purpose, bindings)
	if err != nil {
		return fmt.Errorf("failed to create stream request for %s: %w", streamIDBase, err)
	}

	_, err = registerStreamWithManager(opLogger, bg, request, types.StreamTypePropertyLogger, types.StreamDirectionInternal, processorChain, bindings)
	if err != nil {
		opLogger.WithError(err).WithFields(logrus.Fields{"thing_id": thingID, "property_name": propName, "stream_purpose": purpose}).Error("Failed during property logging stream generation (registering)")
		return err
	}

	opLogger.Info("Property logging stream processing complete")
	return nil
}

func generateActionInvocationStream(logger logrus.FieldLogger, bg *BindingGenerator, thingID, actionName string, action *wot.ActionAffordance, bindings *AllBindings) error {
	opLogger := logger.WithFields(logrus.Fields{"thing_id": thingID, "action_name": actionName, "operation": "generateActionInvocationStream"})
	if !bg.licenseChecker.IsFeatureAvailable("action_invocation") {
		opLogger.WithField("feature", "action_invocation").Debug("Action invocation not available in license")
		return nil
	}

	streamIDBase := fmt.Sprintf("%s_action_%s_invocation", thingID, actionName)
	purpose := "action_invocation"

	logStreamGeneration(opLogger, streamIDBase, thingID, "action", actionName, "", purpose)

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

	processorChain, err := buildProcessorChain(opLogger, bg, streamIDBase,
		fmt.Sprintf("Action %s invocation processors", actionName),
		"action", purpose, thingID, actionName, dataSchemaCore, bindings, invocationMapping, deviceActionMapping)
	if err != nil {
		return fmt.Errorf("failed to build processor chain for %s: %w", streamIDBase, err)
	}

	outputConfig, err := bg.generateActionOutputConfig(thingID, actionName, bg.licenseChecker.GetFeatureConfig("action_invocation"))
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

	request, err := createStreamRequest(opLogger, bg, thingID, "actions", actionName, "input",
		inputConfig, outputConfig, typedProcessorConfigs, purpose, bindings)
	if err != nil {
		return fmt.Errorf("failed to create stream request for %s: %w", streamIDBase, err)
	}

	_, err = registerStreamWithManager(opLogger, bg, request, types.StreamTypeActionInput, types.StreamDirectionInbound, processorChain, bindings)
	if err != nil {
		opLogger.WithError(err).WithFields(logrus.Fields{"thing_id": thingID, "action_name": actionName, "stream_purpose": purpose}).Error("Failed during action invocation stream generation (registering)")
		return err
	}

	opLogger.Info("Action invocation stream processing complete")
	return nil
}

func generateActionLoggingStream(logger logrus.FieldLogger, bg *BindingGenerator, thingID, actionName string, action *wot.ActionAffordance, bindings *AllBindings) error {
	opLogger := logger.WithFields(logrus.Fields{"thing_id": thingID, "action_name": actionName, "operation": "generateActionLoggingStream"})
	if !bg.licenseChecker.IsFeatureAvailable("data_persistence") {
		opLogger.WithField("feature", "data_persistence").Debug("Persistence feature not available in license")
		return nil
	}

	streamIDBase := fmt.Sprintf("%s_action_%s_persistence", thingID, actionName)
	topic := fmt.Sprintf("things.%s.actions.%s", thingID, actionName)
	purpose := "action_persistence"

	logStreamGeneration(opLogger, streamIDBase, thingID, "action", actionName, topic, purpose)

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
					"schema": generateActionParquetSchema(),
				},
				Description: "Encode action data to Parquet format",
			})
		} else if format == "json" {
			additionalProcessors = append(additionalProcessors, ProcessorConfig{
				Type:        types.ProcessorJSONEncode,
				Label:       "json_encoding",
				Config:      map[string]interface{}{},
				Description: "Encode action data to JSON format",
			})
		}
	}
	allMappings := append([]ProcessorConfig{persistenceMapping}, additionalProcessors...)

	processorChain, err := buildProcessorChain(opLogger, bg, streamIDBase,
		fmt.Sprintf("Action %s persistence processors", actionName),
		"action", purpose, thingID, actionName, nil, bindings, allMappings...)
	if err != nil {
		return fmt.Errorf("failed to build processor chain for %s: %w", streamIDBase, err)
	}

	outputConfig, err := bg.generateActionPersistenceOutputConfig(thingID, actionName, persistenceCfg)
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

	request, err := createStreamRequest(opLogger, bg, thingID, "actions", actionName, "input",
		inputConfig, outputConfig, typedProcessorConfigs, purpose, bindings)
	if err != nil {
		return fmt.Errorf("failed to create stream request for %s: %w", streamIDBase, err)
	}

	_, err = registerStreamWithManager(opLogger, bg, request, types.StreamTypeActionLogger, types.StreamDirectionInternal, processorChain, bindings)
	if err != nil {
		opLogger.WithError(err).WithFields(logrus.Fields{"thing_id": thingID, "action_name": actionName, "stream_purpose": purpose}).Error("Failed during action logging stream generation (registering)")
		return err
	}

	opLogger.Info("Action logging stream processing complete")
	return nil
}

func generateEventProcessingStream(logger logrus.FieldLogger, bg *BindingGenerator, thingID, eventName string, event *wot.EventAffordance, bindings *AllBindings) error {
	opLogger := logger.WithFields(logrus.Fields{"thing_id": thingID, "event_name": eventName, "operation": "generateEventProcessingStream"})
	if !bg.licenseChecker.IsFeatureAvailable("event_processing") {
		opLogger.WithField("feature", "event_processing").Debug("Event processing not available in license")
		return nil
	}

	streamIDBase := fmt.Sprintf("%s_event_%s_processing", thingID, eventName)
	topic := fmt.Sprintf("things.%s.events.%s", thingID, eventName)
	purpose := "event_processing"

	logStreamGeneration(opLogger, streamIDBase, thingID, "event", eventName, topic, purpose)

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

	processorChain, err := buildProcessorChain(opLogger, bg, streamIDBase,
		fmt.Sprintf("Event %s processing processors", eventName),
		"event", purpose, thingID, eventName, dataSchemaCore, bindings, processingMapping, enrichmentMapping)
	if err != nil {
		return fmt.Errorf("failed to build processor chain for %s: %w", streamIDBase, err)
	}

	outputConfig, err := bg.generateEventOutputConfig(thingID, eventName, bg.licenseChecker.GetFeatureConfig("event_processing"))
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

	request, err := createStreamRequest(opLogger, bg, thingID, "events", eventName, "output",
		inputConfig, outputConfig, typedProcessorConfigs, purpose, bindings)
	if err != nil {
		return fmt.Errorf("failed to create stream request for %s: %w", streamIDBase, err)
	}

	_, err = registerStreamWithManager(opLogger, bg, request, types.StreamTypeEventOutput, types.StreamDirectionOutbound, processorChain, bindings)
	if err != nil {
		opLogger.WithError(err).WithFields(logrus.Fields{"thing_id": thingID, "event_name": eventName, "stream_purpose": purpose}).Error("Failed during event processing stream generation (registering)")
		return err
	}

	opLogger.Info("Event processing stream processing complete")
	return nil
}

func generateEventLoggingStream(logger logrus.FieldLogger, bg *BindingGenerator, thingID, eventName string, event *wot.EventAffordance, bindings *AllBindings) error {
	opLogger := logger.WithFields(logrus.Fields{"thing_id": thingID, "event_name": eventName, "operation": "generateEventLoggingStream"})
	if !bg.licenseChecker.IsFeatureAvailable("data_persistence") {
		opLogger.WithField("feature", "data_persistence").Debug("Persistence feature not available in license")
		return nil
	}

	streamIDBase := fmt.Sprintf("%s_event_%s_persistence", thingID, eventName)
	topic := fmt.Sprintf("things.%s.events.%s", thingID, eventName)
	purpose := "event_persistence"

	logStreamGeneration(opLogger, streamIDBase, thingID, "event", eventName, topic, purpose)

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
					"schema": generateEventParquetSchema(),
				},
				Description: "Encode event data to Parquet format",
			})
		} else if format == "json" {
			additionalProcessors = append(additionalProcessors, ProcessorConfig{
				Type:        types.ProcessorJSONEncode,
				Label:       "json_encoding",
				Config:      map[string]interface{}{},
				Description: "Encode event data to JSON format",
			})
		}
	}
	allMappings := append([]ProcessorConfig{persistenceMapping}, additionalProcessors...)

	var dataSchemaCore *wot.DataSchemaCore
	if event.Data != nil && event.Data.Type != "" {
		dataSchemaCore = &event.Data.DataSchemaCore
	}

	processorChain, err := buildProcessorChain(opLogger, bg, streamIDBase,
		fmt.Sprintf("Event %s persistence processors", eventName),
		"event", purpose, thingID, eventName, dataSchemaCore, bindings, allMappings...)
	if err != nil {
		return fmt.Errorf("failed to build processor chain for %s: %w", streamIDBase, err)
	}

	outputConfig, err := bg.generateEventPersistenceOutputConfig(thingID, eventName, persistenceCfg)
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

	request, err := createStreamRequest(opLogger, bg, thingID, "events", eventName, "input",
		inputConfig, outputConfig, typedProcessorConfigs, purpose, bindings)
	if err != nil {
		return fmt.Errorf("failed to create stream request for %s: %w", streamIDBase, err)
	}

	_, err = registerStreamWithManager(opLogger, bg, request, types.StreamTypeEventLogger, types.StreamDirectionInternal, processorChain, bindings)
	if err != nil {
		opLogger.WithError(err).WithFields(logrus.Fields{"thing_id": thingID, "event_name": eventName, "stream_purpose": purpose}).Error("Failed during event logging stream generation (registering)")
		return err
	}

	opLogger.Info("Event logging stream processing complete")
	return nil
}

func generateStreamRequestYAML(logger logrus.FieldLogger, bg *BindingGenerator, request types.StreamCreationRequest) (string, error) {
	inputYAML, err := generateInputYAML(logger, bg, request.Input)
	if err != nil {
		return "", fmt.Errorf("failed to generate input YAML: %w", err)
	}

	processorYAML, err := generateProcessorChainYAML(logger, bg, request.ProcessorChain)
	if err != nil {
		return "", fmt.Errorf("failed to generate processor YAML: %w", err)
	}

	outputYAML, err := generateOutputYAML(logger, bg, request.Output)
	if err != nil {
		return "", fmt.Errorf("failed to generate output YAML: %w", err)
	}

	templateData := map[string]string{
		"InputYAML":     indentString(inputYAML, "  "),
		"ProcessorYAML": indentString(processorYAML, "    "),
		"OutputYAML":    indentString(outputYAML, "  "),
	}

	return executeGoTemplate("benthosMain", benthosMainTemplate, templateData)
}

func generateInputYAML(logger logrus.FieldLogger, bg *BindingGenerator, input types.StreamEndpointConfig) (string, error) {
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
			input.Type,
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

func generateProcessorChainYAML(logger logrus.FieldLogger, bg *BindingGenerator, processors []types.ProcessorConfig) (string, error) {
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
			schemaYAML, err := generateParquetSchemaYAML(logger, bg, schema)
			if err != nil {
				return "", fmt.Errorf("failed to generate parquet schema YAML: %w", err)
			}
			lines = append(lines, fmt.Sprintf(`- label: "encode_parquet"
      parquet_encode:
        schema:
%s`, indentString(schemaYAML, "          ")))

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
	return strings.Join(lines, "\n"), nil
}

func generateOutputYAML(logger logrus.FieldLogger, bg *BindingGenerator, output types.StreamEndpointConfig) (string, error) {
	switch output.Type {
	case "kafka":
		addresses := bg.kafkaConfig.Brokers
		topic := output.Config["topic"].(string)
		return fmt.Sprintf(`  kafka:
    addresses: [%s]
    topic: "%s"
    key: "${! this.thing_id }"`,
			quoteAndJoin(addresses),
			topic), nil

	case "mqtt":
		urls := []string{bg.mqttConfig.Broker}
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
			topic,
			clientID,
			qos), nil

	case "file", "parquet":
		path := output.Config["path"].(string)
		return fmt.Sprintf(`%s:
    path: "%s"
    codec: none`, output.Type, path), nil

	default:
		return "", fmt.Errorf("unsupported output type: %s", output.Type)
	}
}

func generateParquetSchemaYAML(logger logrus.FieldLogger, bg *BindingGenerator, schema []map[string]interface{}) (string, error) {
	var lines []string
	for _, field := range schema {
		lines = append(lines, fmt.Sprintf(`- name: "%s"
  type: "%s"
  converted_type: "%s"`,
			field["name"],
			field["type"],
			field["converted_type"]))
	}
	return strings.Join(lines, "\n"), nil
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

// generatePersistenceOutputConfig generates the output config for property persistence streams.
func (bg *BindingGenerator) generatePersistenceOutputConfig(thingID, propName string, persistenceCfg map[string]interface{}) (types.StreamEndpointConfig, error) {
	format, _ := persistenceCfg["format"].(string)
	switch format {
	case "parquet":
		path := fmt.Sprintf("/data/persistence/%s/properties/%s.parquet", thingID, propName)
		return types.StreamEndpointConfig{
			Type: "parquet",
			Config: map[string]interface{}{
				"path": path,
			},
		}, nil
	case "json":
		path := fmt.Sprintf("/data/persistence/%s/properties/%s.json", thingID, propName)
		return types.StreamEndpointConfig{
			Type: "file",
			Config: map[string]interface{}{
				"path": path,
			},
		}, nil
	default:
		return types.StreamEndpointConfig{}, fmt.Errorf("unsupported persistence format: %s", format)
	}
}
