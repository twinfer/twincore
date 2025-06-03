package forms

import (
	"fmt"
	"strings"

	// "github.com/benthosdev/benthos/v4/public/bloblang"
	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/types"
)

// StreamConfigBuilder provides a unified interface for building stream configurations
type StreamConfigBuilder struct {
	logger           logrus.FieldLogger
	templateExecutor *TemplateExecutor
	outputFactory    *OutputConfigFactory
	mappingEngine    *MappingEngine
	schemaRegistry   *SchemaRegistry
}

// NewStreamConfigBuilder creates a new stream configuration builder
func NewStreamConfigBuilder(logger logrus.FieldLogger) *StreamConfigBuilder {
	return &StreamConfigBuilder{
		logger:           logger,
		templateExecutor: NewTemplateExecutor(),
		outputFactory:    NewOutputConfigFactory(),
		mappingEngine:    NewMappingEngine(),
		schemaRegistry:   NewSchemaRegistry(),
	}
}

// StreamBuildConfig contains all parameters needed to build a stream
type StreamBuildConfig struct {
	ThingID         string
	InteractionType string // "property", "action", "event"
	InteractionName string
	Purpose         StreamPurpose
	Direction       StreamDirection
	StreamType      types.BenthosStreamType
	InputConfig     StreamEndpointParams
	OutputConfig    StreamEndpointParams
	Processors      []ProcessorConfig
	Metadata        map[string]interface{}
}

// StreamPurpose defines the purpose of a stream
type StreamPurpose string

const (
	PurposeObservation  StreamPurpose = "observation"
	PurposeCommand      StreamPurpose = "command"
	PurposePersistence  StreamPurpose = "persistence"
	PurposeNotification StreamPurpose = "notification"
	PurposeInternal     StreamPurpose = "internal"
)

// StreamDirection defines the direction of data flow
type StreamDirection string

const (
	DirectionInput    StreamDirection = "input"
	DirectionOutput   StreamDirection = "output"
	DirectionInternal StreamDirection = "internal"
)

// StreamEndpointParams contains parameters for stream endpoints
type StreamEndpointParams struct {
	Type       string                 // "http", "mqtt", "kafka", "file", "s3", etc.
	Protocol   string                 // Protocol-specific type
	Config     map[string]interface{} // Protocol-specific configuration
	FormConfig FormConfiguration      // Form-specific config (href, security, etc.)
}

// ProcessorConfig defines a processor in the pipeline
type ProcessorConfig struct {
	Type       string                 // "mapping", "filter", "throttle", etc.
	Label      string                 // Processor label
	Parameters map[string]interface{} // Processor-specific parameters
}

// FormConfiguration contains WoT form-specific configuration
type FormConfiguration struct {
	Href         string
	Security     []string
	SecurityDefs map[string]interface{}
	ContentType  string
	Method       string // For HTTP
	Topic        string // For MQTT/Kafka
	QoS          int    // For MQTT
}

// BuildStream creates a complete stream configuration
func (b *StreamConfigBuilder) BuildStream(config StreamBuildConfig) (*types.StreamCreationRequest, error) {
	// Generate stream ID
	// streamID := b.generateStreamID(config)

	// Build processor chain
	processors, err := b.buildProcessors(config)
	if err != nil {
		return nil, fmt.Errorf("failed to build processors: %w", err)
	}

	// Build input configuration
	inputConfig, err := b.buildEndpointConfig(config.InputConfig, true)
	if err != nil {
		return nil, fmt.Errorf("failed to build input config: %w", err)
	}

	// Build output configuration
	outputConfig, err := b.buildEndpointConfig(config.OutputConfig, false)
	if err != nil {
		return nil, fmt.Errorf("failed to build output config: %w", err)
	}

	// Create stream request
	request := &types.StreamCreationRequest{
		ThingID:         config.ThingID,
		InteractionType: config.InteractionType,
		InteractionName: config.InteractionName,
		Direction:       string(config.Direction),
		ProcessorChain:  b.convertProcessorChain(processors),
		Input:           inputConfig,
		Output:          outputConfig,
		Metadata:        b.buildMetadata(config),
	}

	return request, nil
}

// generateStreamID creates a unique stream identifier
func (b *StreamConfigBuilder) generateStreamID(config StreamBuildConfig) string {
	parts := []string{
		config.ThingID,
		config.InteractionType,
		config.InteractionName,
		string(config.Purpose),
	}
	return strings.Join(parts, "_")
}

// buildProcessors creates the processor chain
func (b *StreamConfigBuilder) buildProcessors(config StreamBuildConfig) (types.ProcessorChain, error) {
	var processors []types.ProcessorConfigItem

	for _, pc := range config.Processors {
		switch pc.Type {
		case "mapping":
			mapping, err := b.mappingEngine.GenerateMapping(MappingConfig{
				Type:            config.InteractionType,
				Purpose:         string(config.Purpose),
				ThingID:         config.ThingID,
				InteractionName: config.InteractionName,
				Parameters:      pc.Parameters,
			})
			if err != nil {
				return types.ProcessorChain{}, fmt.Errorf("failed to generate mapping: %w", err)
			}

			// Validate the mapping
			if err := b.validateMapping(mapping); err != nil {
				return types.ProcessorChain{}, fmt.Errorf("invalid mapping: %w", err)
			}

			processors = append(processors, types.ProcessorConfigItem{
				Label: pc.Label,
				Type:  types.BenthosProcessorType("bloblang"),
				Config: map[string]interface{}{
					"bloblang": mapping,
				},
			})

		case "filter":
			processors = append(processors, types.ProcessorConfigItem{
				Label:  pc.Label,
				Type:   "filter",
				Config: pc.Parameters,
			})

		case "throttle":
			processors = append(processors, types.ProcessorConfigItem{
				Label:  pc.Label,
				Type:   "throttle",
				Config: pc.Parameters,
			})

		default:
			// Pass through custom processors
			processors = append(processors, types.ProcessorConfigItem{
				Label:  pc.Label,
				Type:   types.BenthosProcessorType(pc.Type),
				Config: pc.Parameters,
			})
		}
	}

	return types.ProcessorChain{
		Processors: processors,
	}, nil
}

// buildEndpointConfig creates input or output configuration
func (b *StreamConfigBuilder) buildEndpointConfig(params StreamEndpointParams, isInput bool) (types.StreamEndpointConfig, error) {
	var config types.StreamEndpointConfig

	switch params.Type {
	case "http":
		if isInput {
			config = b.buildHTTPInputConfig(params)
		} else {
			config = b.buildHTTPOutputConfig(params)
		}
	case "mqtt":
		if isInput {
			config = b.buildMQTTInputConfig(params)
		} else {
			config = b.buildMQTTOutputConfig(params)
		}
	case "kafka":
		if isInput {
			config = b.buildKafkaInputConfig(params)
		} else {
			config = b.buildKafkaOutputConfig(params)
		}
	case "file", "s3", "parquet":
		// Use output factory for persistence outputs
		return b.outputFactory.Generate(params.Type, params)
	case "stream_bridge", "internal":
		// Internal streams (e.g., stream_bridge)
		config = types.StreamEndpointConfig{
			Type:   params.Type,
			Config: params.Config,
		}
	default:
		return types.StreamEndpointConfig{}, fmt.Errorf("unsupported endpoint type: %s", params.Type)
	}

	return config, nil
}

// buildHTTPInputConfig creates HTTP input configuration
func (b *StreamConfigBuilder) buildHTTPInputConfig(params StreamEndpointParams) types.StreamEndpointConfig {
	config := map[string]interface{}{
		"address": ":0", // Dynamic port allocation
		"path":    params.FormConfig.Href,
	}

	if params.FormConfig.Method != "" {
		config["verb"] = params.FormConfig.Method
	}

	// Merge custom config
	for k, v := range params.Config {
		config[k] = v
	}

	return types.StreamEndpointConfig{
		Type:   "http_server",
		Config: config,
	}
}

// buildHTTPOutputConfig creates HTTP output configuration
func (b *StreamConfigBuilder) buildHTTPOutputConfig(params StreamEndpointParams) types.StreamEndpointConfig {
	config := map[string]interface{}{
		"url":  params.FormConfig.Href,
		"verb": params.FormConfig.Method,
		"headers": map[string]string{
			"Content-Type": params.FormConfig.ContentType,
		},
	}

	// Apply security configuration if available
	if len(params.FormConfig.Security) > 0 && params.FormConfig.SecurityDefs != nil {
		// TODO: Apply security configuration based on security definitions
	}

	// Merge custom config
	for k, v := range params.Config {
		config[k] = v
	}

	return types.StreamEndpointConfig{
		Type:   "http_client",
		Config: config,
	}
}

// buildMQTTInputConfig creates MQTT input configuration
func (b *StreamConfigBuilder) buildMQTTInputConfig(params StreamEndpointParams) types.StreamEndpointConfig {
	config := map[string]interface{}{
		"urls":   []string{params.FormConfig.Href},
		"topics": []string{params.FormConfig.Topic},
		"qos":    params.FormConfig.QoS,
	}

	// Merge custom config
	for k, v := range params.Config {
		config[k] = v
	}

	return types.StreamEndpointConfig{
		Type:   "mqtt",
		Config: config,
	}
}

// buildMQTTOutputConfig creates MQTT output configuration
func (b *StreamConfigBuilder) buildMQTTOutputConfig(params StreamEndpointParams) types.StreamEndpointConfig {
	config := map[string]interface{}{
		"urls":  []string{params.FormConfig.Href},
		"topic": params.FormConfig.Topic,
		"qos":   params.FormConfig.QoS,
	}

	// Merge custom config
	for k, v := range params.Config {
		config[k] = v
	}

	return types.StreamEndpointConfig{
		Type:   "mqtt",
		Config: config,
	}
}

// buildKafkaInputConfig creates Kafka input configuration
func (b *StreamConfigBuilder) buildKafkaInputConfig(params StreamEndpointParams) types.StreamEndpointConfig {
	config := map[string]interface{}{
		"addresses": []string{params.FormConfig.Href},
		"topics":    []string{params.FormConfig.Topic},
	}

	// Merge custom config
	for k, v := range params.Config {
		config[k] = v
	}

	return types.StreamEndpointConfig{
		Type:   "kafka",
		Config: config,
	}
}

// buildKafkaOutputConfig creates Kafka output configuration
func (b *StreamConfigBuilder) buildKafkaOutputConfig(params StreamEndpointParams) types.StreamEndpointConfig {
	config := map[string]interface{}{
		"addresses": []string{params.FormConfig.Href},
		"topic":     params.FormConfig.Topic,
	}

	// Merge custom config
	for k, v := range params.Config {
		config[k] = v
	}

	return types.StreamEndpointConfig{
		Type:   "kafka",
		Config: config,
	}
}

// buildMetadata creates stream metadata
func (b *StreamConfigBuilder) buildMetadata(config StreamBuildConfig) map[string]interface{} {
	metadata := map[string]interface{}{
		"thing_id":         config.ThingID,
		"interaction_type": config.InteractionType,
		"interaction_name": config.InteractionName,
		"purpose":          string(config.Purpose),
		"direction":        string(config.Direction),
	}

	// Merge custom metadata
	for k, v := range config.Metadata {
		metadata[k] = v
	}

	return metadata
}

// validateMapping checks if a Bloblang mapping is valid
func (b *StreamConfigBuilder) validateMapping(mapping string) error {
	// TODO: Use Benthos bloblang parser to validate when available
	// _, err := bloblang.Parse(mapping)
	// return err
	return nil
}

// convertProcessorChain converts internal processor chain to types.ProcessorConfig format
func (b *StreamConfigBuilder) convertProcessorChain(chain types.ProcessorChain) []types.ProcessorConfig {
	processors := make([]types.ProcessorConfig, 0, len(chain.Processors))

	for _, p := range chain.Processors {
		processors = append(processors, types.ProcessorConfig{
			Type:   string(p.Type),
			Config: p.Config,
		})
	}

	return processors
}
