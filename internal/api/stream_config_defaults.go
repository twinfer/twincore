package api

import (
	"fmt"
	"time"
)

// StreamConfigDefaults provides default configurations for stream composition
type StreamConfigDefaults struct {
	// Template configurations
	InputTemplates     map[string]StreamTemplateConfig `json:"input_templates"`
	OutputTemplates    map[string]StreamTemplateConfig `json:"output_templates"`
	ProcessorTemplates map[string]StreamTemplateConfig `json:"processor_templates"`

	// Default processor chains by interaction type
	ProcessorChains map[string][]ProcessorConfig `json:"processor_chains"`

	// Protocol preferences
	ProtocolPreferences ProtocolPreferences `json:"protocol_preferences"`

	// Timeouts and limits
	Timeouts StreamTimeouts `json:"timeouts"`

	// Parquet schema configurations
	ParquetSchemas map[string]ParquetSchemaConfig `json:"parquet_schemas"`
}

// StreamTemplateConfig contains configuration for a specific template
type StreamTemplateConfig struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Template    string                 `json:"template"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
	Enabled     bool                   `json:"enabled"`
}

// ProtocolPreferences defines protocol selection preferences
type ProtocolPreferences struct {
	Default      string   `json:"default"`
	Ordered      []string `json:"ordered"`
	Fallback     string   `json:"fallback"`
	DisallowHTTP bool     `json:"disallow_http,omitempty"`
}

// StreamTimeouts defines various timeout configurations
type StreamTimeouts struct {
	ActionTimeout     time.Duration `json:"action_timeout"`
	EventTimeout      time.Duration `json:"event_timeout"`
	ConnectionTimeout time.Duration `json:"connection_timeout"`
	PropertyCacheTTL  time.Duration `json:"property_cache_ttl"`
}

// ParquetSchemaConfig defines Parquet schema configuration for different interaction types
type ParquetSchemaConfig struct {
	Name         string               `json:"name"`
	Schema       []ParquetFieldSchema `json:"schema"`
	Compression  string               `json:"compression,omitempty"`
	RowGroupSize int                  `json:"row_group_size,omitempty"`
}

// ParquetFieldSchema defines a single field in a Parquet schema
type ParquetFieldSchema struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	ConvertedType string `json:"converted_type,omitempty"`
	LogicalType   string `json:"logical_type,omitempty"`
	Repetition    string `json:"repetition,omitempty"`
}

// GetDefaultStreamConfigDefaults returns comprehensive default configurations
func GetDefaultStreamConfigDefaults() StreamConfigDefaults {
	return StreamConfigDefaults{
		InputTemplates: map[string]StreamTemplateConfig{
			"kafka": {
				Name:        "kafka",
				Description: "Kafka input for WoT interactions",
				Template:    "input-kafka",
				Enabled:     true,
				Parameters: map[string]interface{}{
					"auto_replay_nacks": true,
					"start_from_oldest": false,
				},
			},
			"mqtt": {
				Name:        "mqtt",
				Description: "MQTT input for WoT interactions",
				Template:    "input-mqtt",
				Enabled:     true,
				Parameters: map[string]interface{}{
					"qos":           1,
					"clean_session": false,
				},
			},
			"http": {
				Name:        "http",
				Description: "HTTP server input for WoT interactions",
				Template:    "input-http",
				Enabled:     true,
				Parameters: map[string]interface{}{
					"timeout":       "30s",
					"allowed_verbs": []string{"POST", "PUT", "GET"},
				},
			},
		},

		OutputTemplates: map[string]StreamTemplateConfig{
			"kafka": {
				Name:        "kafka",
				Description: "Kafka output for WoT interactions",
				Template:    "output-kafka",
				Enabled:     true,
				Parameters: map[string]interface{}{
					"key":           "${! this.thing_id }",
					"partition_by":  "thing_id",
					"max_in_flight": 1,
				},
			},
			"mqtt": {
				Name:        "mqtt",
				Description: "MQTT output for WoT interactions",
				Template:    "output-mqtt",
				Enabled:     true,
				Parameters: map[string]interface{}{
					"qos":    1,
					"retain": false,
				},
			},
			"parquet": {
				Name:        "parquet",
				Description: "Parquet file output for WoT data logging",
				Template:    "output-parquet",
				Enabled:     true,
				Parameters: map[string]interface{}{
					"codec":          "none",
					"compression":    "SNAPPY",
					"row_group_size": 100000,
				},
			},
		},

		ProcessorTemplates: map[string]StreamTemplateConfig{
			"wot_property": {
				Name:        "wot_property",
				Description: "WoT property formatting processor",
				Template:    "bloblang-wot-property",
				Enabled:     true,
			},
			"wot_action": {
				Name:        "wot_action",
				Description: "WoT action formatting processor",
				Template:    "bloblang-wot-action",
				Enabled:     true,
			},
			"wot_event": {
				Name:        "wot_event",
				Description: "WoT event formatting processor",
				Template:    "bloblang-wot-event",
				Enabled:     true,
			},
			"json_validator": {
				Name:        "json_validator",
				Description: "JSON schema validation processor",
				Template:    "json-schema-validator",
				Enabled:     true,
				Parameters: map[string]interface{}{
					"failure_action": "log",
				},
			},
			"parquet_encoder": {
				Name:        "parquet_encoder",
				Description: "Parquet encoding processor",
				Template:    "parquet-encoder",
				Enabled:     true,
				Parameters: map[string]interface{}{
					"compression_codec": "SNAPPY",
					"row_group_size":    50000,
				},
			},
		},

		ProcessorChains: map[string][]ProcessorConfig{
			"properties": {
				{
					Type: "bloblang_wot_property",
					Config: map[string]interface{}{
						"include_metadata": true,
						"validate_schema":  true,
					},
				},
				{
					Type: "json_schema",
					Config: map[string]interface{}{
						"schema": "wot_property_schema",
					},
				},
				{
					Type: "parquet_encode",
					Config: map[string]interface{}{
						"schema": "wot_property",
					},
				},
			},
			"actions": {
				{
					Type: "bloblang_wot_action",
					Config: map[string]interface{}{
						"include_tracing": true,
						"timeout_default": "30s",
					},
				},
				{
					Type: "json_schema",
					Config: map[string]interface{}{
						"schema": "wot_action_schema",
					},
				},
				{
					Type: "parquet_encode",
					Config: map[string]interface{}{
						"schema": "wot_action",
					},
				},
			},
			"events": {
				{
					Type: "bloblang_wot_event",
					Config: map[string]interface{}{
						"include_tracing":     true,
						"include_sequencing":  true,
						"include_aggregation": false,
					},
				},
				{
					Type: "json_schema",
					Config: map[string]interface{}{
						"schema": "wot_event_schema",
					},
				},
				{
					Type: "parquet_encode",
					Config: map[string]interface{}{
						"schema": "wot_event",
					},
				},
			},
		},

		ProtocolPreferences: ProtocolPreferences{
			Default:  "kafka",
			Ordered:  []string{"kafka", "mqtt", "http"},
			Fallback: "kafka",
		},

		Timeouts: StreamTimeouts{
			ActionTimeout:     30 * time.Second,
			EventTimeout:      5 * time.Second,
			ConnectionTimeout: 10 * time.Second,
			PropertyCacheTTL:  60 * time.Second,
		},

		ParquetSchemas: map[string]ParquetSchemaConfig{
			"wot_property": {
				Name: "wot_property",
				Schema: []ParquetFieldSchema{
					{Name: "thing_id", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
					{Name: "property_name", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
					{Name: "value", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
					{Name: "timestamp", Type: "INT64"},
					{Name: "source", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
					{Name: "data_type", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
					{Name: "context", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
				},
				Compression:  "SNAPPY",
				RowGroupSize: 100000,
			},
			"wot_action": {
				Name: "wot_action",
				Schema: []ParquetFieldSchema{
					{Name: "thing_id", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
					{Name: "action_name", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
					{Name: "action_id", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
					{Name: "input", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
					{Name: "output", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
					{Name: "invoked_at", Type: "INT64"},
					{Name: "completed_at", Type: "INT64"},
					{Name: "status", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
					{Name: "source", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
					{Name: "trace_id", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
					{Name: "context", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
				},
				Compression:  "SNAPPY",
				RowGroupSize: 50000,
			},
			"wot_event": {
				Name: "wot_event",
				Schema: []ParquetFieldSchema{
					{Name: "thing_id", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
					{Name: "event_name", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
					{Name: "data", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
					{Name: "timestamp", Type: "INT64"},
					{Name: "severity", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
					{Name: "category", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
					{Name: "source", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
					{Name: "trace_id", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
					{Name: "sequence_number", Type: "INT64"},
					{Name: "partition_key", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
					{Name: "context", Type: "BYTE_ARRAY", ConvertedType: "UTF8"},
				},
				Compression:  "SNAPPY",
				RowGroupSize: 200000,
			},
		},
	}
}

// GetStreamCompositionConfigFromDefaults creates a StreamCompositionConfig from defaults
func GetStreamCompositionConfigFromDefaults(defaults StreamConfigDefaults, overrides map[string]interface{}) StreamCompositionConfig {
	config := StreamCompositionConfig{
		CreatePropertyStreams:  true,
		CreateActionStreams:    true,
		CreateEventStreams:     true,
		DefaultInputTemplate:   "input-kafka",
		DefaultOutputTemplate:  "output-parquet",
		DefaultProcessorChains: make(map[string][]ProcessorConfig),
		KafkaBrokers:           []string{"localhost:9092"},
		DefaultConsumerGroup:   "twincore-default",
		TopicPrefix:            "things",
		PreferredProtocols:     defaults.ProtocolPreferences.Ordered,
		EnableBidirectional:    true,
		RequiredFeatures: map[string]string{
			"properties": "property_processing",
			"actions":    "action_processing",
			"events":     "event_processing",
		},
		ParquetLogPath: "./logs",
		EnableMetrics:  true,
	}

	// Copy processor chains from defaults
	for interactionType, chain := range defaults.ProcessorChains {
		config.DefaultProcessorChains[interactionType] = make([]ProcessorConfig, len(chain))
		copy(config.DefaultProcessorChains[interactionType], chain)
	}

	// Apply overrides
	if overrides != nil {
		if kafkaBrokers, ok := overrides["kafka_brokers"].([]string); ok {
			config.KafkaBrokers = kafkaBrokers
		}
		if consumerGroup, ok := overrides["consumer_group"].(string); ok {
			config.DefaultConsumerGroup = consumerGroup
		}
		if topicPrefix, ok := overrides["topic_prefix"].(string); ok {
			config.TopicPrefix = topicPrefix
		}
		if parquetPath, ok := overrides["parquet_log_path"].(string); ok {
			config.ParquetLogPath = parquetPath
		}
		if enableMetrics, ok := overrides["enable_metrics"].(bool); ok {
			config.EnableMetrics = enableMetrics
		}
	}

	return config
}

// StreamConfigValidator validates stream configuration
type StreamConfigValidator struct {
	defaults StreamConfigDefaults
}

// NewStreamConfigValidator creates a new validator
func NewStreamConfigValidator(defaults StreamConfigDefaults) *StreamConfigValidator {
	return &StreamConfigValidator{defaults: defaults}
}

// ValidateTemplate validates a template configuration
func (v *StreamConfigValidator) ValidateTemplate(templateType, templateName string, config StreamTemplateConfig) error {
	if !config.Enabled {
		return nil // Skip validation for disabled templates
	}

	if config.Template == "" {
		return fmt.Errorf("template is required for %s template %s", templateType, templateName)
	}

	// Validate template exists in defaults
	var found bool
	switch templateType {
	case "input":
		_, found = v.defaults.InputTemplates[templateName]
	case "output":
		_, found = v.defaults.OutputTemplates[templateName]
	case "processor":
		_, found = v.defaults.ProcessorTemplates[templateName]
	}

	if !found {
		return fmt.Errorf("unknown %s template: %s", templateType, templateName)
	}

	return nil
}

// ValidateProcessorChain validates a processor chain configuration
func (v *StreamConfigValidator) ValidateProcessorChain(interactionType string, chain []ProcessorConfig) error {
	if len(chain) == 0 {
		return fmt.Errorf("processor chain for %s cannot be empty", interactionType)
	}

	for i, processor := range chain {
		if processor.Type == "" {
			return fmt.Errorf("processor %d in %s chain has empty type", i, interactionType)
		}

		// Check if processor type exists in templates
		if _, exists := v.defaults.ProcessorTemplates[processor.Type]; !exists {
			return fmt.Errorf("unknown processor type: %s in %s chain", processor.Type, interactionType)
		}
	}

	return nil
}

// ValidateConfig validates the complete stream composition configuration
func (v *StreamConfigValidator) ValidateConfig(config StreamCompositionConfig) error {
	// Validate basic requirements
	if err := ValidateStreamCompositionConfig(config); err != nil {
		return err
	}

	// Validate processor chains
	for interactionType, chain := range config.DefaultProcessorChains {
		if err := v.ValidateProcessorChain(interactionType, chain); err != nil {
			return fmt.Errorf("invalid processor chain for %s: %w", interactionType, err)
		}
	}

	// Validate preferred protocols
	validProtocols := map[string]bool{"kafka": true, "mqtt": true, "http": true}
	for _, protocol := range config.PreferredProtocols {
		if !validProtocols[protocol] {
			return fmt.Errorf("invalid preferred protocol: %s", protocol)
		}
	}

	return nil
}
