package api

import (
	"fmt"
	"strings"

	"github.com/redpanda-data/benthos/v4/public/service"
	"github.com/sirupsen/logrus"
)

// StreamConfigFactory provides typed wrapper functions for Benthos stream configurations
type StreamConfigFactory struct {
	logger logrus.FieldLogger
}

// NewStreamConfigFactory creates a new stream config factory
func NewStreamConfigFactory(logger logrus.FieldLogger) *StreamConfigFactory {
	return &StreamConfigFactory{
		logger: logger,
	}
}

// Property stream processors

// NewPropertyLoggerStream creates a stream for property state logging to Parquet
func (f *StreamConfigFactory) NewPropertyLoggerStream(parquetPath string) (*service.StreamBuilder, error) {
	builder := service.NewStreamBuilder()

	// Create complete YAML configuration
	yamlConfig := fmt.Sprintf(`
input:
  kafka:
    addresses: ["${KAFKA_BROKERS:localhost:9092}"]
    topics: ["things.*.properties.*"]
    consumer_group: "twincore-property-logger"

pipeline:
  processors:
    - label: "license_check"
      branch:
        if: 'meta("license_feature") == "parquet_logging"'
        processors:
          - log:
              level: "DEBUG"
              message: "Property logging authorized"

    - label: "format_property_record"
      mapping: |
        root.thing_id = this.thing_id
        root.property_name = this.property_name  
        root.value = this.value
        root.timestamp = timestamp_unix_nano()
        root.source = this.source.or("stream")

    - label: "validate_schema"
      json_schema:
        schema:
          type: object
          required: ["thing_id", "property_name", "value", "timestamp"]
          properties:
            thing_id: {type: string}
            property_name: {type: string}
            value: {}
            timestamp: {type: integer}
            source: {type: string}

    - label: "encode_parquet"
      parquet_encode:
        schema:
          - name: "thing_id"
            type: "BYTE_ARRAY"
            converted_type: "UTF8"
          - name: "property_name"
            type: "BYTE_ARRAY"
            converted_type: "UTF8"
          - name: "value"
            type: "BYTE_ARRAY"
            converted_type: "UTF8"
          - name: "timestamp"
            type: "INT64"
          - name: "source"
            type: "BYTE_ARRAY"
            converted_type: "UTF8"

output:
  file:
    path: "%s/properties/props_${!timestamp_unix():yyyy-MM-dd}.parquet"
    codec: none
`, parquetPath)

	if err := builder.SetYAML(yamlConfig); err != nil {
		return nil, fmt.Errorf("failed to set YAML config: %w", err)
	}

	f.logger.Debug("Created property logger stream configuration")
	return builder, nil
}

// NewActionTrackerStream creates a stream for action invocation tracking
func (f *StreamConfigFactory) NewActionTrackerStream(parquetPath string) (*service.StreamBuilder, error) {
	builder := service.NewStreamBuilder()

	yamlConfig := fmt.Sprintf(`
input:
  kafka:
    addresses: ["${KAFKA_BROKERS:localhost:9092}"]
    topics: ["things.*.actions.*"]
    consumer_group: "twincore-action-tracker"

pipeline:
  processors:
    - label: "license_check"
      branch:
        if: 'meta("license_feature") == "action_tracking"'

    - label: "action_enrichment"
      mapping: |
        root = this
        root.action_id = uuid_v4()
        root.invoked_at = timestamp_unix_nano()
        root.timeout = this.timeout.or("30s")

    - label: "encode_parquet"
      parquet_encode:
        schema:
          - name: "thing_id"
            type: "BYTE_ARRAY"
            converted_type: "UTF8"
          - name: "action_name"
            type: "BYTE_ARRAY"
            converted_type: "UTF8"
          - name: "action_id"
            type: "BYTE_ARRAY"
            converted_type: "UTF8"
          - name: "input"
            type: "BYTE_ARRAY"
            converted_type: "UTF8"
          - name: "invoked_at"
            type: "INT64"
          - name: "timeout"
            type: "BYTE_ARRAY"
            converted_type: "UTF8"

output:
  file:
    path: "%s/actions/actions_${!timestamp_unix():yyyy-MM-dd}.parquet"
`, parquetPath)

	if err := builder.SetYAML(yamlConfig); err != nil {
		return nil, fmt.Errorf("failed to set YAML config: %w", err)
	}

	f.logger.Debug("Created action tracker stream configuration")
	return builder, nil
}

// NewEventProcessorStream creates a stream for device event processing
func (f *StreamConfigFactory) NewEventProcessorStream(parquetPath string) (*service.StreamBuilder, error) {
	builder := service.NewStreamBuilder()

	yamlConfig := fmt.Sprintf(`
input:
  kafka:
    addresses: ["${KAFKA_BROKERS:localhost:9092}"]
    topics: ["things.*.events.*"]
    consumer_group: "twincore-event-processor"

pipeline:
  processors:
    - label: "license_check"
      branch:
        if: 'meta("license_feature") == "event_processing"'

    - label: "event_enrichment"
      mapping: |
        root = this
        root.processed_at = timestamp_unix_nano()
        root.event_type = this.event_name
        root.severity = this.data.severity.or("info")

    - label: "event_filtering"
      branch:
        if: 'this.severity != "debug"'

output:
  file:
    path: "%s/events/events_${!timestamp_unix():yyyy-MM-dd}.parquet"
`, parquetPath)

	if err := builder.SetYAML(yamlConfig); err != nil {
		return nil, fmt.Errorf("failed to set YAML config: %w", err)
	}

	f.logger.Debug("Created event processor stream configuration")
	return builder, nil
}

// NewHTTPToKafkaStream creates a stream that bridges HTTP requests to Kafka topics
func (f *StreamConfigFactory) NewHTTPToKafkaStream(httpPath, kafkaTopic string) (*service.StreamBuilder, error) {
	builder := service.NewStreamBuilder()

	yamlConfig := fmt.Sprintf(`
input:
  http_server:
    path: "%s"
    allowed_verbs: ["POST", "PUT"]

pipeline:
  processors:
    - label: "request_validation"
      json_schema:
        schema:
          type: object
          required: ["thing_id"]

    - label: "add_metadata"
      mapping: |
        root = this
        root.received_at = timestamp_unix_nano()
        root.source = "http"
        root.request_id = uuid_v4()

output:
  kafka:
    addresses: ["${KAFKA_BROKERS:localhost:9092}"]
    topic: "%s"
    key: "${! this.thing_id }"
`, httpPath, kafkaTopic)

	if err := builder.SetYAML(yamlConfig); err != nil {
		return nil, fmt.Errorf("failed to set YAML config: %w", err)
	}

	f.logger.Debug("Created HTTP to Kafka bridge stream configuration")
	return builder, nil
}

// Factory methods for processor collections

// ProcessorCollectionFactory manages reusable processor collections
type ProcessorCollectionFactory struct {
	collections map[string]ProcessorCollection
	logger      logrus.FieldLogger
}

// ProcessorDefinition defines a single processor configuration
type ProcessorDefinition struct {
	Type        string                 `json:"type"`
	Label       string                 `json:"label"`
	Config      map[string]interface{} `json:"config"`
	Description string                 `json:"description,omitempty"`
}

// NewProcessorCollectionFactory creates a new processor collection factory
func NewProcessorCollectionFactory(logger logrus.FieldLogger) *ProcessorCollectionFactory {
	factory := &ProcessorCollectionFactory{
		collections: make(map[string]ProcessorCollection),
		logger:      logger,
	}

	// Pre-populate with standard collections
	factory.initializeStandardCollections()

	return factory
}

// initializeStandardCollections creates the built-in processor collections
func (f *ProcessorCollectionFactory) initializeStandardCollections() {
	// License checking collection
	f.collections["license-validation"] = ProcessorCollection{
		ID:          "license-validation",
		Name:        "License Validation Processors",
		Description: "Standard processors for validating license features",
		Processors: []ProcessorConfig{
			{
				Type: "license_check",
				Config: map[string]interface{}{
					"feature": "${! meta(\"required_feature\") }",
				},
			},
			{
				Type: "branch",
				Config: map[string]interface{}{
					"if": "meta(\"license_valid\") == true",
					"processors": []map[string]interface{}{
						{
							"log": map[string]interface{}{
								"level":   "DEBUG",
								"message": "License validation passed",
							},
						},
					},
				},
			},
		},
		Metadata: map[string]interface{}{
			"category": "security",
			"version":  "1.0",
		},
	}

	// Data validation collection
	f.collections["wot-validation"] = ProcessorCollection{
		ID:          "wot-validation",
		Name:        "WoT Schema Validation Processors",
		Description: "Processors for validating WoT Thing Description schemas",
		Processors: []ProcessorConfig{
			{
				Type: "json_schema",
				Config: map[string]interface{}{
					"schema_path": "/schemas/wot/property-schema.json",
				},
			},
			{
				Type: "json_schema",
				Config: map[string]interface{}{
					"schema_path": "/schemas/wot/action-schema.json",
				},
			},
			{
				Type: "mapping",
				Config: map[string]interface{}{
					"mapping": `
root = this
root.@context = "https://www.w3.org/2019/wot/td/v1"
root.normalized_at = timestamp_unix_nano()
`,
				},
			},
		},
		Metadata: map[string]interface{}{
			"category": "validation",
			"version":  "1.1",
		},
	}

	// Parquet encoding collection
	f.collections["parquet-encoding"] = ProcessorCollection{
		ID:          "parquet-encoding",
		Name:        "Parquet Encoding Processors",
		Description: "Processors for encoding data to Parquet format",
		Processors: []ProcessorConfig{
			{
				Type: "mapping",
				Config: map[string]interface{}{
					"mapping": `
root.thing_id = this.thing_id.string()
root.timestamp = this.timestamp.number()
root.data = this.data.string()
root.source = this.source.or("unknown").string()
`,
				},
			},
			{
				Type: "parquet_encode",
				Config: map[string]interface{}{
					"schema": []map[string]interface{}{
						{"name": "thing_id", "type": "BYTE_ARRAY", "converted_type": "UTF8"},
						{"name": "timestamp", "type": "INT64"},
						{"name": "data", "type": "BYTE_ARRAY", "converted_type": "UTF8"},
						{"name": "source", "type": "BYTE_ARRAY", "converted_type": "UTF8"},
					},
				},
			},
		},
		Metadata: map[string]interface{}{
			"category": "encoding",
			"version":  "1.0",
		},
	}
}

// GetCollection retrieves a processor collection by ID
func (f *ProcessorCollectionFactory) GetCollection(id string) (ProcessorCollection, bool) {
	collection, exists := f.collections[id]
	return collection, exists
}

// ListCollections returns all available processor collections
func (f *ProcessorCollectionFactory) ListCollections() []ProcessorCollection {
	var collections []ProcessorCollection
	for _, collection := range f.collections {
		collections = append(collections, collection)
	}
	return collections
}

// RegisterCollection adds a new processor collection
func (f *ProcessorCollectionFactory) RegisterCollection(collection ProcessorCollection) error {
	if collection.ID == "" {
		return fmt.Errorf("processor collection ID cannot be empty")
	}

	f.collections[collection.ID] = collection
	f.logger.WithField("collection_id", collection.ID).Info("Registered processor collection")

	return nil
}

// GenerateStreamWithCollections creates a stream config using processor collections
func (f *ProcessorCollectionFactory) GenerateStreamWithCollections(
	streamName string,
	collectionIDs []string,
	input map[string]interface{},
	output map[string]interface{},
) (*service.StreamBuilder, error) {
	builder := service.NewStreamBuilder()

	// Build YAML configuration
	var yamlParts []string

	// Input section
	inputType := ""
	inputConfig := make(map[string]interface{})
	for k, v := range input {
		if k == "type" {
			inputType = v.(string)
		} else {
			inputConfig[k] = v
		}
	}

	if inputType == "" {
		return nil, fmt.Errorf("input type not specified")
	}

	yamlParts = append(yamlParts, "input:")
	yamlParts = append(yamlParts, fmt.Sprintf("  %s:", inputType))
	for k, v := range inputConfig {
		yamlParts = append(yamlParts, fmt.Sprintf("    %s: %v", k, v))
	}

	// Processor pipeline from collections
	yamlParts = append(yamlParts, "pipeline:")
	yamlParts = append(yamlParts, "  processors:")

	for _, collectionID := range collectionIDs {
		collection, exists := f.GetCollection(collectionID)
		if !exists {
			return nil, fmt.Errorf("processor collection not found: %s", collectionID)
		}

		// Add collection processors to pipeline
		for _, proc := range collection.Processors {
			yamlParts = append(yamlParts, fmt.Sprintf("    - label: \"%s_%s\"", collectionID, proc.Type))
			yamlParts = append(yamlParts, fmt.Sprintf("      %s:", proc.Type))
			// Add processor config (simplified for this example)
			for k, v := range proc.Config {
				yamlParts = append(yamlParts, fmt.Sprintf("        %s: %v", k, v))
			}
		}
	}

	// Output section
	outputType := ""
	outputConfig := make(map[string]interface{})
	for k, v := range output {
		if k == "type" {
			outputType = v.(string)
		} else {
			outputConfig[k] = v
		}
	}

	if outputType == "" {
		return nil, fmt.Errorf("output type not specified")
	}

	yamlParts = append(yamlParts, "output:")
	yamlParts = append(yamlParts, fmt.Sprintf("  %s:", outputType))
	for k, v := range outputConfig {
		yamlParts = append(yamlParts, fmt.Sprintf("    %s: %v", k, v))
	}

	yamlConfig := strings.Join(yamlParts, "\n")

	if err := builder.SetYAML(yamlConfig); err != nil {
		return nil, fmt.Errorf("failed to set YAML config: %w", err)
	}

	f.logger.WithFields(logrus.Fields{
		"stream_name":     streamName,
		"collections":     strings.Join(collectionIDs, ", "),
		"processor_count": len(collectionIDs),
	}).Info("Generated stream config with processor collections")

	return builder, nil
}

// Ensure factories implement required interfaces
var _ interface{} = (*StreamConfigFactory)(nil)
var _ interface{} = (*ProcessorCollectionFactory)(nil)
