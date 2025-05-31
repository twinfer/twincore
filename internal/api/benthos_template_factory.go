package api

import (
	"embed"
	"fmt"
	"strings"
	"text/template"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

//go:embed templates/benthos/*.yaml
var benthosTemplates embed.FS

//go:embed templates/processors/*.yaml
var processorTemplates embed.FS

// BenthosTemplateFactory creates Benthos configurations from embedded YAML templates
type BenthosTemplateFactory struct {
	inputTemplates     map[string]*template.Template
	outputTemplates    map[string]*template.Template
	processorTemplates map[string]*template.Template
	streamTemplates    map[string]*template.Template // Added missing field
	logger             logrus.FieldLogger
}

// StreamTemplateParams provides parameters for stream template execution
type StreamTemplateParams struct {
	// Common parameters
	ThingID        string `yaml:"thing_id"`
	ParquetLogPath string `yaml:"parquet_log_path"`
	KafkaBrokers   string `yaml:"kafka_brokers"`

	// HTTP-specific parameters
	HTTPPath string `yaml:"http_path"`

	// Kafka-specific parameters
	KafkaTopic    string `yaml:"kafka_topic"`
	ConsumerGroup string `yaml:"consumer_group"`

	// License and security
	RequiredFeature string `yaml:"required_feature"`

	// Schema validation
	SchemaPath string `yaml:"schema_path"`

	// Custom metadata
	Metadata map[string]interface{} `yaml:"metadata,omitempty"`
}

// ProcessorCollectionParams provides parameters for processor collection templates
type ProcessorCollectionParams struct {
	CollectionID    string                 `yaml:"collection_id"`
	RequiredFeature string                 `yaml:"required_feature,omitempty"`
	SchemaPath      string                 `yaml:"schema_path,omitempty"`
	Metadata        map[string]interface{} `yaml:"metadata,omitempty"`
}

// NewBenthosTemplateFactory creates a new template-based factory
func NewBenthosTemplateFactory(logger logrus.FieldLogger) (*BenthosTemplateFactory, error) {
	factory := &BenthosTemplateFactory{
		inputTemplates:     make(map[string]*template.Template),
		outputTemplates:    make(map[string]*template.Template),
		processorTemplates: make(map[string]*template.Template),
		streamTemplates:    make(map[string]*template.Template),
		logger:             logger,
	}

	if err := factory.loadAtomicTemplates(); err != nil {
		return nil, fmt.Errorf("failed to load atomic templates: %w", err)
	}

	if err := factory.loadProcessorTemplates(); err != nil {
		return nil, fmt.Errorf("failed to load processor templates: %w", err)
	}

	return factory, nil
}

// loadAtomicTemplates loads and parses input/output templates
func (f *BenthosTemplateFactory) loadAtomicTemplates() error {
	entries, err := benthosTemplates.ReadDir("templates/benthos")
	if err != nil {
		return fmt.Errorf("failed to read benthos templates directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yaml") {
			templateName := strings.TrimSuffix(entry.Name(), ".yaml")

			content, err := benthosTemplates.ReadFile("templates/benthos/" + entry.Name())
			if err != nil {
				return fmt.Errorf("failed to read template %s: %w", entry.Name(), err)
			}

			tmpl, err := template.New(templateName).Parse(string(content))
			if err != nil {
				return fmt.Errorf("failed to parse template %s: %w", templateName, err)
			}

			// Categorize templates by prefix
			if strings.HasPrefix(templateName, "input-") {
				f.inputTemplates[templateName] = tmpl
				f.logger.WithField("template", templateName).Debug("Loaded input template")
			} else if strings.HasPrefix(templateName, "output-") {
				f.outputTemplates[templateName] = tmpl
				f.logger.WithField("template", templateName).Debug("Loaded output template")
			}
		}
	}

	return nil
}

// loadProcessorTemplates loads and parses all embedded processor collection templates
func (f *BenthosTemplateFactory) loadProcessorTemplates() error {
	entries, err := processorTemplates.ReadDir("templates/processors")
	if err != nil {
		return fmt.Errorf("failed to read processor templates directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yaml") {
			templateName := strings.TrimSuffix(entry.Name(), ".yaml")

			content, err := processorTemplates.ReadFile("templates/processors/" + entry.Name())
			if err != nil {
				return fmt.Errorf("failed to read template %s: %w", entry.Name(), err)
			}

			tmpl, err := template.New(templateName).Parse(string(content))
			if err != nil {
				return fmt.Errorf("failed to parse template %s: %w", templateName, err)
			}

			f.processorTemplates[templateName] = tmpl
			f.logger.WithField("template", templateName).Debug("Loaded processor template")
		}
	}

	return nil
}

// GenerateInput creates an input configuration from atomic template
func (f *BenthosTemplateFactory) GenerateInput(templateName string, params interface{}) ([]byte, error) {
	tmpl, exists := f.inputTemplates[templateName]
	if !exists {
		return nil, fmt.Errorf("input template not found: %s", templateName)
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, params); err != nil {
		return nil, fmt.Errorf("failed to execute input template %s: %w", templateName, err)
	}

	return []byte(buf.String()), nil
}

// GenerateOutput creates an output configuration from atomic template
func (f *BenthosTemplateFactory) GenerateOutput(templateName string, params interface{}) ([]byte, error) {
	tmpl, exists := f.outputTemplates[templateName]
	if !exists {
		return nil, fmt.Errorf("output template not found: %s", templateName)
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, params); err != nil {
		return nil, fmt.Errorf("failed to execute output template %s: %w", templateName, err)
	}

	return []byte(buf.String()), nil
}

// GenerateProcessorCollection creates processor collection config from a template
func (f *BenthosTemplateFactory) GenerateProcessorCollection(templateName string, params ProcessorCollectionParams) ([]byte, error) {
	tmpl, exists := f.processorTemplates[templateName]
	if !exists {
		return nil, fmt.Errorf("processor template not found: %s", templateName)
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, params); err != nil {
		return nil, fmt.Errorf("failed to execute processor template %s: %w", templateName, err)
	}

	// Validate YAML syntax
	var yamlCheck interface{}
	if err := yaml.Unmarshal([]byte(buf.String()), &yamlCheck); err != nil {
		return nil, fmt.Errorf("generated YAML is invalid for processor template %s: %w", templateName, err)
	}

	f.logger.WithFields(logrus.Fields{
		"template":      templateName,
		"collection_id": params.CollectionID,
		"feature":       params.RequiredFeature,
	}).Debug("Generated processor collection from template")

	return []byte(buf.String()), nil
}

// ListStreamTemplates returns available stream template names
func (f *BenthosTemplateFactory) ListStreamTemplates() []string {
	var names []string
	for name := range f.streamTemplates {
		names = append(names, name)
	}
	return names
}

// ListProcessorTemplates returns available processor template names
func (f *BenthosTemplateFactory) ListProcessorTemplates() []string {
	var names []string
	for name := range f.processorTemplates {
		names = append(names, name)
	}
	return names
}

// GenerateStreamConfigForThing creates a complete stream config for a Thing
func (f *BenthosTemplateFactory) GenerateStreamConfigForThing(
	thingID string,
	interactionType string,
	interactionName string,
	templateName string,
	parquetLogPath string,
) ([]byte, error) {

	params := StreamTemplateParams{
		ThingID:         thingID,
		ParquetLogPath:  parquetLogPath,
		KafkaBrokers:    "${KAFKA_BROKERS:localhost:9092}",
		KafkaTopic:      fmt.Sprintf("things.%s.%s.%s", thingID, interactionType, interactionName),
		ConsumerGroup:   fmt.Sprintf("twincore-%s-%s", interactionType, thingID),
		HTTPPath:        fmt.Sprintf("/things/%s/%s/%s", thingID, interactionType, interactionName),
		RequiredFeature: getRequiredFeature(interactionType),
	}

	return f.GenerateStreamConfig(templateName, params)
}

// GenerateStreamConfig creates a stream configuration from template
func (f *BenthosTemplateFactory) GenerateStreamConfig(templateName string, params StreamTemplateParams) ([]byte, error) {
	tmpl, exists := f.streamTemplates[templateName]
	if !exists {
		return nil, fmt.Errorf("stream template not found: %s", templateName)
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, params); err != nil {
		return nil, fmt.Errorf("failed to execute stream template %s: %w", templateName, err)
	}

	// Validate YAML syntax
	var yamlCheck interface{}
	if err := yaml.Unmarshal([]byte(buf.String()), &yamlCheck); err != nil {
		return nil, fmt.Errorf("generated YAML is invalid for stream template %s: %w", templateName, err)
	}

	f.logger.WithFields(logrus.Fields{
		"template": templateName,
		"thing_id": params.ThingID,
	}).Debug("Generated stream config from template")

	return []byte(buf.String()), nil
}

// getRequiredFeature maps interaction types to required license features
func getRequiredFeature(interactionType string) string {
	switch interactionType {
	case "properties":
		return "property_processing"
	case "actions":
		return "action_processing"
	case "events":
		return "event_processing"
	default:
		return "basic_processing"
	}
}

// Unified resource identifier generation
func (f *BenthosTemplateFactory) GenerateResourceID(thingID, interactionType, interactionName string) string {
	// Create a unified resource identifier for the stream
	return fmt.Sprintf("twincore.%s.%s.%s", thingID, interactionType, interactionName)
}

// StreamResourceConfig represents a complete stream resource configuration
type StreamResourceConfig struct {
	ResourceID      string                 `yaml:"resource_id"`
	Label           string                 `yaml:"label"`
	StreamConfig    []byte                 `yaml:"stream_config"`
	ProcessorChains []string               `yaml:"processor_chains"`
	Metadata        map[string]interface{} `yaml:"metadata"`
}

// GenerateCompleteStreamResource creates a complete stream resource with unified ID
func (f *BenthosTemplateFactory) GenerateCompleteStreamResource(
	thingID string,
	interactionType string,
	interactionName string,
	templateName string,
	processorChains []string,
	parquetLogPath string,
) (*StreamResourceConfig, error) {

	resourceID := f.GenerateResourceID(thingID, interactionType, interactionName)

	streamConfig, err := f.GenerateStreamConfigForThing(
		thingID, interactionType, interactionName, templateName, parquetLogPath,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate stream config: %w", err)
	}

	resource := &StreamResourceConfig{
		ResourceID:      resourceID,
		Label:           fmt.Sprintf("%s %s %s stream", thingID, interactionType, interactionName),
		StreamConfig:    streamConfig,
		ProcessorChains: processorChains,
		Metadata: map[string]interface{}{
			"thing_id":         thingID,
			"interaction_type": interactionType,
			"interaction_name": interactionName,
			"template":         templateName,
			"generated_at":     "{{ timestamp_unix() }}",
		},
	}

	f.logger.WithFields(logrus.Fields{
		"resource_id":      resourceID,
		"thing_id":         thingID,
		"interaction_type": interactionType,
		"template":         templateName,
	}).Info("Generated complete stream resource")

	return resource, nil
}
