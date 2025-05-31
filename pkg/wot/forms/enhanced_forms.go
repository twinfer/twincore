package forms

import (
	"fmt"
	"strings"
	"time"

	"github.com/redpanda-data/benthos/v4/public/service"
	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
)

// EnhancedForm extends the basic Form interface with methods for stream configuration
type EnhancedForm interface {
	wot.Form
	// GetStreamProtocol returns the protocol type for stream configuration
	GetStreamProtocol() types.StreamProtocol
	// GetStreamDirection returns the data flow direction
	GetStreamDirection(op []string) types.StreamDirection
	// GenerateStreamEndpoint generates endpoint configuration for stream manager
	GenerateStreamEndpoint() (map[string]interface{}, error)
}

// GetStreamDirection determines stream direction based on WoT operations
func GetStreamDirection(ops []string) types.StreamDirection {
	for _, op := range ops {
		switch op {
		case "readproperty", "observeproperty", "subscribeevent":
			return types.StreamDirectionInbound
		case "writeproperty", "invokeaction":
			return types.StreamDirectionOutbound
		}
	}
	return types.StreamDirectionInternal
}

// GenerateProcessorChain creates a processor chain based on interaction type and options
func GenerateProcessorChain(interactionType string, options map[string]interface{}) []map[string]interface{} {
	processors := []map[string]interface{}{}
	
	// Add WoT-specific processor based on interaction type
	switch interactionType {
	case "property":
		processors = append(processors, map[string]interface{}{
			"type": string(types.ProcessorBloblangWoTProperty),
			"config": map[string]interface{}{
				"mapping": "root = this", // Default passthrough, can be customized
			},
		})
	case "action":
		processors = append(processors, map[string]interface{}{
			"type": string(types.ProcessorBloblangWoTAction),
			"config": map[string]interface{}{
				"mapping": "root = this",
			},
		})
	case "event":
		processors = append(processors, map[string]interface{}{
			"type": string(types.ProcessorBloblangWoTEvent),
			"config": map[string]interface{}{
				"mapping": "root = this",
			},
		})
	}
	
	// Add JSON schema validation if schema is provided
	if schema, ok := options["schema"]; ok {
		processors = append(processors, map[string]interface{}{
			"type": string(types.ProcessorJSONSchema),
			"config": map[string]interface{}{
				"schema": schema,
			},
		})
	}
	
	// Add Parquet encoding for logging streams
	if enableParquet, ok := options["enable_parquet"].(bool); ok && enableParquet {
		processors = append(processors, map[string]interface{}{
			"type": string(types.ProcessorParquetEncode),
			"config": map[string]interface{}{
				"schema": generateParquetSchema(interactionType),
			},
		})
	}
	
	return processors
}

// generateParquetSchema creates a Parquet schema for the given interaction type
func generateParquetSchema(interactionType string) []map[string]interface{} {
	baseSchema := []map[string]interface{}{
		{
			"name":            "thing_id",
			"type":            "BYTE_ARRAY",
			"converted_type":  "UTF8",
			"repetition_type": "REQUIRED",
		},
		{
			"name":            "timestamp",
			"type":            "INT64",
			"converted_type":  "TIMESTAMP_NANOS",
			"repetition_type": "REQUIRED",
		},
	}
	
	switch interactionType {
	case "property":
		baseSchema = append(baseSchema, 
			map[string]interface{}{
				"name":            "property_name",
				"type":            "BYTE_ARRAY",
				"converted_type":  "UTF8",
				"repetition_type": "REQUIRED",
			},
			map[string]interface{}{
				"name":            "value",
				"type":            "BYTE_ARRAY",
				"converted_type":  "UTF8",
				"repetition_type": "REQUIRED",
			},
		)
	case "action":
		baseSchema = append(baseSchema,
			map[string]interface{}{
				"name":            "action_name",
				"type":            "BYTE_ARRAY",
				"converted_type":  "UTF8",
				"repetition_type": "REQUIRED",
			},
			map[string]interface{}{
				"name":            "action_id",
				"type":            "BYTE_ARRAY",
				"converted_type":  "UTF8",
				"repetition_type": "REQUIRED",
			},
			map[string]interface{}{
				"name":            "input",
				"type":            "BYTE_ARRAY",
				"converted_type":  "UTF8",
				"repetition_type": "OPTIONAL",
			},
			map[string]interface{}{
				"name":            "status",
				"type":            "BYTE_ARRAY",
				"converted_type":  "UTF8",
				"repetition_type": "REQUIRED",
			},
		)
	case "event":
		baseSchema = append(baseSchema,
			map[string]interface{}{
				"name":            "event_name",
				"type":            "BYTE_ARRAY",
				"converted_type":  "UTF8",
				"repetition_type": "REQUIRED",
			},
			map[string]interface{}{
				"name":            "data",
				"type":            "BYTE_ARRAY",
				"converted_type":  "UTF8",
				"repetition_type": "OPTIONAL",
			},
			map[string]interface{}{
				"name":            "severity",
				"type":            "BYTE_ARRAY",
				"converted_type":  "UTF8",
				"repetition_type": "REQUIRED",
			},
		)
	}
	
	baseSchema = append(baseSchema, map[string]interface{}{
		"name":            "source",
		"type":            "BYTE_ARRAY",
		"converted_type":  "UTF8",
		"repetition_type": "REQUIRED",
	})
	
	return baseSchema
}

// ConvertFormToStreamEndpoint converts a WoT form to a stream endpoint configuration
func ConvertFormToStreamEndpoint(form wot.Form) (map[string]interface{}, error) {
	config := map[string]interface{}{
		"type": form.GetProtocol(),
	}
	
	switch form.GetProtocol() {
	case "kafka":
		if kf, ok := form.(*KafkaForm); ok {
			config["config"] = map[string]interface{}{
				"brokers": []string{kf.Href},
				"topic":   kf.Topic,
			}
		}
	case "mqtt":
		// TODO: Implement MQTT form conversion
		config["config"] = map[string]interface{}{
			"broker": form.GetHref(),
		}
	case "http":
		if hf, ok := form.(*HTTPForm); ok {
			config["config"] = map[string]interface{}{
				"url":    hf.Href,
				"method": hf.Method,
			}
		}
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", form.GetProtocol())
	}
	
	return config, nil
}

// BindingGenerator centralizes all protocol binding generation from Thing Descriptions
type BindingGenerator struct {
	logger         logrus.FieldLogger
	parquetConfig  types.ParquetConfig
	kafkaConfig    types.KafkaConfig
	mqttConfig     types.MQTTConfig
	licenseChecker LicenseChecker
}

// LicenseChecker interface for checking feature availability
type LicenseChecker interface {
	IsFeatureAvailable(feature string) bool
	GetFeatureConfig(feature string) map[string]interface{}
}

// NewBindingGenerator creates a new binding generator
func NewBindingGenerator(logger logrus.FieldLogger, licenseChecker LicenseChecker) *BindingGenerator {
	return &BindingGenerator{
		logger:         logger,
		licenseChecker: licenseChecker,
		parquetConfig: types.ParquetConfig{
			BasePath:        "${PARQUET_LOG_PATH}",
			BatchSize:       1000,
			BatchPeriod:     "5s",
			Compression:     "gzip",
			FileNamePattern: "%s_%s.parquet",
		},
		kafkaConfig: types.KafkaConfig{
			Brokers: []string{"${KAFKA_BROKERS:localhost:9092}"},
		},
		mqttConfig: types.MQTTConfig{
			Broker: "${MQTT_BROKER:tcp://localhost:1883}",
			QoS:    1,
		},
	}
}

// GenerateAllBindings generates all bindings (HTTP routes + Benthos streams) from a Thing Description
func (bg *BindingGenerator) GenerateAllBindings(td *wot.ThingDescription) (*AllBindings, error) {
	bindings := &AllBindings{
		ThingID:     td.ID,
		HTTPRoutes:  make(map[string]HTTPRoute),
		Streams:     make(map[string]StreamConfig),
		Processors:  make(map[string]ProcessorChain),
		GeneratedAt: time.Now(),
	}

	// Generate property bindings
	for propName, prop := range td.Properties {
		if err := bg.generatePropertyBindings(td.ID, propName, prop, bindings); err != nil {
			return nil, fmt.Errorf("failed to generate property bindings for %s: %w", propName, err)
		}
	}

	// Generate action bindings
	for actionName, action := range td.Actions {
		if err := bg.generateActionBindings(td.ID, actionName, action, bindings); err != nil {
			return nil, fmt.Errorf("failed to generate action bindings for %s: %w", actionName, err)
		}
	}

	// Generate event bindings
	for eventName, event := range td.Events {
		if err := bg.generateEventBindings(td.ID, eventName, event, bindings); err != nil {
			return nil, fmt.Errorf("failed to generate event bindings for %s: %w", eventName, err)
		}
	}

	bg.logger.WithFields(logrus.Fields{
		"thing_id":    td.ID,
		"http_routes": len(bindings.HTTPRoutes),
		"streams":     len(bindings.Streams),
		"processors":  len(bindings.Processors),
	}).Info("Generated all bindings for Thing Description")

	return bindings, nil
}

// AllBindings contains all generated bindings for a Thing Description
type AllBindings struct {
	ThingID     string                     `json:"thing_id"`
	HTTPRoutes  map[string]HTTPRoute       `json:"http_routes"`
	Streams     map[string]StreamConfig    `json:"streams"`
	Processors  map[string]ProcessorChain  `json:"processors"`
	GeneratedAt time.Time                  `json:"generated_at"`
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
	ID             string                   `json:"id"`
	Type           types.BenthosStreamType  `json:"type"`
	Direction      types.StreamDirection    `json:"direction"`
	Input          StreamEndpoint           `json:"input"`
	Output         StreamEndpoint           `json:"output"`
	ProcessorChain ProcessorChain           `json:"processor_chain"`
	YAML           string                   `json:"yaml"`
}

// StreamEndpoint represents input/output configuration for streams
type StreamEndpoint struct {
	Protocol types.StreamProtocol  `json:"protocol"`
	Config   map[string]interface{} `json:"config"`
}

// ProcessorChain represents a sequence of Benthos processors
type ProcessorChain struct {
	ID         string                     `json:"id"`
	Name       string                     `json:"name"`
	Processors []ProcessorConfig          `json:"processors"`
	Metadata   map[string]interface{}     `json:"metadata,omitempty"`
}

// ProcessorConfig represents a single Benthos processor configuration
type ProcessorConfig struct {
	Type        types.BenthosProcessorType `json:"type"`
	Label       string                     `json:"label"`
	Config      map[string]interface{}     `json:"config"`
	Description string                     `json:"description,omitempty"`
}

// generatePropertyBindings creates all bindings for a property affordance
func (bg *BindingGenerator) generatePropertyBindings(thingID, propName string, prop *wot.PropertyAffordance, bindings *AllBindings) error {
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
		if err := bg.generatePropertyObservationStream(thingID, propName, prop, bindings); err != nil {
			return err
		}
	}

	// Generate streams for writable properties
	if !prop.IsReadOnly() && bg.licenseChecker.IsFeatureAvailable("property_commands") {
		if err := bg.generatePropertyCommandStream(thingID, propName, prop, bindings); err != nil {
			return err
		}
	}

	// Generate persistence stream if logging is enabled
	if bg.licenseChecker.IsFeatureAvailable("parquet_logging") {
		if err := bg.generatePropertyLoggingStream(thingID, propName, prop, bindings); err != nil {
			return err
		}
	}

	return nil
}

// generateActionBindings creates all bindings for an action affordance
func (bg *BindingGenerator) generateActionBindings(thingID, actionName string, action *wot.ActionAffordance, bindings *AllBindings) error {
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
		if err := bg.generateActionInvocationStream(thingID, actionName, action, bindings); err != nil {
			return err
		}
	}

	// Generate action logging stream
	if bg.licenseChecker.IsFeatureAvailable("parquet_logging") {
		if err := bg.generateActionLoggingStream(thingID, actionName, action, bindings); err != nil {
			return err
		}
	}

	return nil
}

// generateEventBindings creates all bindings for an event affordance
func (bg *BindingGenerator) generateEventBindings(thingID, eventName string, event *wot.EventAffordance, bindings *AllBindings) error {
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
		if err := bg.generateEventProcessingStream(thingID, eventName, event, bindings); err != nil {
			return err
		}
	}

	// Generate event logging stream
	if bg.licenseChecker.IsFeatureAvailable("parquet_logging") {
		if err := bg.generateEventLoggingStream(thingID, eventName, event, bindings); err != nil {
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

// Helper methods for stream generation
func (bg *BindingGenerator) generateStreamYAML(config StreamConfig) (string, error) {
	// Create YAML template for the stream
	yamlTemplate := `
input:
  %s:
%s

pipeline:
  processors:
%s

output:
  %s:
%s
`

	// Generate input section
	inputConfig := bg.generateEndpointYAML(config.Input, "    ")
	
	// Generate processor section
	processorConfig := ""
	for _, proc := range config.ProcessorChain.Processors {
		processorConfig += fmt.Sprintf("    - label: \"%s\"\n", proc.Label)
		processorConfig += fmt.Sprintf("      %s:\n", string(proc.Type))
		for key, value := range proc.Config {
			processorConfig += fmt.Sprintf("        %s: %v\n", key, value)
		}
	}

	// Generate output section
	outputConfig := bg.generateEndpointYAML(config.Output, "    ")

	yaml := fmt.Sprintf(yamlTemplate,
		string(config.Input.Protocol),
		inputConfig,
		processorConfig,
		string(config.Output.Protocol),
		outputConfig,
	)

	return yaml, nil
}

func (bg *BindingGenerator) generateEndpointYAML(endpoint StreamEndpoint, indent string) string {
	var lines []string
	for key, value := range endpoint.Config {
		switch v := value.(type) {
		case string:
			lines = append(lines, fmt.Sprintf("%s%s: \"%s\"", indent, key, v))
		case []string:
			lines = append(lines, fmt.Sprintf("%s%s:", indent, key))
			for _, item := range v {
				lines = append(lines, fmt.Sprintf("%s  - \"%s\"", indent, item))
			}
		default:
			lines = append(lines, fmt.Sprintf("%s%s: %v", indent, key, v))
		}
	}
	return strings.Join(lines, "\n")
}

// Mapping generation methods
func (bg *BindingGenerator) generatePropertyMapping(thingID, propName string) string {
	return fmt.Sprintf(`
root.thing_id = "%s"
root.property_name = "%s"
root.value = this.value
root.timestamp = timestamp_unix_nano()
root.source = this.source.or("stream")
`, thingID, propName)
}

func (bg *BindingGenerator) generatePropertyLoggingMapping(thingID, propName string) string {
	return fmt.Sprintf(`
root.thing_id = "%s"
root.property_name = "%s"
root.value = this.value.string()
root.timestamp = timestamp_unix_nano()
root.source = this.source.or("stream")
`, thingID, propName)
}

func (bg *BindingGenerator) generatePropertyCommandMapping(thingID, propName string) string {
	return fmt.Sprintf(`
root.thing_id = "%s"
root.property_name = "%s"
root.value = this.value
root.command_id = uuid_v4()
root.timestamp = timestamp_unix_nano()
root.source = "http"
`, thingID, propName)
}

// Schema generation methods
func (bg *BindingGenerator) generatePropertyParquetSchema() []map[string]interface{} {
	return []map[string]interface{}{
		{"name": "thing_id", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "property_name", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "value", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "timestamp", "type": "INT64", "converted_type": "TIMESTAMP_NANOS", "repetition_type": "REQUIRED"},
		{"name": "source", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
	}
}

func (bg *BindingGenerator) convertDataSchemaToJSONSchema(schema wot.DataSchemaCore) map[string]interface{} {
	jsonSchema := map[string]interface{}{
		"type": schema.Type,
	}
	
	if schema.Type == "object" && schema.Properties != nil {
		properties := make(map[string]interface{})
		for name, prop := range schema.Properties {
			properties[name] = bg.convertDataSchemaToJSONSchema(prop.DataSchemaCore)
		}
		jsonSchema["properties"] = properties
		
		if len(schema.Required) > 0 {
			jsonSchema["required"] = schema.Required
		}
	}
	
	return jsonSchema
}

// Placeholder methods for action and event stream generation
func (bg *BindingGenerator) generatePropertyObservationStream(thingID, propName string, prop *wot.PropertyAffordance, bindings *AllBindings) error {
	// Implementation similar to generatePropertyLoggingStream but for observation
	return nil
}

func (bg *BindingGenerator) generatePropertyCommandStream(thingID, propName string, prop *wot.PropertyAffordance, bindings *AllBindings) error {
	// Implementation for property command streams
	return nil
}

func (bg *BindingGenerator) generatePropertyLoggingStream(thingID, propName string, prop *wot.PropertyAffordance, bindings *AllBindings) error {
	// Implementation for property logging streams
	return nil
}

func (bg *BindingGenerator) generateActionInvocationStream(thingID, actionName string, action *wot.ActionAffordance, bindings *AllBindings) error {
	// Implementation for action invocation streams
	return nil
}

func (bg *BindingGenerator) generateActionLoggingStream(thingID, actionName string, action *wot.ActionAffordance, bindings *AllBindings) error {
	// Implementation for action logging streams
	return nil
}

func (bg *BindingGenerator) generateEventProcessingStream(thingID, eventName string, event *wot.EventAffordance, bindings *AllBindings) error {
	// Implementation for event processing streams
	return nil
}

func (bg *BindingGenerator) generateEventLoggingStream(thingID, eventName string, event *wot.EventAffordance, bindings *AllBindings) error {
	// Implementation for event logging streams
	return nil
}