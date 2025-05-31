package forms

import (
	"bytes"
	"context"
	"encoding/base64"
	_ "embed"
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
)

//go:embed templates/kafka_input.yaml
var kafkaInputTemplate string

//go:embed templates/kafka_output.yaml
var kafkaOutputTemplate string

//go:embed templates/http_client.yaml
var httpClientTemplate string

//go:embed templates/http_server.yaml
var httpServerTemplate string

// KafkaForm implements Form interface for Kafka/Redpanda with enhanced stream capabilities
type KafkaForm struct {
	Href        string   `json:"href"`
	ContentType string   `json:"contentType"`
	Op          []string `json:"op"`
	Topic       string   `json:"kafka:topic,omitempty"`
	Partition   int      `json:"kafka:partition,omitempty"`
}

func (f *KafkaForm) GetProtocol() string {
	return "kafka"
}

func (f *KafkaForm) GetHref() string {
	return f.Href
}

func (f *KafkaForm) GetContentType() string {
	if f.ContentType == "" {
		return "application/json"
	}
	return f.ContentType
}

func (f *KafkaForm) GetOp() []string {
	return f.Op
}

func (f *KafkaForm) GetStreamProtocol() types.StreamProtocol {
	return types.ProtocolKafka
}

func (f *KafkaForm) GetStreamDirection(op []string) types.StreamDirection {
	return GetStreamDirection(op)
}

func (f *KafkaForm) GenerateStreamEndpoint() (map[string]interface{}, error) {
	return f.GenerateConfig(nil)
}

func (f *KafkaForm) GenerateConfig(securityDefs map[string]wot.SecurityScheme) (map[string]interface{}, error) {
	// Determine if this is input or output based on operations
	isInput := false
	for _, op := range f.Op {
		if op == "readproperty" || op == "subscribeevent" {
			isInput = true
			break
		}
	}

	// Select template
	tmplStr := kafkaOutputTemplate
	if isInput {
		tmplStr = kafkaInputTemplate
	}

	// Parse template
	tmpl, err := template.New("kafka").Parse(tmplStr)
	if err != nil {
		return nil, err
	}

	// Build config data
	config := map[string]interface{}{
		"addresses": []string{f.Href},
		"topic":     f.Topic,
		"partition": f.Partition,
	}

	// Add security config
	if auth := f.extractAuthConfig(securityDefs); auth != nil {
		config["auth"] = auth
	}

	// Execute template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, config); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"yaml":   buf.String(),
		"type":   f.GetProtocol(),
		"config": config,
	}, nil
}

func (f *KafkaForm) extractAuthConfig(securityDefs map[string]wot.SecurityScheme) map[string]interface{} {
	for _, schemeDef := range securityDefs {
		if schemeDef.Scheme == "" {
			continue
		}

		switch strings.ToLower(schemeDef.Scheme) {
		case "basic", "plain": // SASL PLAIN
			username := "${TWINEDGE_KAFKA_USER}" // Default placeholder
			password := "${TWINEDGE_KAFKA_PASS}" // Default placeholder

			if schemeDef.Properties != nil {
				if userVal, ok := schemeDef.Properties["user"].(string); ok && userVal != "" {
					username = userVal
				} else if userVal, ok := schemeDef.Properties["username"].(string); ok && userVal != "" {
					username = userVal
				}
				if passVal, ok := schemeDef.Properties["password"].(string); ok && passVal != "" {
					password = passVal
				}
			}
			return map[string]interface{}{
				"mechanism": "PLAIN",
				"username":  username,
				"password":  password,
			}
		case "scram-sha-256", "scram-sha-512":
			username := "${TWINEDGE_KAFKA_USER}"
			password := "${TWINEDGE_KAFKA_PASS}"
			mechanism := strings.ToUpper(schemeDef.Scheme) // SCRAM-SHA-256 or SCRAM-SHA-512

			if schemeDef.Properties != nil {
				if userVal, ok := schemeDef.Properties["user"].(string); ok && userVal != "" {
					username = userVal
				} else if userVal, ok := schemeDef.Properties["username"].(string); ok && userVal != "" {
					username = userVal
				}
				if passVal, ok := schemeDef.Properties["password"].(string); ok && passVal != "" {
					password = passVal
				}
			}
			return map[string]interface{}{
				"mechanism": mechanism,
				"username":  username,
				"password":  password,
			}

		case "oauth2":
			// SASL OAUTHBEARER
			tokenPlaceholder := "${TWINEDGE_KAFKA_OAUTH_TOKEN}"
			if schemeDef.Properties != nil {
				if tokenVal, ok := schemeDef.Properties["token"].(string); ok && tokenVal != "" {
					tokenPlaceholder = tokenVal
				}
			}
			return map[string]interface{}{
				"mechanism": "OAUTHBEARER",
				"token":     tokenPlaceholder,
			}

		case "nosec":
			return nil // No auth config needed
		}
	}
	return nil // No suitable and configured security scheme found
}

// HTTPForm implements Form interface for HTTP with enhanced capabilities
type HTTPForm struct {
	Href        string            `json:"href"`
	ContentType string            `json:"contentType"`
	Method      string            `json:"htv:methodName,omitempty"` // W3C WoT compliant
	Op          []string          `json:"op"`
	Headers     map[string]string `json:"htv:headers,omitempty"`    // W3C WoT compliant
}

func (f *HTTPForm) GetProtocol() string {
	return "http"
}

func (f *HTTPForm) GetHref() string {
	return f.Href
}

func (f *HTTPForm) GetContentType() string {
	if f.ContentType == "" {
		return "application/json"
	}
	return f.ContentType
}

func (f *HTTPForm) GetOp() []string {
	return f.Op
}

func (f *HTTPForm) GetStreamProtocol() types.StreamProtocol {
	return types.ProtocolHTTP
}

func (f *HTTPForm) GetStreamDirection(op []string) types.StreamDirection {
	return GetStreamDirection(op)
}

func (f *HTTPForm) GenerateStreamEndpoint() (map[string]interface{}, error) {
	return f.GenerateConfig(nil)
}

func (f *HTTPForm) GenerateConfig(securityDefs map[string]wot.SecurityScheme) (map[string]interface{}, error) {
	// Determine if this is client or server based on operations
	isServer := false
	for _, op := range f.Op {
		if op == "writeproperty" || op == "invokeaction" {
			isServer = true
			break
		}
	}

	// Select template
	tmplStr := httpClientTemplate
	if isServer {
		tmplStr = httpServerTemplate
	}

	// Parse template
	tmpl, err := template.New("http").Parse(tmplStr)
	if err != nil {
		return nil, err
	}

	// Determine HTTP method
	method := f.Method
	if method == "" {
		method = f.inferHTTPMethod()
	}

	// Build config data
	config := map[string]interface{}{
		"url":     f.Href,
		"method":  method,
		"headers": f.Headers,
	}

	// Add security config
	if auth := f.extractAuthHeaders(securityDefs); auth != nil {
		if config["headers"] == nil {
			config["headers"] = make(map[string]string)
		}
		headers := config["headers"].(map[string]string)
		for k, v := range auth {
			headers[k] = v
		}
	}

	// Execute template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, config); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"yaml":   buf.String(),
		"type":   f.GetProtocol(),
		"config": config,
	}, nil
}

func (f *HTTPForm) inferHTTPMethod() string {
	for _, op := range f.Op {
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

func (f *HTTPForm) extractAuthHeaders(securityDefs map[string]wot.SecurityScheme) map[string]string {
	headers := make(map[string]string)

	for _, schemeDef := range securityDefs {
		if schemeDef.Scheme == "" {
			continue
		}

		switch schemeDef.Scheme {
		case "basic":
			// W3C WoT: name (optional), user (optional), password (optional)
			// Use environment variable placeholders for actual credentials
			authUsername := "${TWINEDGE_BASIC_USER}" // Default placeholder
			authPassword := "${TWINEDGE_BASIC_PASS}" // Default placeholder
			
			// Encode credentials for HTTP Basic Auth
			authVal := base64.StdEncoding.EncodeToString([]byte(authUsername + ":" + authPassword))
			headers["Authorization"] = "Basic " + authVal

		case "bearer":
			// W3C WoT: token (optional string for direct token), format (e.g. "jwt"), alg, authorization (URL)
			bearerToken := "${TWINEDGE_BEARER_TOKEN}"
			headers["Authorization"] = "Bearer " + bearerToken

		case "apikey":
			// W3C WoT: in ("header", "query", "cookie"), name (header/query/cookie name)
			// Only handle "header" for Benthos http_client headers
			if schemeDef.In == "header" && schemeDef.Name != "" {
				apiKey := fmt.Sprintf("${TWINEDGE_APIKEY_%s}", schemeDef.Name) // Placeholder by default
				headers[schemeDef.Name] = apiKey
			}

		case "oauth2":
			// W3C WoT: authorization (URL), token (URL), refresh (URL), scopes, flow
			// For forms, indicate intent with a placeholder - actual token must be fetched externally
			headers["Authorization"] = "Bearer ${TWINEDGE_OAUTH2_TOKEN}"
		}
	}

	if len(headers) == 0 {
		return nil
	}
	return headers
}

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

	// Use the form's own configuration generation if available
	if configGen, ok := form.(interface{ GenerateConfig(map[string]wot.SecurityScheme) (map[string]interface{}, error) }); ok {
		formConfig, err := configGen.GenerateConfig(nil) // Pass empty security for now
		if err != nil {
			return nil, fmt.Errorf("failed to generate form config: %w", err)
		}
		// Extract the actual config from the form's response
		if actualConfig, exists := formConfig["config"]; exists {
			config["config"] = actualConfig
		} else {
			config["config"] = formConfig
		}
		return config, nil
	}

	// Fallback to basic configuration for forms without GenerateConfig
	switch form.GetProtocol() {
	case "kafka":
		config["config"] = map[string]interface{}{
			"brokers": []string{form.GetHref()},
			"topic":   "default_topic", // Should be extracted from form
		}
	case "mqtt":
		config["config"] = map[string]interface{}{
			"broker": form.GetHref(),
		}
	case "http":
		config["config"] = map[string]interface{}{
			"url":    form.GetHref(),
			"method": "GET", // Default method
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

	// Generate persistence stream if data persistence is enabled
	if bg.licenseChecker.IsFeatureAvailable("data_persistence") {
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

	// Generate action persistence stream
	if bg.licenseChecker.IsFeatureAvailable("data_persistence") {
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

	// Generate event persistence stream
	if bg.licenseChecker.IsFeatureAvailable("data_persistence") {
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

func (bg *BindingGenerator) generatePropertyPersistenceMapping(thingID, propName string) string {
	return fmt.Sprintf(`
root.thing_id = "%s"
root.property_name = "%s"
root.value = this.value
root.timestamp = timestamp_unix_nano()
root.source = this.source.or("stream")
`, thingID, propName)
}

func (bg *BindingGenerator) generatePropertyObservationMapping(thingID, propName string) string {
	return fmt.Sprintf(`
# Format for real-time property observation
root.thing_id = "%s"
root.property_name = "%s"
root.value = this.value
root.timestamp = timestamp_unix_nano()
root.change_type = this.change_type.or("update")
root.previous_value = this.previous_value
root.source = this.source.or("device")

# Add metadata for observers
root.metadata = {
  "observable": true,
  "data_type": this.data_type.or("unknown"),
  "unit": this.unit.or(""),
  "quality": this.quality.or("good")
}
`, thingID, propName)
}

func (bg *BindingGenerator) generatePropertyLoggingMapping(thingID, propName string) string {
	// Legacy method - redirect to persistence mapping
	return bg.generatePropertyPersistenceMapping(thingID, propName)
}

func (bg *BindingGenerator) generatePropertyCommandMapping(thingID, propName string) string {
	return fmt.Sprintf(`
# Process incoming property command
root.thing_id = "%s"
root.property_name = "%s"
root.value = this.value
root.command_id = uuid_v4()
root.timestamp = timestamp_unix_nano()
root.source = "http"
root.requester = this.requester.or("anonymous")
root.correlation_id = this.correlation_id.or(uuid_v4())

# Command metadata
root.command_type = "property_write"
root.target_device = "%s"
root.expected_response = true
`, thingID, propName, thingID)
}

func (bg *BindingGenerator) generateDeviceCommandMapping(thingID, propName string) string {
	return fmt.Sprintf(`
# Transform for device-specific protocol
root.device_id = "%s"
root.command = {
  "type": "set_property",
  "property": "%s",
  "value": this.value,
  "timestamp": this.timestamp,
  "command_id": this.command_id,
  "correlation_id": this.correlation_id
}

# Device protocol envelope
root.message_type = "command"
root.target = "%s"
root.reply_to = "twincore.responses." + this.correlation_id
root.expires_at = (timestamp_unix() + 30).ts_format("2006-01-02T15:04:05Z07:00")
`, thingID, propName, thingID)
}

func (bg *BindingGenerator) generateActionInvocationMapping(thingID, actionName string) string {
	return fmt.Sprintf(`
# Process incoming action invocation
root.thing_id = "%s"
root.action_name = "%s"
root.input = this.input
root.action_id = uuid_v4()
root.timestamp = timestamp_unix_nano()
root.source = "http"
root.requester = this.requester.or("anonymous")
root.correlation_id = this.correlation_id.or(uuid_v4())

# Action metadata
root.invocation_type = "action_invoke"
root.target_device = "%s"
root.expected_response = true
root.timeout = this.timeout.or(30)
`, thingID, actionName, thingID)
}

func (bg *BindingGenerator) generateDeviceActionMapping(thingID, actionName string) string {
	return fmt.Sprintf(`
# Transform for device-specific protocol
root.device_id = "%s"
root.command = {
  "type": "invoke_action",
  "action": "%s",
  "input": this.input,
  "timestamp": this.timestamp,
  "action_id": this.action_id,
  "correlation_id": this.correlation_id,
  "timeout": this.timeout
}

# Device protocol envelope
root.message_type = "action"
root.target = "%s"
root.reply_to = "twincore.responses." + this.correlation_id
root.expires_at = (timestamp_unix() + this.timeout).ts_format("2006-01-02T15:04:05Z07:00")
`, thingID, actionName, thingID)
}

func (bg *BindingGenerator) generateActionPersistenceMapping(thingID, actionName string) string {
	return fmt.Sprintf(`
# Normalize action data for persistence
root.thing_id = "%s"
root.action_name = "%s"
root.action_id = this.action_id
root.input = this.input
root.output = this.output
root.status = this.status.or("pending")
root.timestamp = timestamp_unix_nano()
root.duration_ms = this.duration_ms.or(0)
root.error = this.error
root.source = this.source.or("stream")
`, thingID, actionName)
}

func (bg *BindingGenerator) generateEventProcessingMapping(thingID, eventName string) string {
	return fmt.Sprintf(`
# Process incoming event for client distribution
root.thing_id = "%s"
root.event_name = "%s"
root.event_id = uuid_v4()
root.data = this.data
root.timestamp = timestamp_unix_nano()
root.source = this.source.or("device")
root.severity = this.severity.or("info")

# Event metadata for clients
root.event_type = "thing_event"
root.subscription_topic = "things.%s.events.%s"
`, thingID, eventName, thingID, eventName)
}

func (bg *BindingGenerator) generateEventEnrichmentMapping(thingID, eventName string) string {
	return fmt.Sprintf(`
# Enrich event data for client consumption
root.thing_id = "%s"
root.event_name = "%s"
root.event_id = this.event_id
root.data = this.data
root.timestamp = this.timestamp
root.source = this.source
root.severity = this.severity

# Client-specific enrichment
root.subscription_info = {
  "thing_id": "%s",
  "event_name": "%s",
  "client_format": "sse",
  "content_type": "application/json"
}

# Add SSE formatting for web clients
root.sse_data = "event: %s\\ndata: " + json.dumps(this) + "\\n\\n"
`, thingID, eventName, thingID, eventName, eventName)
}

func (bg *BindingGenerator) generateEventPersistenceMapping(thingID, eventName string) string {
	return fmt.Sprintf(`
# Normalize event data for persistence
root.thing_id = "%s"
root.event_name = "%s"
root.event_id = this.event_id.or(uuid_v4())
root.data = this.data
root.timestamp = timestamp_unix_nano()
root.severity = this.severity.or("info")
root.source = this.source.or("stream")
root.subscription_count = this.subscription_count.or(0)
`, thingID, eventName)
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

func (bg *BindingGenerator) generateActionParquetSchema() []map[string]interface{} {
	return []map[string]interface{}{
		{"name": "thing_id", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "action_name", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "action_id", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "input", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "OPTIONAL"},
		{"name": "output", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "OPTIONAL"},
		{"name": "status", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "timestamp", "type": "INT64", "converted_type": "TIMESTAMP_NANOS", "repetition_type": "REQUIRED"},
		{"name": "duration_ms", "type": "INT64", "converted_type": "TIMESTAMP_MILLIS", "repetition_type": "OPTIONAL"},
		{"name": "error", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "OPTIONAL"},
		{"name": "source", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
	}
}

func (bg *BindingGenerator) generateEventParquetSchema() []map[string]interface{} {
	return []map[string]interface{}{
		{"name": "thing_id", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "event_name", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "event_id", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "data", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "OPTIONAL"},
		{"name": "timestamp", "type": "INT64", "converted_type": "TIMESTAMP_NANOS", "repetition_type": "REQUIRED"},
		{"name": "severity", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "source", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "subscription_count", "type": "INT64", "converted_type": "INT_64", "repetition_type": "OPTIONAL"},
	}
}

// generateStreamRequestYAML generates complete YAML configuration for a stream request
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
				"mapping": bg.generatePropertyObservationMapping(thingID, propName),
			},
			Description: "Map property data for observation clients",
		},
	}

	// Add schema validation if property has a schema
	if prop.Type != "" {
		jsonSchema := bg.convertDataSchemaToJSONSchema(prop.DataSchemaCore)
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

	// Generate output configuration for observation (typically WebSocket/SSE)
	observationConfig := bg.licenseChecker.GetFeatureConfig("property_streaming")
	outputConfig, err := bg.generateObservationOutputConfig(thingID, propName, observationConfig)
	if err != nil {
		return fmt.Errorf("failed to generate observation output config: %w", err)
	}

	request := types.StreamCreationRequest{
		ThingID:         thingID,
		InteractionType: "properties",
		InteractionName: propName,
		Direction:       "output", // Property changes flow OUT to observers
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

	// Generate YAML configuration for the stream
	yamlConfig, err := bg.generateStreamRequestYAML(request)
	if err != nil {
		return fmt.Errorf("failed to generate YAML for property observation stream %s: %w", streamID, err)
	}

	request.Metadata["yaml_config"] = yamlConfig

	// Use existing stream manager to create stream
	streamInfo, err := bg.streamManager.CreateStream(context.Background(), request)
	if err != nil {
		return fmt.Errorf("failed to create property observation stream %s: %w", streamID, err)
	}

	// Convert StreamInfo to StreamConfig and store
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
		YAML:           "", // Would be generated by stream manager
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
	// License validation at app level
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

	// Create processor chain for property commands
	processorChainID := fmt.Sprintf("%s_command_processors", streamID)
	processors := []ProcessorConfig{
		{
			Type:  types.ProcessorBloblangWoTProperty,
			Label: "property_command_mapping",
			Config: map[string]interface{}{
				"mapping": bg.generatePropertyCommandMapping(thingID, propName),
			},
			Description: "Map property command data for device execution",
		},
	}

	// Add schema validation if property has a schema
	if prop.Type != "" {
		jsonSchema := bg.convertDataSchemaToJSONSchema(prop.DataSchemaCore)
		processors = append(processors, ProcessorConfig{
			Type:  types.ProcessorJSONSchema,
			Label: "property_command_validation",
			Config: map[string]interface{}{
				"schema": jsonSchema,
			},
			Description: "Validate property command against Thing Description schema",
		})
	}

	// Add command transformation for device protocol
	processors = append(processors, ProcessorConfig{
		Type:  types.ProcessorBloblangWoTProperty,
		Label: "device_command_transform",
		Config: map[string]interface{}{
			"mapping": bg.generateDeviceCommandMapping(thingID, propName),
		},
		Description: "Transform command for device-specific protocol",
	})

	// Store processor chain
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

	// Generate output configuration for commands (device communication)
	commandConfig := bg.licenseChecker.GetFeatureConfig("property_commands")
	outputConfig, err := bg.generateCommandOutputConfig(thingID, propName, commandConfig)
	if err != nil {
		return fmt.Errorf("failed to generate command output config: %w", err)
	}

	request := types.StreamCreationRequest{
		ThingID:         thingID,
		InteractionType: "properties",
		InteractionName: propName,
		Direction:       "input", // Commands flow IN from clients to devices
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

	// Generate YAML configuration for the stream
	yamlConfig, err := bg.generateStreamRequestYAML(request)
	if err != nil {
		return fmt.Errorf("failed to generate YAML for property command stream %s: %w", streamID, err)
	}

	request.Metadata["yaml_config"] = yamlConfig

	// Use existing stream manager to create stream
	streamInfo, err := bg.streamManager.CreateStream(context.Background(), request)
	if err != nil {
		return fmt.Errorf("failed to create property command stream %s: %w", streamID, err)
	}

	// Convert StreamInfo to StreamConfig and store
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
		YAML:           "", // Would be generated by stream manager
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
	// License validation should happen at app level before calling this method
	if !bg.licenseChecker.IsFeatureAvailable("data_persistence") {
		bg.logger.WithField("feature", "data_persistence").Debug("Persistence feature not available in license")
		return nil // Skip stream generation
	}

	streamID := fmt.Sprintf("%s_property_%s_persistence", thingID, propName)
	topic := fmt.Sprintf("things.%s.properties.%s", thingID, propName)

	bg.logger.WithFields(logrus.Fields{
		"stream_id": streamID,
		"thing_id":  thingID,
		"property":  propName,
		"topic":     topic,
	}).Debug("Generating property persistence stream")

	// Get persistence configuration from license
	persistenceConfig := bg.licenseChecker.GetFeatureConfig("data_persistence")
	
	// Create processor chain for data normalization only
	processorChainID := fmt.Sprintf("%s_persistence_processors", streamID)
	processors := []ProcessorConfig{
		{
			Type:  types.ProcessorBloblangWoTProperty,
			Label: "property_normalization",
			Config: map[string]interface{}{
				"mapping": bg.generatePropertyPersistenceMapping(thingID, propName),
			},
			Description: "Normalize property data for persistence",
		},
	}

	// Add format-specific processors based on persistence config
	if format, ok := persistenceConfig["format"].(string); ok {
		switch format {
		case "parquet":
			processors = append(processors, ProcessorConfig{
				Type:  types.ProcessorParquetEncode,
				Label: "parquet_encoding",
				Config: map[string]interface{}{
					"schema": bg.generatePropertyParquetSchema(),
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

	// Store processor chain
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

	// Generate output configuration based on persistence settings
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

	// Generate YAML configuration for the stream
	yamlConfig, err := bg.generateStreamRequestYAML(request)
	if err != nil {
		return fmt.Errorf("failed to generate YAML for property logging stream %s: %w", streamID, err)
	}

	// Add YAML to metadata
	request.Metadata["yaml_config"] = yamlConfig

	// Use existing stream manager to create stream
	streamInfo, err := bg.streamManager.CreateStream(context.Background(), request)
	if err != nil {
		return fmt.Errorf("failed to create property logging stream %s: %w", streamID, err)
	}

	// Convert StreamInfo to StreamConfig and store
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
		YAML:           "", // Would be generated by stream manager
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
	// License validation at app level
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

	// Create processor chain for action invocation
	processorChainID := fmt.Sprintf("%s_invocation_processors", streamID)
	processors := []ProcessorConfig{
		{
			Type:  types.ProcessorBloblangWoTAction,
			Label: "action_invocation_mapping",
			Config: map[string]interface{}{
				"mapping": bg.generateActionInvocationMapping(thingID, actionName),
			},
			Description: "Map action invocation data for device execution",
		},
	}

	// Add schema validation if action has input schema
	if action.Input != nil && action.Input.Type != "" {
		jsonSchema := bg.convertDataSchemaToJSONSchema(action.Input.DataSchemaCore)
		processors = append(processors, ProcessorConfig{
			Type:  types.ProcessorJSONSchema,
			Label: "action_input_validation",
			Config: map[string]interface{}{
				"schema": jsonSchema,
			},
			Description: "Validate action input against Thing Description schema",
		})
	}

	// Add command transformation for device protocol
	processors = append(processors, ProcessorConfig{
		Type:  types.ProcessorBloblangWoTAction,
		Label: "device_action_transform",
		Config: map[string]interface{}{
			"mapping": bg.generateDeviceActionMapping(thingID, actionName),
		},
		Description: "Transform action for device-specific protocol",
	})

	// Store processor chain
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

	// Generate output configuration for action invocation (device communication)
	invocationConfig := bg.licenseChecker.GetFeatureConfig("action_invocation")
	outputConfig, err := bg.generateActionOutputConfig(thingID, actionName, invocationConfig)
	if err != nil {
		return fmt.Errorf("failed to generate action output config: %w", err)
	}

	request := types.StreamCreationRequest{
		ThingID:         thingID,
		InteractionType: "actions",
		InteractionName: actionName,
		Direction:       "input", // Action invocations flow IN from clients to devices
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

	// Generate YAML configuration for the stream
	yamlConfig, err := bg.generateStreamRequestYAML(request)
	if err != nil {
		return fmt.Errorf("failed to generate YAML for action invocation stream %s: %w", streamID, err)
	}

	request.Metadata["yaml_config"] = yamlConfig

	// Use existing stream manager to create stream
	streamInfo, err := bg.streamManager.CreateStream(context.Background(), request)
	if err != nil {
		return fmt.Errorf("failed to create action invocation stream %s: %w", streamID, err)
	}

	// Convert StreamInfo to StreamConfig and store
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
		YAML:           "", // Would be generated by stream manager
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
	// License validation at app level
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

	// Get persistence configuration from license
	persistenceConfig := bg.licenseChecker.GetFeatureConfig("data_persistence")
	
	// Create processor chain for data normalization only
	processorChainID := fmt.Sprintf("%s_persistence_processors", streamID)
	processors := []ProcessorConfig{
		{
			Type:  types.ProcessorBloblangWoTAction,
			Label: "action_normalization",
			Config: map[string]interface{}{
				"mapping": bg.generateActionPersistenceMapping(thingID, actionName),
			},
			Description: "Normalize action data for persistence",
		},
	}

	// Add format-specific processors based on persistence config
	if format, ok := persistenceConfig["format"].(string); ok {
		switch format {
		case "parquet":
			processors = append(processors, ProcessorConfig{
				Type:  types.ProcessorParquetEncode,
				Label: "parquet_encoding",
				Config: map[string]interface{}{
					"schema": bg.generateActionParquetSchema(),
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

	// Store processor chain
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

	// Generate output configuration based on persistence settings
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

	// Generate YAML configuration for the stream
	yamlConfig, err := bg.generateStreamRequestYAML(request)
	if err != nil {
		return fmt.Errorf("failed to generate YAML for action logging stream %s: %w", streamID, err)
	}

	// Add YAML to metadata
	request.Metadata["yaml_config"] = yamlConfig

	// Use existing stream manager to create stream
	streamInfo, err := bg.streamManager.CreateStream(context.Background(), request)
	if err != nil {
		return fmt.Errorf("failed to create action logging stream %s: %w", streamID, err)
	}

	// Convert StreamInfo to StreamConfig and store
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
		YAML:           "", // Would be generated by stream manager
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
	// License validation at app level
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

	// Create processor chain for event processing
	processorChainID := fmt.Sprintf("%s_processing_processors", streamID)
	processors := []ProcessorConfig{
		{
			Type:  types.ProcessorBloblangWoTEvent,
			Label: "event_processing_mapping",
			Config: map[string]interface{}{
				"mapping": bg.generateEventProcessingMapping(thingID, eventName),
			},
			Description: "Map event data for client distribution",
		},
	}

	// Add schema validation if event has data schema
	if event.Data != nil && event.Data.Type != "" {
		jsonSchema := bg.convertDataSchemaToJSONSchema(event.Data.DataSchemaCore)
		processors = append(processors, ProcessorConfig{
			Type:  types.ProcessorJSONSchema,
			Label: "event_data_validation",
			Config: map[string]interface{}{
				"schema": jsonSchema,
			},
			Description: "Validate event data against Thing Description schema",
		})
	}

	// Add event enrichment and routing
	processors = append(processors, ProcessorConfig{
		Type:  types.ProcessorBloblangWoTEvent,
		Label: "event_enrichment",
		Config: map[string]interface{}{
			"mapping": bg.generateEventEnrichmentMapping(thingID, eventName),
		},
		Description: "Enrich event data for client consumption",
	})

	// Store processor chain
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

	// Generate output configuration for event distribution (SSE, WebSocket, etc.)
	processingConfig := bg.licenseChecker.GetFeatureConfig("event_processing")
	outputConfig, err := bg.generateEventOutputConfig(thingID, eventName, processingConfig)
	if err != nil {
		return fmt.Errorf("failed to generate event output config: %w", err)
	}

	request := types.StreamCreationRequest{
		ThingID:         thingID,
		InteractionType: "events",
		InteractionName: eventName,
		Direction:       "output", // Events flow OUT from devices to clients
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

	// Generate YAML configuration for the stream
	yamlConfig, err := bg.generateStreamRequestYAML(request)
	if err != nil {
		return fmt.Errorf("failed to generate YAML for event processing stream %s: %w", streamID, err)
	}

	request.Metadata["yaml_config"] = yamlConfig

	// Use existing stream manager to create stream
	streamInfo, err := bg.streamManager.CreateStream(context.Background(), request)
	if err != nil {
		return fmt.Errorf("failed to create event processing stream %s: %w", streamID, err)
	}

	// Convert StreamInfo to StreamConfig and store
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
		YAML:           "", // Would be generated by stream manager
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
	// License validation at app level
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

	// Get persistence configuration from license
	persistenceConfig := bg.licenseChecker.GetFeatureConfig("data_persistence")
	
	// Create processor chain for data normalization only
	processorChainID := fmt.Sprintf("%s_persistence_processors", streamID)
	processors := []ProcessorConfig{
		{
			Type:  types.ProcessorBloblangWoTEvent,
			Label: "event_normalization",
			Config: map[string]interface{}{
				"mapping": bg.generateEventPersistenceMapping(thingID, eventName),
			},
			Description: "Normalize event data for persistence",
		},
	}

	// Add format-specific processors based on persistence config
	if format, ok := persistenceConfig["format"].(string); ok {
		switch format {
		case "parquet":
			processors = append(processors, ProcessorConfig{
				Type:  types.ProcessorParquetEncode,
				Label: "parquet_encoding",
				Config: map[string]interface{}{
					"schema": bg.generateEventParquetSchema(),
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

	// Store processor chain
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

	// Generate output configuration based on persistence settings
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

	// Generate YAML configuration for the stream
	yamlConfig, err := bg.generateStreamRequestYAML(request)
	if err != nil {
		return fmt.Errorf("failed to generate YAML for event logging stream %s: %w", streamID, err)
	}

	// Add YAML to metadata
	request.Metadata["yaml_config"] = yamlConfig

	// Use existing stream manager to create stream
	streamInfo, err := bg.streamManager.CreateStream(context.Background(), request)
	if err != nil {
		return fmt.Errorf("failed to create event logging stream %s: %w", streamID, err)
	}

	// Convert StreamInfo to StreamConfig and store
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
		YAML:           "", // Would be generated by stream manager
	}

	bindings.Streams[streamID] = streamConfig

	bg.logger.WithFields(logrus.Fields{
		"stream_id":       streamInfo.ID,
		"stream_status":   streamInfo.Status,
		"processor_count": len(processors),
	}).Info("Event logging stream created successfully")

	return nil
}

// generatePersistenceOutputConfig creates output configuration based on persistence settings
func (bg *BindingGenerator) generatePersistenceOutputConfig(thingID, name string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	// Default to local file if no config provided
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
		return bg.generateLocalFileOutput(thingID, name, format)
	case "s3":
		return bg.generateS3Output(thingID, name, format, config)
	case "kafka":
		return bg.generateKafkaPersistenceOutput(thingID, name, config)
	case "noop":
		return types.StreamEndpointConfig{
			Type: "drop",
			Config: map[string]interface{}{},
		}, nil
	default:
		return types.StreamEndpointConfig{}, fmt.Errorf("unsupported sink type: %s", sinkType)
	}
}

// generateLocalFileOutput creates local file output configuration
func (bg *BindingGenerator) generateLocalFileOutput(thingID, name, format string) (types.StreamEndpointConfig, error) {
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

	filePath := fmt.Sprintf("%s/properties/%s_%s_${!timestamp_unix():yyyy-MM-dd}.%s",
		basePath, thingID, name, extension)

	return types.StreamEndpointConfig{
		Type: "file",
		Config: map[string]interface{}{
			"path":  filePath,
			"codec": "none",
		},
	}, nil
}

// generateS3Output creates S3 output configuration
func (bg *BindingGenerator) generateS3Output(thingID, name, format string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
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

	// Use environment variables for AWS credentials
	s3Config := map[string]interface{}{
		"bucket": bucket,
		"path":   fmt.Sprintf("twincore/properties/%s/%s/${!timestamp_unix():yyyy/MM/dd}/%s_${!uuid_v4()}.%s", thingID, name, name, extension),
		"region": "${AWS_REGION:us-east-1}",
		"credentials": map[string]interface{}{
			"id":     "${AWS_ACCESS_KEY_ID}",
			"secret": "${AWS_SECRET_ACCESS_KEY}",
			"token":  "${AWS_SESSION_TOKEN:}",
		},
	}

	// Add optional S3 configuration
	if region, ok := config["s3_region"].(string); ok {
		s3Config["region"] = region
	}

	return types.StreamEndpointConfig{
		Type:   "aws_s3",
		Config: s3Config,
	}, nil
}

// generateKafkaPersistenceOutput creates Kafka persistence output
func (bg *BindingGenerator) generateKafkaPersistenceOutput(thingID, name string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	persistenceTopic := fmt.Sprintf("twincore.persistence.%s.%s", thingID, name)
	if topic, ok := config["persistence_topic"].(string); ok {
		persistenceTopic = topic
	}

	return types.StreamEndpointConfig{
		Type: "kafka",
		Config: map[string]interface{}{
			"addresses": bg.kafkaConfig.Brokers,
			"topic":     persistenceTopic,
			"key":       fmt.Sprintf("${! this.thing_id }-%s", name),
		},
	}, nil
}

// convertToTypesProcessorConfig converts internal ProcessorConfig to types.ProcessorConfig
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

// generateObservationOutputConfig creates output configuration for property observation
func (bg *BindingGenerator) generateObservationOutputConfig(thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	// Default to WebSocket for real-time observation
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

// generateWebSocketObservationOutput creates WebSocket output for real-time property updates
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

// generateSSEObservationOutput creates Server-Sent Events output for property updates
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
			"timeout":           "0", // Keep-alive for SSE
			"stream_response":   true,
			"content_type":      "text/event-stream",
			"response_headers": map[string]string{
				"Cache-Control": "no-cache",
				"Connection":    "keep-alive",
			},
		},
	}, nil
}

// generateMQTTObservationOutput creates MQTT output for property observation
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

// generateKafkaObservationOutput creates Kafka output for property observation
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

// generateHTTPServerObservationOutput creates HTTP server output for polling-based observation
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

// generateCommandOutputConfig creates output configuration for property commands
func (bg *BindingGenerator) generateCommandOutputConfig(thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	// Default to Kafka for device communication
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

// generateKafkaCommandOutput creates Kafka output for device commands
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

// generateMQTTCommandOutput creates MQTT output for device commands
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

// generateHTTPClientCommandOutput creates HTTP client output for device commands
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

// generateWebSocketCommandOutput creates WebSocket output for device commands
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

// generateActionOutputConfig creates output configuration for action invocations
func (bg *BindingGenerator) generateActionOutputConfig(thingID, actionName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	// Default to Kafka for device communication
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

// generateKafkaActionOutput creates Kafka output for action invocations
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

// generateMQTTActionOutput creates MQTT output for action invocations
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

// generateHTTPClientActionOutput creates HTTP client output for action invocations
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

// generateWebSocketActionOutput creates WebSocket output for action invocations
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

// generateActionPersistenceOutputConfig creates output configuration for action persistence
func (bg *BindingGenerator) generateActionPersistenceOutputConfig(thingID, actionName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	// Default to local file if no config provided
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

// generateLocalActionFileOutput creates local file output for action persistence
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

// generateS3ActionOutput creates S3 output for action persistence
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

	// Use environment variables for AWS credentials
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

	// Add optional S3 configuration
	if region, ok := config["s3_region"].(string); ok {
		s3Config["region"] = region
	}

	return types.StreamEndpointConfig{
		Type:   "aws_s3",
		Config: s3Config,
	}, nil
}

// generateKafkaActionPersistenceOutput creates Kafka persistence output for actions
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

// generateEventOutputConfig creates output configuration for event processing
func (bg *BindingGenerator) generateEventOutputConfig(thingID, eventName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	// Default to Server-Sent Events for real-time event distribution
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

// generateSSEEventOutput creates Server-Sent Events output for real-time event distribution
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
			"timeout":           "0", // Keep-alive for SSE
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

// generateWebSocketEventOutput creates WebSocket output for real-time event distribution
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
			"timeout": "300s", // 5 minute timeout for event subscriptions
		},
	}, nil
}

// generateMQTTEventOutput creates MQTT output for event distribution
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

// generateKafkaEventOutput creates Kafka output for event distribution
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

// generateHTTPServerEventOutput creates HTTP server output for polling-based event access
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

// generateEventPersistenceOutputConfig creates output configuration for event persistence
func (bg *BindingGenerator) generateEventPersistenceOutputConfig(thingID, eventName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	// Default to local file if no config provided
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

// generateLocalEventFileOutput creates local file output for event persistence
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

// generateS3EventOutput creates S3 output for event persistence
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

	// Use environment variables for AWS credentials
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

	// Add optional S3 configuration
	if region, ok := config["s3_region"].(string); ok {
		s3Config["region"] = region
	}

	return types.StreamEndpointConfig{
		Type:   "aws_s3",
		Config: s3Config,
	}, nil
}

// generateKafkaEventPersistenceOutput creates Kafka persistence output for events
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
