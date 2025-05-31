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
		case string(types.ProcessorLicenseCheck):
			feature := proc.Config["feature"].(string)
			lines = append(lines, fmt.Sprintf(`    - label: "license_check_%s"
      license_check:
        feature: "%s"`, feature, feature))

		case string(types.ProcessorBloblangWoTProperty):
			mapping := proc.Config["mapping"].(string)
			lines = append(lines, fmt.Sprintf(`    - label: "format_wot_property"
      mapping: |%s`, indentString(mapping, "        ")))

		case string(types.ProcessorParquetEncode):
			schema := proc.Config["schema"].([]map[string]interface{})
			schemaYAML := bg.generateParquetSchemaYAML(schema)
			lines = append(lines, fmt.Sprintf(`    - label: "encode_parquet"
      parquet_encode:
        schema:
%s`, schemaYAML))

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
	// Implementation similar to generatePropertyLoggingStream but for observation
	return nil
}

func (bg *BindingGenerator) generatePropertyCommandStream(thingID, propName string, prop *wot.PropertyAffordance, bindings *AllBindings) error {
	// Implementation for property command streams
	return nil
}

func (bg *BindingGenerator) generatePropertyLoggingStream(thingID, propName string, prop *wot.PropertyAffordance, bindings *AllBindings) error {
	streamID := fmt.Sprintf("%s_property_%s_logging", thingID, propName)
	topic := fmt.Sprintf("things.%s.properties.%s", thingID, propName)

	bg.logger.WithFields(logrus.Fields{
		"stream_id": streamID,
		"thing_id":  thingID,
		"property":  propName,
		"topic":     topic,
	}).Debug("Generating property logging stream")

	// Create processor chain with license check and Parquet encoding
	processorChainID := fmt.Sprintf("%s_logging_processors", streamID)
	processors := []ProcessorConfig{
		{
			Type:  types.ProcessorLicenseCheck,
			Label: "license_validation",
			Config: map[string]interface{}{
				"feature": "parquet_logging",
			},
			Description: "Validate license allows Parquet logging",
		},
		{
			Type:  types.ProcessorBloblangWoTProperty,
			Label: "property_normalization",
			Config: map[string]interface{}{
				"mapping": bg.generatePropertyLoggingMapping(thingID, propName),
			},
			Description: "Normalize property data for logging",
		},
		{
			Type:  types.ProcessorParquetEncode,
			Label: "parquet_encoding",
			Config: map[string]interface{}{
				"schema": bg.generatePropertyParquetSchema(),
			},
			Description: "Encode property data to Parquet format",
		},
	}

	// Store processor chain
	bindings.Processors[processorChainID] = ProcessorChain{
		ID:         processorChainID,
		Name:       fmt.Sprintf("Property %s logging processors", propName),
		Processors: processors,
		Metadata: map[string]interface{}{
			"thing_id":         thingID,
			"property_name":    propName,
			"interaction_type": "property",
			"purpose":          "logging",
		},
	}

	// Create StreamCreationRequest using existing API
	filePath := fmt.Sprintf("%s/properties/props_%s_%s.parquet",
		bg.parquetConfig.BasePath, thingID, "${!timestamp_unix():yyyy-MM-dd}")

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
				"consumer_group": fmt.Sprintf("twincore-property-logger-%s", thingID),
			},
		},
		Output: types.StreamEndpointConfig{
			Type: "file",
			Config: map[string]interface{}{
				"path":  filePath,
				"codec": "none",
			},
		},
		ProcessorChain: []types.ProcessorConfig{
			{
				Type: string(types.ProcessorLicenseCheck),
				Config: map[string]interface{}{
					"feature": "parquet_logging",
				},
			},
			{
				Type: string(types.ProcessorBloblangWoTProperty),
				Config: map[string]interface{}{
					"mapping": bg.generatePropertyLoggingMapping(thingID, propName),
				},
			},
			{
				Type: string(types.ProcessorParquetEncode),
				Config: map[string]interface{}{
					"schema": bg.generatePropertyParquetSchema(),
				},
			},
		},
		Metadata: map[string]interface{}{
			"generated_by": "centralized_binding_generator",
			"purpose":      "property_logging",
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
