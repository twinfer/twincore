package forms

import (
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
	streamManager  types.BenthosStreamManager
}

// LicenseChecker interface for checking feature availability
type LicenseChecker interface {
	IsFeatureEnabled(category, feature string) (bool, error)
	CheckLimit(resource string, currentCount int) (bool, error)
	GetAllowedFeatures() (map[string]interface{}, error)
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

	for propName, prop := range td.Properties {
		if err := bg.generatePropertyBindings(methodLogger, td.ID, propName, prop, bindings); err != nil {
			return nil, fmt.Errorf("failed to generate property bindings for %s: %w", propName, err)
		}
	}

	for actionName, action := range td.Actions {
		if err := bg.generateActionBindings(methodLogger, td.ID, actionName, action, bindings); err != nil {
			return nil, fmt.Errorf("failed to generate action bindings for %s: %w", actionName, err)
		}
	}

	for eventName, event := range td.Events {
		if err := bg.generateEventBindings(methodLogger, td.ID, eventName, event, bindings); err != nil {
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
	for i, form := range prop.Forms {
		routeID := fmt.Sprintf("%s_property_%s_form_%d", thingID, propName, i)
		route := HTTPRoute{
			Path:        strings.Replace(form.GetHref(), "{thingId}", thingID, -1),
			Method:      bg.getHTTPMethod(form.GetOp()),
			ContentType: form.GetContentType(),
		}
		bindings.HTTPRoutes[routeID] = route
	}

	if prop.IsObservable() && bg.licenseChecker.IsFeatureAvailable("property_streaming") {
		if err := generatePropertyObservationStream(opLogger, bg, thingID, propName, prop, bindings); err != nil {
			return err
		}
	}

	if !prop.IsReadOnly() && bg.licenseChecker.IsFeatureAvailable("property_commands") {
		if err := generatePropertyCommandStream(opLogger, bg, thingID, propName, prop, bindings); err != nil {
			return err
		}
	}

	if bg.licenseChecker.IsFeatureAvailable("data_persistence") {
		if err := generatePropertyLoggingStream(opLogger, bg, thingID, propName, prop, bindings); err != nil {
			return err
		}
	}
	return nil
}

// generateActionBindings creates all bindings for an action affordance
func (bg *BindingGenerator) generateActionBindings(logger logrus.FieldLogger, thingID, actionName string, action *wot.ActionAffordance, bindings *AllBindings) error {
	opLogger := logger.WithFields(logrus.Fields{"action_name": actionName, "operation": "generateActionBindings"})
	opLogger.Debug("Generating bindings for action")
	for i, form := range action.Forms {
		routeID := fmt.Sprintf("%s_action_%s_form_%d", thingID, actionName, i)
		route := HTTPRoute{
			Path:        strings.Replace(form.GetHref(), "{thingId}", thingID, -1),
			Method:      "POST",
			ContentType: form.GetContentType(),
		}
		bindings.HTTPRoutes[routeID] = route
	}

	if bg.licenseChecker.IsFeatureAvailable("action_invocation") {
		if err := generateActionInvocationStream(opLogger, bg, thingID, actionName, action, bindings); err != nil {
			return err
		}
	}

	if bg.licenseChecker.IsFeatureAvailable("data_persistence") {
		if err := generateActionLoggingStream(opLogger, bg, thingID, actionName, action, bindings); err != nil {
			return err
		}
	}
	return nil
}

// generateEventBindings creates all bindings for an event affordance
func (bg *BindingGenerator) generateEventBindings(logger logrus.FieldLogger, thingID, eventName string, event *wot.EventAffordance, bindings *AllBindings) error {
	opLogger := logger.WithFields(logrus.Fields{"event_name": eventName, "operation": "generateEventBindings"})
	opLogger.Debug("Generating bindings for event")
	for i, form := range event.Forms {
		routeID := fmt.Sprintf("%s_event_%s_form_%d", thingID, eventName, i)
		route := HTTPRoute{
			Path:        strings.Replace(form.GetHref(), "{thingId}", thingID, -1),
			Method:      "GET",
			ContentType: "text/event-stream",
		}
		bindings.HTTPRoutes[routeID] = route
	}

	if bg.licenseChecker.IsFeatureAvailable("event_processing") {
		if err := generateEventProcessingStream(opLogger, bg, thingID, eventName, event, bindings); err != nil {
			return err
		}
	}

	if bg.licenseChecker.IsFeatureAvailable("data_persistence") {
		if err := generateEventLoggingStream(opLogger, bg, thingID, eventName, event, bindings); err != nil {
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
	return "GET"
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
