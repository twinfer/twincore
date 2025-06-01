package forms

import (
	"fmt"
	"github.com/twinfer/twincore/pkg/types"
)

// generatePersistenceOutputConfig creates output configuration based on persistence settings
func generatePersistenceOutputConfig(bg *BindingGenerator, thingID, name string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
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
		return generateLocalFileOutput(bg, thingID, name, format)
	case "s3":
		return generateS3Output(bg, thingID, name, format, config)
	case "kafka":
		return generateKafkaPersistenceOutput(bg, thingID, name, config)
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
func generateLocalFileOutput(bg *BindingGenerator, thingID, name, format string) (types.StreamEndpointConfig, error) {
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

	basePath := bg.parquetConfig.BasePath // Assumes bg.parquetConfig is accessible
	if basePath == "" {
		basePath = "./twincore_data"
	}

	filePath := fmt.Sprintf("%s/properties/%s_%s_${!timestamp_unix():yyyy-MM-dd}.%s", // TODO: Generalize path beyond properties
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
func generateS3Output(bg *BindingGenerator, thingID, name, format string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
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
		"path":   fmt.Sprintf("twincore/properties/%s/%s/${!timestamp_unix():yyyy/MM/dd}/%s_${!uuid_v4()}.%s", thingID, name, name, extension), // TODO: Generalize path
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
func generateKafkaPersistenceOutput(bg *BindingGenerator, thingID, name string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	persistenceTopic := fmt.Sprintf("twincore.persistence.%s.%s", thingID, name)
	if topic, ok := config["persistence_topic"].(string); ok {
		persistenceTopic = topic
	}

	return types.StreamEndpointConfig{
		Type: "kafka",
		Config: map[string]interface{}{
			"addresses": bg.kafkaConfig.Brokers, // Assumes bg.kafkaConfig is accessible
			"topic":     persistenceTopic,
			"key":       fmt.Sprintf("${! this.thing_id }-%s", name),
		},
	}, nil
}

// generateObservationOutputConfig creates output configuration for property observation
func generateObservationOutputConfig(bg *BindingGenerator, thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	outputType := "websocket"
	if ot, ok := config["output_type"].(string); ok {
		outputType = ot
	}

	switch outputType {
	case "websocket":
		return generateWebSocketObservationOutput(bg, thingID, propName, config)
	case "sse", "server_sent_events":
		return generateSSEObservationOutput(bg, thingID, propName, config)
	case "mqtt":
		return generateMQTTObservationOutput(bg, thingID, propName, config)
	case "kafka":
		return generateKafkaObservationOutput(bg, thingID, propName, config)
	case "http_server":
		return generateHTTPServerObservationOutput(bg, thingID, propName, config)
	default:
		return types.StreamEndpointConfig{}, fmt.Errorf("unsupported observation output type: %s", outputType)
	}
}

func generateWebSocketObservationOutput(bg *BindingGenerator, thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
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

func generateSSEObservationOutput(bg *BindingGenerator, thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
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

func generateMQTTObservationOutput(bg *BindingGenerator, thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	topic := fmt.Sprintf("things/%s/properties/%s/observe", thingID, propName)
	if customTopic, ok := config["mqtt_topic"].(string); ok {
		topic = customTopic
	}

	return types.StreamEndpointConfig{
		Type: "mqtt",
		Config: map[string]interface{}{
			"urls":      []string{bg.mqttConfig.Broker}, // Assumes bg.mqttConfig is accessible
			"topic":     topic,
			"client_id": fmt.Sprintf("twincore-observer-%s-%s", thingID, propName),
			"qos":       1,
		},
	}, nil
}

func generateKafkaObservationOutput(bg *BindingGenerator, thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	topic := fmt.Sprintf("twincore.observations.%s.%s", thingID, propName)
	if customTopic, ok := config["kafka_topic"].(string); ok {
		topic = customTopic
	}

	return types.StreamEndpointConfig{
		Type: "kafka",
		Config: map[string]interface{}{
			"addresses": bg.kafkaConfig.Brokers, // Assumes bg.kafkaConfig is accessible
			"topic":     topic,
			"key":       fmt.Sprintf("${! this.thing_id }-%s", propName),
		},
	}, nil
}

func generateHTTPServerObservationOutput(bg *BindingGenerator, thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
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

func generateCommandOutputConfig(bg *BindingGenerator, thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	outputType := "kafka"
	if ot, ok := config["output_type"].(string); ok {
		outputType = ot
	}

	switch outputType {
	case "kafka":
		return generateKafkaCommandOutput(bg, thingID, propName, config)
	case "mqtt":
		return generateMQTTCommandOutput(bg, thingID, propName, config)
	case "http_client":
		return generateHTTPClientCommandOutput(bg, thingID, propName, config)
	case "websocket":
		return generateWebSocketCommandOutput(bg, thingID, propName, config)
	default:
		return types.StreamEndpointConfig{}, fmt.Errorf("unsupported command output type: %s", outputType)
	}
}

func generateKafkaCommandOutput(bg *BindingGenerator, thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	topic := fmt.Sprintf("twincore.commands.%s", thingID)
	if customTopic, ok := config["kafka_topic"].(string); ok {
		topic = customTopic
	}

	return types.StreamEndpointConfig{
		Type: "kafka",
		Config: map[string]interface{}{
			"addresses": bg.kafkaConfig.Brokers, // Assumes bg.kafkaConfig is accessible
			"topic":     topic,
			"key":       fmt.Sprintf("${! this.device_id }"),
		},
	}, nil
}

func generateMQTTCommandOutput(bg *BindingGenerator, thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	topic := fmt.Sprintf("devices/%s/commands", thingID)
	if customTopic, ok := config["mqtt_topic"].(string); ok {
		topic = customTopic
	}

	return types.StreamEndpointConfig{
		Type: "mqtt",
		Config: map[string]interface{}{
			"urls":      []string{bg.mqttConfig.Broker}, // Assumes bg.mqttConfig is accessible
			"topic":     topic,
			"client_id": fmt.Sprintf("twincore-commands-%s", thingID),
			"qos":       1,
		},
	}, nil
}

func generateHTTPClientCommandOutput(bg *BindingGenerator, thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
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

func generateWebSocketCommandOutput(bg *BindingGenerator, thingID, propName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
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

func generateActionOutputConfig(bg *BindingGenerator, thingID, actionName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	outputType := "kafka"
	if ot, ok := config["output_type"].(string); ok {
		outputType = ot
	}

	switch outputType {
	case "kafka":
		return generateKafkaActionOutput(bg, thingID, actionName, config)
	case "mqtt":
		return generateMQTTActionOutput(bg, thingID, actionName, config)
	case "http_client":
		return generateHTTPClientActionOutput(bg, thingID, actionName, config)
	case "websocket":
		return generateWebSocketActionOutput(bg, thingID, actionName, config)
	default:
		return types.StreamEndpointConfig{}, fmt.Errorf("unsupported action output type: %s", outputType)
	}
}

func generateKafkaActionOutput(bg *BindingGenerator, thingID, actionName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	topic := fmt.Sprintf("twincore.actions.%s", thingID)
	if customTopic, ok := config["kafka_topic"].(string); ok {
		topic = customTopic
	}

	return types.StreamEndpointConfig{
		Type: "kafka",
		Config: map[string]interface{}{
			"addresses": bg.kafkaConfig.Brokers, // Assumes bg.kafkaConfig is accessible
			"topic":     topic,
			"key":       fmt.Sprintf("${! this.device_id }"),
		},
	}, nil
}

func generateMQTTActionOutput(bg *BindingGenerator, thingID, actionName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	topic := fmt.Sprintf("devices/%s/actions", thingID)
	if customTopic, ok := config["mqtt_topic"].(string); ok {
		topic = customTopic
	}

	return types.StreamEndpointConfig{
		Type: "mqtt",
		Config: map[string]interface{}{
			"urls":      []string{bg.mqttConfig.Broker}, // Assumes bg.mqttConfig is accessible
			"topic":     topic,
			"client_id": fmt.Sprintf("twincore-actions-%s", thingID),
			"qos":       1,
		},
	}, nil
}

func generateHTTPClientActionOutput(bg *BindingGenerator, thingID, actionName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
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

func generateWebSocketActionOutput(bg *BindingGenerator, thingID, actionName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
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

func generateActionPersistenceOutputConfig(bg *BindingGenerator, thingID, actionName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
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
		return generateLocalActionFileOutput(bg, thingID, actionName, format)
	case "s3":
		return generateS3ActionOutput(bg, thingID, actionName, format, config) // Corrected: generateS3ActionOutput
	case "kafka":
		return generateKafkaActionPersistenceOutput(bg, thingID, actionName, config)
	case "noop":
		return types.StreamEndpointConfig{
			Type:   "drop",
			Config: map[string]interface{}{},
		}, nil
	default:
		return types.StreamEndpointConfig{}, fmt.Errorf("unsupported action persistence sink type: %s", sinkType)
	}
}

func generateLocalActionFileOutput(bg *BindingGenerator, thingID, actionName, format string) (types.StreamEndpointConfig, error) {
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

	basePath := bg.parquetConfig.BasePath // Assumes bg.parquetConfig is accessible
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

func generateS3ActionOutput(bg *BindingGenerator, thingID, actionName, format string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
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

func generateKafkaActionPersistenceOutput(bg *BindingGenerator, thingID, actionName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	persistenceTopic := fmt.Sprintf("twincore.persistence.%s.%s", thingID, actionName) // TODO: Check if this topic structure is intended for actions too
	if topic, ok := config["persistence_topic"].(string); ok {
		persistenceTopic = topic
	}

	return types.StreamEndpointConfig{
		Type: "kafka",
		Config: map[string]interface{}{
			"addresses": bg.kafkaConfig.Brokers, // Assumes bg.kafkaConfig is accessible
			"topic":     persistenceTopic,
			"key":       fmt.Sprintf("${! this.thing_id }-%s", actionName),
		},
	}, nil
}

func generateEventOutputConfig(bg *BindingGenerator, thingID, eventName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	outputType := "sse"
	if ot, ok := config["output_type"].(string); ok {
		outputType = ot
	}

	switch outputType {
	case "sse", "server_sent_events":
		return generateSSEEventOutput(bg, thingID, eventName, config)
	case "websocket":
		return generateWebSocketEventOutput(bg, thingID, eventName, config)
	case "mqtt":
		return generateMQTTEventOutput(bg, thingID, eventName, config)
	case "kafka":
		return generateKafkaEventOutput(bg, thingID, eventName, config)
	case "http_server":
		return generateHTTPServerEventOutput(bg, thingID, eventName, config)
	default:
		return types.StreamEndpointConfig{}, fmt.Errorf("unsupported event output type: %s", outputType)
	}
}

func generateSSEEventOutput(bg *BindingGenerator, thingID, eventName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
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

func generateWebSocketEventOutput(bg *BindingGenerator, thingID, eventName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
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

func generateMQTTEventOutput(bg *BindingGenerator, thingID, eventName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	topic := fmt.Sprintf("things/%s/events/%s", thingID, eventName)
	if customTopic, ok := config["mqtt_topic"].(string); ok {
		topic = customTopic
	}

	return types.StreamEndpointConfig{
		Type: "mqtt",
		Config: map[string]interface{}{
			"urls":      []string{bg.mqttConfig.Broker}, // Assumes bg.mqttConfig is accessible
			"topic":     topic,
			"client_id": fmt.Sprintf("twincore-events-%s-%s", thingID, eventName),
			"qos":       1,
		},
	}, nil
}

func generateKafkaEventOutput(bg *BindingGenerator, thingID, eventName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	topic := fmt.Sprintf("twincore.events.%s.%s", thingID, eventName)
	if customTopic, ok := config["kafka_topic"].(string); ok {
		topic = customTopic
	}

	return types.StreamEndpointConfig{
		Type: "kafka",
		Config: map[string]interface{}{
			"addresses": bg.kafkaConfig.Brokers, // Assumes bg.kafkaConfig is accessible
			"topic":     topic,
			"key":       fmt.Sprintf("${! this.thing_id }-%s", eventName),
		},
	}, nil
}

func generateHTTPServerEventOutput(bg *BindingGenerator, thingID, eventName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
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

func generateEventPersistenceOutputConfig(bg *BindingGenerator, thingID, eventName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
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
		return generateLocalEventFileOutput(bg, thingID, eventName, format)
	case "s3":
		return generateS3EventOutput(bg, thingID, eventName, format, config) // Corrected: generateS3EventOutput
	case "kafka":
		return generateKafkaEventPersistenceOutput(bg, thingID, eventName, config)
	case "noop":
		return types.StreamEndpointConfig{
			Type:   "drop",
			Config: map[string]interface{}{},
		}, nil
	default:
		return types.StreamEndpointConfig{}, fmt.Errorf("unsupported event persistence sink type: %s", sinkType)
	}
}

func generateLocalEventFileOutput(bg *BindingGenerator, thingID, eventName, format string) (types.StreamEndpointConfig, error) {
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

	basePath := bg.parquetConfig.BasePath // Assumes bg.parquetConfig is accessible
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

func generateS3EventOutput(bg *BindingGenerator, thingID, eventName, format string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
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

func generateKafkaEventPersistenceOutput(bg *BindingGenerator, thingID, eventName string, config map[string]interface{}) (types.StreamEndpointConfig, error) {
	persistenceTopic := fmt.Sprintf("twincore.persistence.%s.%s", thingID, eventName) // TODO: Check if this topic structure is intended for events too
	if topic, ok := config["persistence_topic"].(string); ok {
		persistenceTopic = topic
	}

	return types.StreamEndpointConfig{
		Type: "kafka",
		Config: map[string]interface{}{
			"addresses": bg.kafkaConfig.Brokers, // Assumes bg.kafkaConfig is accessible
			"topic":     persistenceTopic,
			"key":       fmt.Sprintf("${! this.thing_id }-%s", eventName),
		},
	}, nil
}
