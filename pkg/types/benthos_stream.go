package types

// BenthosStreamType represents the type of Benthos stream
type BenthosStreamType string

const (
	// Stream types based on WoT interactions
	StreamTypePropertyLogger BenthosStreamType = "property_logger"
	StreamTypeEventLogger    BenthosStreamType = "event_logger"
	StreamTypeActionLogger   BenthosStreamType = "action_logger"
	StreamTypePropertyInput  BenthosStreamType = "property_input"
	StreamTypePropertyOutput BenthosStreamType = "property_output"
	StreamTypeEventInput     BenthosStreamType = "event_input"
	StreamTypeEventOutput    BenthosStreamType = "event_output"
	StreamTypeActionInput    BenthosStreamType = "action_input"
	StreamTypeActionOutput   BenthosStreamType = "action_output"
)

// BenthosProcessorType represents types of Benthos processors
type BenthosProcessorType string

const (
	// WoT-specific processors
	ProcessorBloblangWoTProperty BenthosProcessorType = "bloblang_wot_property"
	ProcessorBloblangWoTAction   BenthosProcessorType = "bloblang_wot_action"
	ProcessorBloblangWoTEvent    BenthosProcessorType = "bloblang_wot_event"

	// Data format processors
	ProcessorJSONSchema    BenthosProcessorType = "json_schema"
	ProcessorJSONEncode    BenthosProcessorType = "json_encode"
	ProcessorParquetEncode BenthosProcessorType = "parquet_encode"
	ProcessorParquetDecode BenthosProcessorType = "parquet_decode"

	// License-aware processors
	ProcessorLicenseCheck BenthosProcessorType = "license_check"
)

// StreamDirection indicates data flow direction
type StreamDirection string

const (
	StreamDirectionInbound  StreamDirection = "inbound"  // Data coming into TwinCore
	StreamDirectionOutbound StreamDirection = "outbound" // Data going out from TwinCore
	StreamDirectionInternal StreamDirection = "internal" // Internal processing streams
)

// StreamProtocol represents the protocol used by a stream endpoint
type StreamProtocol string

const (
	ProtocolKafka     StreamProtocol = "kafka"
	ProtocolMQTT      StreamProtocol = "mqtt"
	ProtocolHTTP      StreamProtocol = "http"
	ProtocolWebSocket StreamProtocol = "websocket"
	ProtocolFile      StreamProtocol = "file"
	ProtocolInProc    StreamProtocol = "inproc" // In-process channels
)

// ParquetConfig holds configuration for Parquet file outputs
type ParquetConfig struct {
	BasePath        string `json:"base_path"`
	BatchSize       int    `json:"batch_size"`
	BatchPeriod     string `json:"batch_period"`
	BatchBytes      string `json:"batch_bytes"`
	Compression     string `json:"compression"`
	FileNamePattern string `json:"file_name_pattern"`
}

// KafkaConfig holds Kafka-specific configuration
type KafkaConfig struct {
	Brokers       []string          `json:"brokers"`
	Topic         string            `json:"topic"`
	ConsumerGroup string            `json:"consumer_group"`
	Partition     int               `json:"partition,omitempty"`
	Auth          map[string]string `json:"auth,omitempty"`
}

// MQTTConfig holds MQTT-specific configuration
type MQTTConfig struct {
	Broker   string `json:"broker"`
	Topic    string `json:"topic"`
	ClientID string `json:"client_id"`
	QoS      int    `json:"qos"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}
