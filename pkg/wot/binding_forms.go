package wot

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// W3C WoT Binding Template compliant form implementations

// HTTPHeader represents an HTTP header with W3C vocabulary
type HTTPHeader struct {
	FieldName  string `json:"htv:fieldName"`
	FieldValue string `json:"htv:fieldValue"`
}

// HTTPForm implements W3C HTTP Binding Template
type HTTPForm struct {
	// Base form properties
	Op           []string               `json:"op,omitempty"`
	Href         string                 `json:"href"`
	ContentType  string                 `json:"contentType,omitempty"`
	Security     []string               `json:"security,omitempty"`
	Response     *ExpectedResponse      `json:"response,omitempty"`
	URIVariables map[string]*DataSchema `json:"uriVariables,omitempty"`
	Subprotocol  string                 `json:"subprotocol,omitempty"`

	// HTTP vocabulary (htv namespace)
	MethodName       string       `json:"htv:methodName,omitempty"`       // GET, POST, PUT, DELETE, PATCH
	Headers          []HTTPHeader `json:"htv:headers,omitempty"`
	StatusCodeNumber *int         `json:"htv:statusCodeNumber,omitempty"` // Expected status code
	StatusCodeValue  string       `json:"htv:statusCodeValue,omitempty"`  // Expected status text
}

func (f *HTTPForm) GetOp() []string                         { return f.Op }
func (f *HTTPForm) GetHref() string                         { return f.Href }
func (f *HTTPForm) GetContentType() string                  { return f.ContentType }
func (f *HTTPForm) GetSecurity() []string                   { return f.Security }
func (f *HTTPForm) GetResponse() *ExpectedResponse          { return f.Response }
func (f *HTTPForm) GetURIVariables() map[string]*DataSchema { return f.URIVariables }
func (f *HTTPForm) GetSubprotocol() string                  { return f.Subprotocol }
func (f *HTTPForm) GetProtocol() string                     { return "http" }

func (f *HTTPForm) GenerateConfig(securityDefs map[string]SecurityScheme) (map[string]any, error) {
	config := map[string]any{
		"url":         f.Href,
		"method":      f.getHTTPMethod(),
		"contentType": f.ContentType,
	}

	// Add headers from W3C vocabulary
	if len(f.Headers) > 0 {
		headers := make(map[string]string)
		for _, header := range f.Headers {
			headers[header.FieldName] = header.FieldValue
		}
		config["headers"] = headers
	}

	return config, nil
}

func (f *HTTPForm) getHTTPMethod() string {
	if f.MethodName != "" {
		return f.MethodName
	}
	// Fallback: infer from operation
	if len(f.Op) > 0 {
		switch f.Op[0] {
		case "readproperty":
			return "GET"
		case "writeproperty":
			return "PUT"
		case "invokeaction":
			return "POST"
		case "subscribeevent", "unsubscribeevent":
			return "GET"
		}
	}
	return "GET"
}

// MQTTForm implements W3C MQTT Binding Template
type MQTTForm struct {
	// Base form properties
	Op           []string               `json:"op,omitempty"`
	Href         string                 `json:"href"`
	ContentType  string                 `json:"contentType,omitempty"`
	Security     []string               `json:"security,omitempty"`
	Response     *ExpectedResponse      `json:"response,omitempty"`
	URIVariables map[string]*DataSchema `json:"uriVariables,omitempty"`
	Subprotocol  string                 `json:"subprotocol,omitempty"`

	// MQTT vocabulary (mqv namespace)
	ControlPacket string `json:"mqv:controlPacket,omitempty"` // publish, subscribe, unsubscribe
	QoS           string `json:"mqv:qos,omitempty"`           // "0", "1", "2"
	Retain        *bool  `json:"mqv:retain,omitempty"`
	Topic         string `json:"mqv:topic,omitempty"`
	Filter        string `json:"mqv:filter,omitempty"`
}

func (f *MQTTForm) GetOp() []string                         { return f.Op }
func (f *MQTTForm) GetHref() string                         { return f.Href }
func (f *MQTTForm) GetContentType() string                  { return f.ContentType }
func (f *MQTTForm) GetSecurity() []string                   { return f.Security }
func (f *MQTTForm) GetResponse() *ExpectedResponse          { return f.Response }
func (f *MQTTForm) GetURIVariables() map[string]*DataSchema { return f.URIVariables }
func (f *MQTTForm) GetSubprotocol() string                  { return f.Subprotocol }
func (f *MQTTForm) GetProtocol() string                     { return "mqtt" }

func (f *MQTTForm) GenerateConfig(securityDefs map[string]SecurityScheme) (map[string]any, error) {
	config := map[string]any{
		"urls":   []string{f.Href},
		"topics": []string{f.getTopic()},
		"qos":    f.getQoS(),
	}

	if f.Retain != nil {
		config["retain"] = *f.Retain
	}

	return config, nil
}

func (f *MQTTForm) getTopic() string {
	if f.Topic != "" {
		return f.Topic
	}
	if f.Filter != "" {
		return f.Filter
	}
	// Extract topic from MQTT URL
	if strings.HasPrefix(f.Href, "mqtt://") || strings.HasPrefix(f.Href, "mqtts://") {
		parts := strings.Split(f.Href, "/")
		if len(parts) > 3 {
			return strings.Join(parts[3:], "/")
		}
	}
	return "default/topic"
}

func (f *MQTTForm) getQoS() int {
	switch f.QoS {
	case "1":
		return 1
	case "2":
		return 2
	default:
		return 0
	}
}

// ValidateControlPacket validates that the control packet matches the WoT operation
func (f *MQTTForm) ValidateControlPacket() error {
	if f.ControlPacket == "" {
		return nil // No validation if not specified
	}

	if len(f.Op) == 0 {
		return nil // No validation if no operations specified
	}

	operation := f.Op[0] // Check first operation
	
	switch f.ControlPacket {
	case "publish":
		// Publish is valid for operations that send data to the device
		validOps := []string{"writeproperty", "invokeaction"}
		if !slices.Contains(validOps, operation) {
			return fmt.Errorf("mqv:controlPacket 'publish' is not compatible with operation '%s'", operation)
		}
		
	case "subscribe":
		// Subscribe is valid for operations that receive data from the device
		validOps := []string{"readproperty", "observeproperty", "subscribeevent"}
		if !slices.Contains(validOps, operation) {
			return fmt.Errorf("mqv:controlPacket 'subscribe' is not compatible with operation '%s'", operation)
		}
		
	case "unsubscribe":
		// Unsubscribe is valid for stopping observations/subscriptions
		validOps := []string{"unobserveproperty", "unsubscribeevent"}
		if !slices.Contains(validOps, operation) {
			return fmt.Errorf("mqv:controlPacket 'unsubscribe' is not compatible with operation '%s'", operation)
		}
		
	default:
		return fmt.Errorf("invalid mqv:controlPacket value: %s", f.ControlPacket)
	}
	
	return nil
}

// WebSocketForm implements W3C WebSocket Binding Template (for future NATS integration)
type WebSocketForm struct {
	// Base form properties
	Op           []string               `json:"op,omitempty"`
	Href         string                 `json:"href"`
	ContentType  string                 `json:"contentType,omitempty"`
	Security     []string               `json:"security,omitempty"`
	Response     *ExpectedResponse      `json:"response,omitempty"`
	URIVariables map[string]*DataSchema `json:"uriVariables,omitempty"`
	Subprotocol  string                 `json:"subprotocol,omitempty"`

	// WebSocket vocabulary (wsv namespace) - future extension
	KeepAlive        *int  `json:"wsv:keepAlive,omitempty"`        // Keep-alive interval in seconds
	PingInterval     *int  `json:"wsv:pingInterval,omitempty"`     // Ping interval in seconds
	MaxMessageSize   *int  `json:"wsv:maxMessageSize,omitempty"`   // Maximum message size in bytes
	CompressionLevel *int  `json:"wsv:compressionLevel,omitempty"` // Compression level (0-9)
	
	// NATS-specific fields (for future use)
	NATSSubject string `json:"nats:subject,omitempty"` // NATS subject for WebSocket bridging
	NATSQueue   string `json:"nats:queue,omitempty"`   // NATS queue group
}

func (f *WebSocketForm) GetOp() []string                         { return f.Op }
func (f *WebSocketForm) GetHref() string                         { return f.Href }
func (f *WebSocketForm) GetContentType() string                  { return f.ContentType }
func (f *WebSocketForm) GetSecurity() []string                   { return f.Security }
func (f *WebSocketForm) GetResponse() *ExpectedResponse          { return f.Response }
func (f *WebSocketForm) GetURIVariables() map[string]*DataSchema { return f.URIVariables }
func (f *WebSocketForm) GetSubprotocol() string                  { return f.Subprotocol }
func (f *WebSocketForm) GetProtocol() string                     { return "ws" }

func (f *WebSocketForm) GenerateConfig(securityDefs map[string]SecurityScheme) (map[string]any, error) {
	config := map[string]any{
		"url":         f.Href,
		"subprotocol": f.Subprotocol,
	}

	// Add WebSocket-specific configuration
	if f.KeepAlive != nil {
		config["keep_alive"] = *f.KeepAlive
	}

	if f.PingInterval != nil {
		config["ping_interval"] = *f.PingInterval
	}

	if f.MaxMessageSize != nil {
		config["max_message_size"] = *f.MaxMessageSize
	}

	// NATS bridging configuration (for future implementation)
	if f.NATSSubject != "" {
		config["nats_subject"] = f.NATSSubject
	}

	if f.NATSQueue != "" {
		config["nats_queue"] = f.NATSQueue
	}

	return config, nil
}

// ValidateSubprotocol validates WebSocket subprotocol against IANA registry
func (f *WebSocketForm) ValidateSubprotocol() error {
	if f.Subprotocol == "" {
		return nil // No validation if not specified
	}

	// IANA-registered WebSocket subprotocols for IoT/WoT
	// https://www.iana.org/assignments/websocket/websocket.xml
	ianaSubprotocols := []string{
		"wamp",            // Web Application Messaging Protocol
		"mqtt",            // MQTT over WebSocket  
		"amqp",            // AMQP over WebSocket
		"coap",            // CoAP over WebSocket
		"opcua+uacp",      // OPC UA Binary Protocol over WebSocket
		"opcua+uajson",    // OPC UA JSON Protocol over WebSocket
	}

	// Custom TwinCore subprotocols for WoT binding alignment
	customSubprotocols := []string{
		"kafka",           // Kafka over WebSocket (TwinCore custom)
		"nats",            // NATS over WebSocket (TwinCore custom)
	}

	// Check against IANA registry first
	if slices.Contains(ianaSubprotocols, f.Subprotocol) {
		return nil
	}

	// Check against custom subprotocols
	if slices.Contains(customSubprotocols, f.Subprotocol) {
		return nil
	}

	// Unknown subprotocol - warn but don't fail completely
	return fmt.Errorf("unknown WebSocket subprotocol: %s (not in IANA registry or TwinCore custom)", f.Subprotocol)
}

// KafkaForm implements custom Kafka binding (following W3C pattern)
type KafkaForm struct {
	// Base form properties
	Op           []string               `json:"op,omitempty"`
	Href         string                 `json:"href"`
	ContentType  string                 `json:"contentType,omitempty"`
	Security     []string               `json:"security,omitempty"`
	Response     *ExpectedResponse      `json:"response,omitempty"`
	URIVariables map[string]*DataSchema `json:"uriVariables,omitempty"`
	Subprotocol  string                 `json:"subprotocol,omitempty"`

	// Kafka vocabulary (kfv namespace - custom extension)
	Topic         string            `json:"kfv:topic"`
	Partition     *int              `json:"kfv:partition,omitempty"`
	ConsumerGroup string            `json:"kfv:consumerGroup,omitempty"`
	Key           string            `json:"kfv:key,omitempty"`
	Headers       map[string]string `json:"kfv:headers,omitempty"`
}

func (f *KafkaForm) GetOp() []string                         { return f.Op }
func (f *KafkaForm) GetHref() string                         { return f.Href }
func (f *KafkaForm) GetContentType() string                  { return f.ContentType }
func (f *KafkaForm) GetSecurity() []string                   { return f.Security }
func (f *KafkaForm) GetResponse() *ExpectedResponse          { return f.Response }
func (f *KafkaForm) GetURIVariables() map[string]*DataSchema { return f.URIVariables }
func (f *KafkaForm) GetSubprotocol() string                  { return f.Subprotocol }
func (f *KafkaForm) GetProtocol() string                     { return "kafka" }

func (f *KafkaForm) GenerateConfig(securityDefs map[string]SecurityScheme) (map[string]any, error) {
	config := map[string]any{
		"topic": f.Topic,
	}

	if f.Partition != nil {
		config["partition"] = *f.Partition
	}

	if f.ConsumerGroup != "" {
		config["consumer_group"] = f.ConsumerGroup
	}

	// Extract broker addresses from URL
	if f.Href != "" {
		addresses, err := f.extractKafkaBrokers()
		if err == nil {
			config["addresses"] = addresses
		}
	}

	return config, nil
}

func (f *KafkaForm) extractKafkaBrokers() ([]string, error) {
	if !strings.HasPrefix(f.Href, "kafka://") {
		return nil, fmt.Errorf("invalid Kafka URL: %s", f.Href)
	}

	// Parse kafka://broker1:9092,broker2:9092/topic
	url := strings.TrimPrefix(f.Href, "kafka://")
	parts := strings.Split(url, "/")
	if len(parts) < 1 {
		return nil, fmt.Errorf("invalid Kafka URL format")
	}

	brokers := strings.Split(parts[0], ",")
	return brokers, nil
}

// FormParser helps parse generic forms into protocol-specific forms
type FormParser struct{}

// ParseForm attempts to parse a generic form map into a protocol-specific form
func (p *FormParser) ParseForm(formData map[string]any) (Form, error) {
	// Detect protocol based on vocabulary presence
	if _, hasHTTPMethod := formData["htv:methodName"]; hasHTTPMethod {
		return p.parseHTTPForm(formData)
	}

	if _, hasMQTTControl := formData["mqv:controlPacket"]; hasMQTTControl {
		return p.parseMQTTForm(formData)
	}

	if _, hasKafkaTopic := formData["kfv:topic"]; hasKafkaTopic {
		return p.parseKafkaForm(formData)
	}

	if _, hasWebSocketKeepAlive := formData["wsv:keepAlive"]; hasWebSocketKeepAlive {
		return p.parseWebSocketForm(formData)
	}

	// Fallback to href-based detection
	if href, ok := formData["href"].(string); ok {
		switch {
		case strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://"):
			return p.parseHTTPForm(formData)
		case strings.HasPrefix(href, "mqtt://") || strings.HasPrefix(href, "mqtts://"):
			return p.parseMQTTForm(formData)
		case strings.HasPrefix(href, "kafka://"):
			return p.parseKafkaForm(formData)
		case strings.HasPrefix(href, "ws://") || strings.HasPrefix(href, "wss://"):
			return p.parseWebSocketForm(formData)
		}
	}

	return nil, fmt.Errorf("unable to determine form protocol")
}

func (p *FormParser) parseHTTPForm(data map[string]any) (*HTTPForm, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	var form HTTPForm
	err = json.Unmarshal(jsonData, &form)
	return &form, err
}

func (p *FormParser) parseMQTTForm(data map[string]any) (*MQTTForm, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	var form MQTTForm
	err = json.Unmarshal(jsonData, &form)
	return &form, err
}

func (p *FormParser) parseKafkaForm(data map[string]any) (*KafkaForm, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	var form KafkaForm
	err = json.Unmarshal(jsonData, &form)
	return &form, err
}

func (p *FormParser) parseWebSocketForm(data map[string]any) (*WebSocketForm, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	var form WebSocketForm
	err = json.Unmarshal(jsonData, &form)
	return &form, err
}

// SubprotocolValidator provides validation for WoT subprotocols
type SubprotocolValidator struct{}

// ValidateSubprotocol validates a subprotocol against a base protocol and operations
func (v *SubprotocolValidator) ValidateSubprotocol(protocol, subprotocol string, operations []string) error {
	if subprotocol == "" {
		return nil // No validation if not specified
	}

	// Define valid subprotocols per protocol
	validSubprotocols := map[string][]string{
		"http": {"longpoll", "sse", "websub"},
		"ws": {
			// IANA-registered subprotocols for IoT/WoT
			"wamp", "mqtt", "amqp", "coap", "opcua+uacp", "opcua+uajson",
			// TwinCore custom subprotocols for WoT binding alignment
			"kafka", "nats",
		},
		"coap": {"cov:observe"},
		"mqtt": {}, // MQTT doesn't typically use subprotocols
	}

	// Check if protocol supports subprotocols
	supportedSubprotocols, protocolSupported := validSubprotocols[protocol]
	if !protocolSupported {
		return fmt.Errorf("protocol '%s' does not support subprotocols", protocol)
	}

	// Check if subprotocol is valid for this protocol
	if !slices.Contains(supportedSubprotocols, subprotocol) {
		return fmt.Errorf("subprotocol '%s' is not valid for protocol '%s'", subprotocol, protocol)
	}

	// Validate subprotocol against operations
	return v.validateSubprotocolOperations(protocol, subprotocol, operations)
}

// validateSubprotocolOperations validates that subprotocol is compatible with operations
func (v *SubprotocolValidator) validateSubprotocolOperations(protocol, subprotocol string, operations []string) error {
	if len(operations) == 0 {
		return nil
	}

	// Define operation compatibility rules
	switch protocol {
	case "http":
		switch subprotocol {
		case "sse":
			// SSE is for receiving events
			validOps := []string{"subscribeevent", "observeproperty"}
			for _, op := range operations {
				if !slices.Contains(validOps, op) {
					return fmt.Errorf("HTTP SSE subprotocol is not compatible with operation '%s'", op)
				}
			}
		case "longpoll":
			// Long polling can be used for various operations but typically for updates
			validOps := []string{"subscribeevent", "observeproperty", "readproperty"}
			for _, op := range operations {
				if !slices.Contains(validOps, op) {
					return fmt.Errorf("HTTP longpoll subprotocol is not compatible with operation '%s'", op)
				}
			}
		case "websub":
			// WebSub is for subscription-based operations
			validOps := []string{"subscribeevent"}
			for _, op := range operations {
				if !slices.Contains(validOps, op) {
					return fmt.Errorf("HTTP WebSub subprotocol is not compatible with operation '%s'", op)
				}
			}
		}

	case "ws":
		// WebSocket subprotocols - validate based on their nature
		switch subprotocol {
		case "mqtt":
			// MQTT over WebSocket supports all WoT operations
			break
		case "wamp":
			// WAMP supports all WoT operations (RPC and PubSub)
			break
		case "amqp":
			// AMQP supports all WoT operations (message queuing)
			break
		case "coap":
			// CoAP over WebSocket supports all WoT operations
			break
		case "opcua+uacp", "opcua+uajson":
			// OPC UA supports all WoT operations (industrial automation)
			break
		case "kafka":
			// Kafka over WebSocket (TwinCore custom) supports all operations
			break
		case "nats":
			// NATS over WebSocket (TwinCore custom) supports all operations
			break
		default:
			// Unknown WebSocket subprotocols are assumed compatible
			break
		}

	case "coap":
		switch subprotocol {
		case "cov:observe":
			// CoAP observe is for observation operations
			validOps := []string{"observeproperty", "subscribeevent"}
			for _, op := range operations {
				if !slices.Contains(validOps, op) {
					return fmt.Errorf("CoAP observe subprotocol is not compatible with operation '%s'", op)
				}
			}
		}
	}

	return nil
}
