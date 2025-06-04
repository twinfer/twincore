package wot

import (
	"encoding/json"
	"fmt"
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
	MethodName string       `json:"htv:methodName,omitempty"` // GET, POST, PUT, DELETE, PATCH
	Headers    []HTTPHeader `json:"htv:headers,omitempty"`
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

	// Fallback to href-based detection
	if href, ok := formData["href"].(string); ok {
		switch {
		case strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://"):
			return p.parseHTTPForm(formData)
		case strings.HasPrefix(href, "mqtt://") || strings.HasPrefix(href, "mqtts://"):
			return p.parseMQTTForm(formData)
		case strings.HasPrefix(href, "kafka://"):
			return p.parseKafkaForm(formData)
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
