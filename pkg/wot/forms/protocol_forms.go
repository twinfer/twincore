package forms

import (
	"bytes"
	"context"
	"encoding/base64"
	_ "embed"
	"fmt"
	"net/url"
	"strings"
	"text/template"
	"time"

	"github.com/google/uuid"
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

//go:embed templates/mqtt_input.yaml
var mqttInputTemplate string

//go:embed templates/mqtt_output.yaml
var mqttOutputTemplate string

// executeTemplate parses and executes a template with the given data.
func executeTemplate(templateName, tmplStr string, data map[string]interface{}) (string, error) {
	tmpl, err := template.New(templateName).Parse(tmplStr)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

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
	yamlOutput, err := executeTemplate("kafka", tmplStr, config)
	if err != nil {
		return nil, fmt.Errorf("failed to execute kafka template: %w", err)
	}

	return map[string]interface{}{
		"yaml":   yamlOutput,
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
	yamlOutput, err := executeTemplate("http", tmplStr, config)
	if err != nil {
		return nil, fmt.Errorf("failed to execute http template: %w", err)
	}

	return map[string]interface{}{
		"yaml":   yamlOutput,
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

// MQTTForm implements Form interface for MQTT with enhanced security capabilities
type MQTTForm struct {
	Href        string                 `json:"href"`
	ContentType string                 `json:"contentType"`
	Op          []string               `json:"op"`
	QoS         int                    `json:"mqtt:qos,omitempty"` // W3C WoT compliant
	Retain      bool                   `json:"mqtt:retain,omitempty"` // W3C WoT compliant
	Headers     map[string]string      `json:"mqtt:headers,omitempty"` // For MQTT 5.0 user properties
	Options     map[string]interface{} `json:"mqtt:options,omitempty"` // Additional MQTT options
}

func (f *MQTTForm) GetProtocol() string {
	return "mqtt"
}

func (f *MQTTForm) GetHref() string {
	return f.Href
}

func (f *MQTTForm) GetContentType() string {
	if f.ContentType == "" {
		return "application/json"
	}
	return f.ContentType
}

func (f *MQTTForm) GetOp() []string {
	return f.Op
}

func (f *MQTTForm) GetStreamProtocol() types.StreamProtocol {
	return types.ProtocolMQTT
}

func (f *MQTTForm) GetStreamDirection(op []string) types.StreamDirection {
	return GetStreamDirection(op)
}

func (f *MQTTForm) GenerateStreamEndpoint() (map[string]interface{}, error) {
	return f.GenerateConfig(nil)
}

func (f *MQTTForm) GenerateConfig(securityDefs map[string]wot.SecurityScheme) (map[string]interface{}, error) {
	// Parse MQTT URL to extract broker and topic
	u, err := url.Parse(f.Href)
	if err != nil {
		return nil, fmt.Errorf("invalid MQTT URL: %w", err)
	}

	// Extract broker URL (scheme + host + port)
	scheme := u.Scheme
	if scheme == "mqtt" {
		scheme = "tcp" // Benthos uses tcp for MQTT
	} else if scheme == "mqtts" {
		scheme = "ssl" // Benthos uses ssl for MQTTS
	}

	port := u.Port()
	if port == "" {
		if scheme == "ssl" {
			port = "8883"
		} else {
			port = "1883"
		}
	}

	brokerURL := fmt.Sprintf("%s://%s:%s", scheme, u.Hostname(), port)

	// Extract topic from path
	topic := strings.TrimPrefix(u.Path, "/")
	if topic == "" {
		return nil, fmt.Errorf("MQTT topic not specified in URL")
	}

	// Generate client ID
	clientID := fmt.Sprintf("twincore-%s", uuid.New().String()[:8])
	if f.Options != nil {
		if cid, ok := f.Options["client_id"].(string); ok {
			clientID = cid
		}
	}

	// Determine if input or output based on operations
	isInput := false
	for _, op := range f.Op {
		if op == "observeproperty" || op == "subscribeevent" {
			isInput = true
			break
		}
	}

	// Prepare template config
	config := map[string]interface{}{
		"label":     fmt.Sprintf("mqtt_%s", topic),
		"urls":      []string{brokerURL},
		"client_id": clientID,
		"qos":       f.QoS,
	}

	if isInput {
		// For input, we subscribe to topics
		config["topics"] = []string{topic}
		config["clean_session"] = true
	} else {
		// For output, we publish to a topic
		config["topic"] = topic
		config["retained"] = f.Retain
	}

	// Add authentication configuration
	if authConfig := f.extractAuthConfig(securityDefs); authConfig != nil {
		for k, v := range authConfig {
			config[k] = v
		}
	}

	// Add TLS configuration if using mqtts
	if scheme == "ssl" && (config["tls"] == nil || config["tls"] == "") {
		config["tls"] = map[string]interface{}{
			"enabled": true,
		}
	}

	// Add connection options
	if f.Options != nil {
		if timeout, ok := f.Options["connect_timeout"].(string); ok {
			config["connect_timeout"] = timeout
		}
		if pingTimeout, ok := f.Options["ping_timeout"].(string); ok {
			config["ping_timeout"] = pingTimeout
		}
		if keepAlive, ok := f.Options["keep_alive"].(int); ok {
			config["keep_alive"] = keepAlive
		}
	}

	// Select template
	tmplStr := mqttOutputTemplate
	if isInput {
		tmplStr = mqttInputTemplate
	}

	// Parse and execute template
	yamlOutput, err := executeTemplate("mqtt", tmplStr, config)
	if err != nil {
		return nil, fmt.Errorf("failed to execute mqtt template: %w", err)
	}

	return map[string]interface{}{
		"yaml":   yamlOutput,
		"type":   f.GetProtocol(),
		"config": config,
	}, nil
}

func (f *MQTTForm) extractAuthConfig(securityDefs map[string]wot.SecurityScheme) map[string]interface{} {
	for _, schemeDef := range securityDefs {
		if schemeDef.Scheme == "" {
			continue
		}

		switch strings.ToLower(schemeDef.Scheme) {
		case "basic":
			// Basic username/password authentication
			username := "${MQTT_USERNAME}"
			password := "${MQTT_PASSWORD}"

			if schemeDef.Properties != nil {
				if user, ok := schemeDef.Properties["username"].(string); ok && user != "" {
					username = user
				}
				if pass, ok := schemeDef.Properties["password"].(string); ok && pass != "" {
					password = pass
				}
			}

			return map[string]interface{}{
				"username": username,
				"password": password,
			}

		case "clientcert", "cert", "mtls":
			// mTLS authentication
			tlsConfig := map[string]interface{}{
				"enabled": true,
			}

			if schemeDef.Properties != nil {
				if ca, ok := schemeDef.Properties["ca_cert"].(string); ok && ca != "" {
					tlsConfig["ca_cert"] = ca
				} else {
					tlsConfig["ca_cert"] = "${MQTT_CA_CERT}"
				}

				if cert, ok := schemeDef.Properties["client_cert"].(string); ok && cert != "" {
					tlsConfig["client_cert"] = cert
				} else {
					tlsConfig["client_cert"] = "${MQTT_CLIENT_CERT}"
				}

				if key, ok := schemeDef.Properties["client_key"].(string); ok && key != "" {
					tlsConfig["client_key"] = key
				} else {
					tlsConfig["client_key"] = "${MQTT_CLIENT_KEY}"
				}

				if skipVerify, ok := schemeDef.Properties["skip_verify"].(bool); ok {
					tlsConfig["skip_verify"] = skipVerify
				}
			}

			return map[string]interface{}{
				"tls": tlsConfig,
			}

		case "bearer", "jwt":
			// JWT bearer token - pass as username with empty password (MQTT 5.0 enhanced auth)
			token := "${MQTT_JWT_TOKEN}"
			if schemeDef.Properties != nil {
				if t, ok := schemeDef.Properties["token"].(string); ok && t != "" {
					token = t
				}
			}

			return map[string]interface{}{
				"username": token,
				"password": "", // Empty password for token auth
			}

		case "nosec":
			return nil // No auth config needed
		}
	}
	return nil // No suitable security scheme found
}

// GetStreamDirection determines stream direction based on WoT operations
// This function is used by the GetStreamDirection methods of the forms
// and needs to be accessible.
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
