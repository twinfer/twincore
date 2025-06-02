package forms

import (
	_ "embed"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
)

//go:embed templates/mqtt_input.yaml
var mqttInputTemplate string

//go:embed templates/mqtt_output.yaml
var mqttOutputTemplate string

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
	return GetStreamDirection(op) // Assumes GetStreamDirection is in the same package
}

func (f *MQTTForm) GenerateStreamEndpoint() (map[string]interface{}, error) {
	return f.GenerateConfig(logrus.NewEntry(logrus.StandardLogger()), nil) // Pass default logger if called directly
}

func (f *MQTTForm) GenerateConfig(logger logrus.FieldLogger, securityDefs map[string]wot.SecurityScheme) (map[string]interface{}, error) {
	logger.WithFields(logrus.Fields{"form_href": f.Href, "protocol": f.GetProtocol()}).Debug("Generating config for MQTT form")
	// Parse MQTT URL to extract broker and topic
	u, err := url.Parse(f.Href)
	if err != nil {
		logger.WithError(err).WithField("form_href", f.Href).Error("Invalid MQTT URL in form")
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
		err := fmt.Errorf("MQTT topic not specified in URL")
		logger.WithError(err).WithField("form_href", f.Href).Error("Missing MQTT topic in form URL")
		return nil, err
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
	if authConfig := f.extractAuthConfig(logger, securityDefs); authConfig != nil { // Pass logger
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
	var tmplStr string
	var templateName string
	if isInput {
		tmplStr = mqttInputTemplate
		templateName = "mqttInputTemplate"
		logger.WithField("template_name", templateName).Debug("Selected MQTT input template")
	} else {
		tmplStr = mqttOutputTemplate
		templateName = "mqttOutputTemplate"
		logger.WithField("template_name", templateName).Debug("Selected MQTT output template")
	}

	// Parse and execute template
	yamlOutput, err := executeTemplate("mqtt", tmplStr, config)
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"form_href": f.Href, "template_name": templateName}).Error("Failed to execute MQTT form template")
		return nil, fmt.Errorf("failed to execute mqtt template: %w", err)
	}

	return map[string]interface{}{
		"yaml":   yamlOutput,
		"type":   f.GetProtocol(),
		"config": config,
	}, nil
}

func (f *MQTTForm) extractAuthConfig(logger logrus.FieldLogger, securityDefs map[string]wot.SecurityScheme) map[string]interface{} {
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
			logger.WithFields(logrus.Fields{"scheme": schemeDef.Scheme, "form_href": f.Href}).Debug("Applying basic auth security scheme to MQTT form config")
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
			logger.WithFields(logrus.Fields{"scheme": schemeDef.Scheme, "form_href": f.Href}).Debug("Applying mTLS security scheme to MQTT form config")
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
			logger.WithFields(logrus.Fields{"scheme": schemeDef.Scheme, "form_href": f.Href}).Debug("Applying JWT bearer security scheme to MQTT form config")
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
