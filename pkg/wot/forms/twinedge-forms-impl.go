// pkg/wot/forms/kafka.go
package forms

import (
	"bytes"
	_ "embed"
	"strings"       // Added for SCRAM mechanism
	"text/template" // Retained for potential logging, or remove if not used

	"github.com/twinfer/twincore/pkg/wot"
)

//go:embed templates/kafka_input.yaml
var kafkaInputTemplate string

//go:embed templates/kafka_output.yaml
var kafkaOutputTemplate string

// KafkaForm implements Form interface for Kafka/Redpanda
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
		"yaml": buf.String(),
		"type": f.GetProtocol(),
	}, nil
}

func (f *KafkaForm) extractAuthConfig(securityDefs map[string]wot.SecurityScheme) map[string]interface{} {
	for _, schemeInterface := range securityDefs {
		// Attempt to treat schemeInterface as map[string]interface{}
		schemeData, ok := schemeInterface.(map[string]interface{})
		if !ok {
			// Potentially log or handle cases where schemeInterface is not a map
			// For this subtask, we'll skip if it's not in the expected map format
			continue
		}

		schemeTypeStr, ok := schemeData["scheme"].(string)
		if !ok {
			continue // Scheme type is mandatory
		}

		switch strings.ToLower(schemeTypeStr) {
		case "basic", "plain": // SASL PLAIN
			username := "${TWINEDGE_KAFKA_USER}" // Default placeholder
			password := "${TWINEDGE_KAFKA_PASS}" // Default placeholder

			if userVal, ok := schemeData["user"].(string); ok && userVal != "" {
				username = userVal
			} else if userVal, ok := schemeData["username"].(string); ok && userVal != "" {
				username = userVal
			}

			if passVal, ok := schemeData["password"].(string); ok && passVal != "" {
				password = passVal
			}
			return map[string]interface{}{
				"mechanism": "PLAIN",
				"username":  username,
				"password":  password,
			}

		case "scram-sha-256", "scram-sha-512":
			username := "${TWINEDGE_KAFKA_USER}"
			password := "${TWINEDGE_KAFKA_PASS}"
			mechanism := strings.ToUpper(schemeTypeStr) // SCRAM-SHA-256 or SCRAM-SHA-512

			if userVal, ok := schemeData["user"].(string); ok && userVal != "" {
				username = userVal
			} else if userVal, ok := schemeData["username"].(string); ok && userVal != "" {
				username = userVal
			}
			if passVal, ok := schemeData["password"].(string); ok && passVal != "" {
				password = passVal
			}
			return map[string]interface{}{
				"mechanism": mechanism,
				"username":  username,
				"password":  password,
			}

		case "oauth2":
			// SASL OAUTHBEARER. Benthos expects the token to be provided.
			// The actual token must be sourced externally (e.g., env var).
			tokenPlaceholder := "${TWINEDGE_KAFKA_OAUTH_TOKEN}"
			if tokenVal, ok := schemeData["token"].(string); ok && tokenVal != "" { // If TD provides a direct token string
				tokenPlaceholder = tokenVal
			}
			// The current Kafka template (kafka_input.yaml/kafka_output.yaml) needs to be updated
			// to actually use this token. It currently only has username/password fields for SASL.
			return map[string]interface{}{
				"mechanism": "OAUTHBEARER",
				"token":     tokenPlaceholder, // Custom field for template to use
			}

		case "nosec":
			return nil // No auth config needed
		}
	}
	return nil // No suitable and configured security scheme found
}
