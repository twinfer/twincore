package forms

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
)

//go:embed templates/kafka_input.yaml
var kafkaInputTemplate string

//go:embed templates/kafka_output.yaml
var kafkaOutputTemplate string

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
	return GetStreamDirection(op) // Assumes GetStreamDirection is in the same package or imported
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
	yamlOutput, err := executeTemplate("kafka", tmplStr, config) // Assumes executeTemplate is in the same package
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
