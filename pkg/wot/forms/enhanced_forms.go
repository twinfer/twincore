package forms

import (
	"fmt"
	// "time" // No longer directly needed after removals
	// "context" // No longer directly needed
	// "encoding/base64" // No longer directly needed
	// _ "embed" // No longer directly needed
	// "net/url" // No longer directly needed
	// "strings" // No longer directly needed
	// "text/template" // No longer directly needed

	// "github.com/google/uuid" // No longer directly needed
	// "github.com/sirupsen/logrus" // No longer directly needed
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
)

// EnhancedForm extends the basic Form interface with methods for stream configuration
type EnhancedForm interface {
	wot.Form
	// GetStreamProtocol returns the protocol type for stream configuration
	GetStreamProtocol() types.StreamProtocol
	// GetStreamDirection returns the data flow direction
	GetStreamDirection(op []string) types.StreamDirection
	// GenerateStreamEndpoint generates endpoint configuration for stream manager
	GenerateStreamEndpoint() (map[string]interface{}, error)
	// GenerateConfig generates the protocol-specific configuration for a form,
	// now requiring a logger for internal logging.
	GenerateConfig(logger logrus.FieldLogger, securityDefs map[string]wot.SecurityScheme) (map[string]interface{}, error)
}

// ConvertFormToStreamEndpoint converts a WoT form to a stream endpoint configuration
func ConvertFormToStreamEndpoint(form wot.Form) (map[string]interface{}, error) {
	config := map[string]interface{}{
		"type": form.GetProtocol(),
	}

	// Use the form's own configuration generation if available
	// Note: The types.Form interface was extended by EnhancedForm, but wot.Form is the base.
	// The GenerateConfig method is part of the protocol-specific forms (KafkaForm, etc.)
	// which are expected to implement wot.Form.
	// For this call, we pass a default logger. A more sophisticated approach might involve
	// threading a logger through, but for now, a new entry is acceptable for this utility.
	if configGen, ok := form.(interface{ GenerateConfig(logger logrus.FieldLogger, securityDefs map[string]wot.SecurityScheme) (map[string]interface{}, error) }); ok {
		// Create a default logger entry if no specific logger is available in this context.
		// Consider making logger a mandatory pass-through in all relevant call chains if detailed context is always needed.
		defaultLogger := logrus.NewEntry(logrus.StandardLogger())
		formConfig, err := configGen.GenerateConfig(defaultLogger, nil) // Pass default logger and empty security for now
		if err != nil {
			return nil, fmt.Errorf("failed to generate form config: %w", err)
		}
		// Extract the actual config from the form's response
		if actualConfig, exists := formConfig["config"]; exists {
			config["config"] = actualConfig
		} else {
			// If "config" key doesn't exist, the returned map itself might be the config
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
