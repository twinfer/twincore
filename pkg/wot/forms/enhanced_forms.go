package forms

import (
	"fmt"

	"github.com/twinfer/twincore/pkg/wot"
)

// ConvertFormToStreamEndpoint converts a WoT form to a stream endpoint configuration
func ConvertFormToStreamEndpoint(form wot.Form) (map[string]interface{}, error) {
	config := map[string]interface{}{
		"type": form.GetProtocol(),
	}

	// Form interface already has GenerateConfig method
	formConfig, err := form.GenerateConfig(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate form config: %w", err)
	}
	if actualConfig, exists := formConfig["config"]; exists {
		config["config"] = actualConfig
	} else {
		config["config"] = formConfig
	}
	return config, nil

	switch form.GetProtocol() {
	case "kafka":
		config["config"] = map[string]interface{}{
			"brokers": []string{form.GetHref()},
			"topic":   "default_topic",
		}
	case "mqtt":
		config["config"] = map[string]interface{}{
			"broker": form.GetHref(),
		}
	case "http":
		config["config"] = map[string]interface{}{
			"url":    form.GetHref(),
			"method": "GET",
		}
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", form.GetProtocol())
	}

	return config, nil
}
