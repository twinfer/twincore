package forms

import (
	"fmt"
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
}

// GetStreamDirection determines stream direction based on WoT operations
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

// GenerateProcessorChain creates a processor chain based on interaction type and options
func GenerateProcessorChain(interactionType string, options map[string]interface{}) []map[string]interface{} {
	processors := []map[string]interface{}{}
	
	// Add WoT-specific processor based on interaction type
	switch interactionType {
	case "property":
		processors = append(processors, map[string]interface{}{
			"type": string(types.ProcessorBloblangWoTProperty),
			"config": map[string]interface{}{
				"mapping": "root = this", // Default passthrough, can be customized
			},
		})
	case "action":
		processors = append(processors, map[string]interface{}{
			"type": string(types.ProcessorBloblangWoTAction),
			"config": map[string]interface{}{
				"mapping": "root = this",
			},
		})
	case "event":
		processors = append(processors, map[string]interface{}{
			"type": string(types.ProcessorBloblangWoTEvent),
			"config": map[string]interface{}{
				"mapping": "root = this",
			},
		})
	}
	
	// Add JSON schema validation if schema is provided
	if schema, ok := options["schema"]; ok {
		processors = append(processors, map[string]interface{}{
			"type": string(types.ProcessorJSONSchema),
			"config": map[string]interface{}{
				"schema": schema,
			},
		})
	}
	
	// Add Parquet encoding for logging streams
	if enableParquet, ok := options["enable_parquet"].(bool); ok && enableParquet {
		processors = append(processors, map[string]interface{}{
			"type": string(types.ProcessorParquetEncode),
			"config": map[string]interface{}{
				"schema": generateParquetSchema(interactionType),
			},
		})
	}
	
	return processors
}

// generateParquetSchema creates a Parquet schema for the given interaction type
func generateParquetSchema(interactionType string) []map[string]interface{} {
	baseSchema := []map[string]interface{}{
		{
			"name":            "thing_id",
			"type":            "BYTE_ARRAY",
			"converted_type":  "UTF8",
			"repetition_type": "REQUIRED",
		},
		{
			"name":            "timestamp",
			"type":            "INT64",
			"converted_type":  "TIMESTAMP_NANOS",
			"repetition_type": "REQUIRED",
		},
	}
	
	switch interactionType {
	case "property":
		baseSchema = append(baseSchema, 
			map[string]interface{}{
				"name":            "property_name",
				"type":            "BYTE_ARRAY",
				"converted_type":  "UTF8",
				"repetition_type": "REQUIRED",
			},
			map[string]interface{}{
				"name":            "value",
				"type":            "BYTE_ARRAY",
				"converted_type":  "UTF8",
				"repetition_type": "REQUIRED",
			},
		)
	case "action":
		baseSchema = append(baseSchema,
			map[string]interface{}{
				"name":            "action_name",
				"type":            "BYTE_ARRAY",
				"converted_type":  "UTF8",
				"repetition_type": "REQUIRED",
			},
			map[string]interface{}{
				"name":            "action_id",
				"type":            "BYTE_ARRAY",
				"converted_type":  "UTF8",
				"repetition_type": "REQUIRED",
			},
			map[string]interface{}{
				"name":            "input",
				"type":            "BYTE_ARRAY",
				"converted_type":  "UTF8",
				"repetition_type": "OPTIONAL",
			},
			map[string]interface{}{
				"name":            "status",
				"type":            "BYTE_ARRAY",
				"converted_type":  "UTF8",
				"repetition_type": "REQUIRED",
			},
		)
	case "event":
		baseSchema = append(baseSchema,
			map[string]interface{}{
				"name":            "event_name",
				"type":            "BYTE_ARRAY",
				"converted_type":  "UTF8",
				"repetition_type": "REQUIRED",
			},
			map[string]interface{}{
				"name":            "data",
				"type":            "BYTE_ARRAY",
				"converted_type":  "UTF8",
				"repetition_type": "OPTIONAL",
			},
			map[string]interface{}{
				"name":            "severity",
				"type":            "BYTE_ARRAY",
				"converted_type":  "UTF8",
				"repetition_type": "REQUIRED",
			},
		)
	}
	
	baseSchema = append(baseSchema, map[string]interface{}{
		"name":            "source",
		"type":            "BYTE_ARRAY",
		"converted_type":  "UTF8",
		"repetition_type": "REQUIRED",
	})
	
	return baseSchema
}

// ConvertFormToStreamEndpoint converts a WoT form to a stream endpoint configuration
func ConvertFormToStreamEndpoint(form wot.Form) (map[string]interface{}, error) {
	config := map[string]interface{}{
		"type": form.GetProtocol(),
	}
	
	switch form.GetProtocol() {
	case "kafka":
		if kf, ok := form.(*KafkaForm); ok {
			config["config"] = map[string]interface{}{
				"brokers": []string{kf.Href},
				"topic":   kf.Topic,
			}
		}
	case "mqtt":
		// TODO: Implement MQTT form conversion
		config["config"] = map[string]interface{}{
			"broker": form.GetHref(),
		}
	case "http":
		if hf, ok := form.(*HTTPForm); ok {
			config["config"] = map[string]interface{}{
				"url":    hf.Href,
				"method": hf.Method,
			}
		}
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", form.GetProtocol())
	}
	
	return config, nil
}