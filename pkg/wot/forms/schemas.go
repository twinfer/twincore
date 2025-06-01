package forms

import (
	"fmt"
	"github.com/twinfer/twincore/pkg/wot"
)

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

func generatePropertyParquetSchema() []map[string]interface{} {
	return []map[string]interface{}{
		{"name": "thing_id", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "property_name", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "value", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "timestamp", "type": "INT64", "converted_type": "TIMESTAMP_NANOS", "repetition_type": "REQUIRED"},
		{"name": "source", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
	}
}

func generateActionParquetSchema() []map[string]interface{} {
	return []map[string]interface{}{
		{"name": "thing_id", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "action_name", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "action_id", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "input", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "OPTIONAL"},
		{"name": "output", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "OPTIONAL"},
		{"name": "status", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "timestamp", "type": "INT64", "converted_type": "TIMESTAMP_NANOS", "repetition_type": "REQUIRED"},
		{"name": "duration_ms", "type": "INT64", "converted_type": "TIMESTAMP_MILLIS", "repetition_type": "OPTIONAL"},
		{"name": "error", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "OPTIONAL"},
		{"name": "source", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
	}
}

func generateEventParquetSchema() []map[string]interface{} {
	return []map[string]interface{}{
		{"name": "thing_id", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "event_name", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "event_id", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "data", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "OPTIONAL"},
		{"name": "timestamp", "type": "INT64", "converted_type": "TIMESTAMP_NANOS", "repetition_type": "REQUIRED"},
		{"name": "severity", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "source", "type": "BYTE_ARRAY", "converted_type": "UTF8", "repetition_type": "REQUIRED"},
		{"name": "subscription_count", "type": "INT64", "converted_type": "INT_64", "repetition_type": "OPTIONAL"},
	}
}

func convertDataSchemaToJSONSchema(schema wot.DataSchemaCore) map[string]interface{} {
	jsonSchema := map[string]interface{}{
		"type": schema.Type,
	}

	if schema.Type == "object" && schema.Properties != nil {
		properties := make(map[string]interface{})
		for name, prop := range schema.Properties {
			properties[name] = convertDataSchemaToJSONSchema(prop.DataSchemaCore)
		}
		jsonSchema["properties"] = properties

		if len(schema.Required) > 0 {
			jsonSchema["required"] = schema.Required
		}
	}

	return jsonSchema
}
