package api

import (
	"context"
	"io"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/twinfer/twincore/pkg/wot"
)

func TestJSONSchemaValidator_ValidateProperty(t *testing.T) {
	validator := NewJSONSchemaValidator()
	baseLogger := logrus.New()
	baseLogger.SetOutput(io.Discard) // Suppress log output during tests
	logger := baseLogger.WithContext(context.Background())

	testCases := []struct {
		name          string
		propertyName  string
		schema        wot.DataSchema
		data          interface{}
		expectError   bool
		errorContains string
	}{
		{
			name:         "valid string",
			propertyName: "deviceName",
			schema:       wot.DataSchema{DataSchemaCore: wot.DataSchemaCore{Type: "string"}},
			data:         "Test Device",
			expectError:  false,
		},
		{
			name:          "invalid type - number for string",
			propertyName:  "deviceName",
			schema:        wot.DataSchema{DataSchemaCore: wot.DataSchemaCore{Type: "string"}},
			data:          12345,
			expectError:   true,
			errorContains: "type is wrong. Expected: string, Got: integer",
		},
		{
			name:         "valid integer",
			propertyName: "sensorReading",
			schema:       wot.DataSchema{DataSchemaCore: wot.DataSchemaCore{Type: "integer"}},
			data:         42,
			expectError:  false,
		},
		{
			name:          "invalid type - string for integer",
			propertyName:  "sensorReading",
			schema:        wot.DataSchema{DataSchemaCore: wot.DataSchemaCore{Type: "integer"}},
			data:          "not-a-number",
			expectError:   true,
			errorContains: "type is wrong. Expected: integer, Got: string",
		},
		{
			name:         "valid number",
			propertyName: "temperature",
			schema:       wot.DataSchema{DataSchemaCore: wot.DataSchemaCore{Type: "number"}},
			data:         23.5,
			expectError:  false,
		},
		{
			name:         "valid boolean true",
			propertyName: "isActive",
			schema:       wot.DataSchema{DataSchemaCore: wot.DataSchemaCore{Type: "boolean"}},
			data:         true,
			expectError:  false,
		},
		{
			name:         "valid boolean false",
			propertyName: "isOffline",
			schema:       wot.DataSchema{DataSchemaCore: wot.DataSchemaCore{Type: "boolean"}},
			data:         false,
			expectError:  false,
		},
		{
			name:          "invalid type - string for boolean",
			propertyName:  "isActive",
			schema:        wot.DataSchema{DataSchemaCore: wot.DataSchemaCore{Type: "boolean"}},
			data:          "true_string",
			expectError:   true,
			errorContains: "type is wrong. Expected: boolean, Got: string",
		},
		{
			name:         "valid object with required property",
			propertyName: "location",
			schema: wot.DataSchema{
				DataSchemaCore: wot.DataSchemaCore{
					Type: "object",
					Properties: map[string]*wot.DataSchema{ // Changed from InteractionAffordance to *DataSchema for Properties
						"latitude":  {DataSchemaCore: wot.DataSchemaCore{Type: "number"}},
						"longitude": {DataSchemaCore: wot.DataSchemaCore{Type: "number"}},
					},
					Required: []string{"latitude"},
				},
			},
			data:        map[string]interface{}{"latitude": 40.7128, "longitude": -74.0060},
			expectError: false,
		},
		{
			name:         "invalid object - missing required property",
			propertyName: "location",
			schema: wot.DataSchema{
				DataSchemaCore: wot.DataSchemaCore{
					Type: "object",
					Properties: map[string]*wot.DataSchema{
						"latitude":  {DataSchemaCore: wot.DataSchemaCore{Type: "number"}},
						"longitude": {DataSchemaCore: wot.DataSchemaCore{Type: "number"}},
					},
					Required: []string{"latitude"},
				},
			},
			data:          map[string]interface{}{"longitude": -74.0060},
			expectError:   true,
			errorContains: "latitude: (root): latitude is required",
		},
		{
			name:         "invalid object - wrong type for property",
			propertyName: "location",
			schema: wot.DataSchema{
				DataSchemaCore: wot.DataSchemaCore{
					Type: "object",
					Properties: map[string]*wot.DataSchema{
						"latitude": {DataSchemaCore: wot.DataSchemaCore{Type: "number"}},
					},
				},
			},
			data:          map[string]interface{}{"latitude": "not-a-number"},
			expectError:   true,
			errorContains: "latitude: type is wrong. Expected: number, Got: string",
		},
		{
			name:          "nil data for required string",
			propertyName:  "deviceName",
			schema:        wot.DataSchema{DataSchemaCore: wot.DataSchemaCore{Type: "string"}}, // Assumes string is implicitly required if not nullable
			data:          nil,
			expectError:   true,
			errorContains: "type is wrong. Expected: string, Got: null",
		},
		{
			name:         "valid string for enum",
			propertyName: "status",
			schema:       wot.DataSchema{DataSchemaCore: wot.DataSchemaCore{Type: "string", Enum: []interface{}{"active", "inactive", "error"}}},
			data:         "active",
			expectError:  false,
		},
		{
			name:          "invalid string for enum",
			propertyName:  "status",
			schema:        wot.DataSchema{DataSchemaCore: wot.DataSchemaCore{Type: "string", Enum: []interface{}{"active", "inactive", "error"}}},
			data:          "pending",
			expectError:   true,
			errorContains: "does not match any of the options in the enum", // Actual message might vary slightly
		},
		// TODO: Developer to add many more cases:
		// - format validations (e.g., "date-time", "uri") - note: gojsonschema has limitations/requires specific setup for some formats.
		// - array schemas (valid, invalid items, item type violations, minItems, maxItems)
		// - object schemas with additionalProperties: false (if wot.DataSchema supports it clearly)
		// - more complex nested objects and arrays.
		// - schemas with default values (though validation typically happens on provided data).
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.ValidateProperty(logger.WithField("test_case", tc.name), tc.propertyName, tc.schema, tc.data)
			if tc.expectError {
				assert.Error(t, err, "Expected an error for test case: %s", tc.name)
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains, "Error message mismatch for test case: %s", tc.name)
				}
			} else {
				assert.NoError(t, err, "Expected no error for test case: %s", tc.name)
			}
		})
	}
}

func TestJSONSchemaValidator_ValidateActionInput(t *testing.T) {
	validator := NewJSONSchemaValidator()
	baseLogger := logrus.New()
	baseLogger.SetOutput(io.Discard)
	logger := baseLogger.WithContext(context.Background())

	// TODO: Developer to implement table-driven tests for ValidateActionInput.
	// Similar structure to TestJSONSchemaValidator_ValidateProperty.
	// Key differences:
	// - The `schema` field in test cases will be for action input.
	// - The `data` field will represent action invocation payloads.
	// - Test cases should cover various input structures expected by actions.
	// Example test case:
	/*
		{
			name: "valid action input - object",
			schema: wot.DataSchema{
				DataSchemaCore: wot.DataSchemaCore{
					Type: "object",
					Properties: map[string]*wot.DataSchema{
						"targetSpeed": {DataSchemaCore: wot.DataSchemaCore{Type: "integer"}},
					},
					Required: []string{"targetSpeed"},
				},
			},
			data: map[string]interface{}{"targetSpeed": 100},
			expectError: false,
		},
	*/
	t.Skip("TestJSONSchemaValidator_ValidateActionInput not yet implemented by developer.")
}

func TestJSONSchemaValidator_ValidateEventData(t *testing.T) {
	validator := NewJSONSchemaValidator()
	baseLogger := logrus.New()
	baseLogger.SetOutput(io.Discard)
	logger := baseLogger.WithContext(context.Background())

	// TODO: Developer to implement table-driven tests for ValidateEventData.
	// Similar structure to TestJSONSchemaValidator_ValidateProperty.
	// Key differences:
	// - The `schema` field in test cases will be for event data.
	// - The `data` field will represent event payloads.
	// - Test cases should cover various event data structures.
	// Example test case:
	/*
		{
			name: "valid event data - simple string",
			schema: wot.DataSchema{DataSchemaCore: wot.DataSchemaCore{Type: "string"}},
			data: "overheat_warning",
			expectError: false,
		},
	*/
	t.Skip("TestJSONSchemaValidator_ValidateEventData not yet implemented by developer.")
}
