// internal/api/schema_validator.go
package api

import (
	"encoding/json"
	"fmt"
	"sync/atomic"

	"github.com/twinfer/twincore/pkg/wot"
	"github.com/xeipuuv/gojsonschema"
)

// JSONSchemaValidator implements SchemaValidator using JSON Schema
type JSONSchemaValidator struct {
	schemaCache map[string]*gojsonschema.Schema
}

func NewJSONSchemaValidator() *JSONSchemaValidator {
	return &JSONSchemaValidator{
		schemaCache: make(map[string]*gojsonschema.Schema),
	}
}

// getCachedOrCompile attempts to retrieve a compiled schema from cache.
// If not found, it compiles the provided dataSchema, caches it, and returns it.
// The cacheKey must uniquely identify the schema.
func (v *JSONSchemaValidator) getCachedOrCompile(cacheKey string, dataSchema wot.DataSchema) (*gojsonschema.Schema, error) {
	if compiled, ok := v.schemaCache[cacheKey]; ok {
		return compiled, nil
	}

	if dataSchema == nil { // If no schema is provided, no validation can occur.
		// Cache nil to avoid recompilation attempts for this key if it's intentionally nil.
		v.schemaCache[cacheKey] = nil
		return nil, nil
	}

	schemaJSON, err := json.Marshal(dataSchema)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal schema to JSON for key '%s': %w", cacheKey, err)
	}

	schemaLoader := gojsonschema.NewStringLoader(string(schemaJSON))
	compiledSchema, err := gojsonschema.NewSchema(schemaLoader)
	if err != nil {
		return nil, fmt.Errorf("failed to compile schema for key '%s': %w", cacheKey, err)
	}

	v.schemaCache[cacheKey] = compiledSchema
	return compiledSchema, nil
}

func (v *JSONSchemaValidator) ValidateProperty(propertyName string, propertySchema wot.DataSchema, value interface{}) error {
	// Note: propertyName as a cache key might not be globally unique if the validator
	// is shared across different Things with potentially colliding property names.
	// A more robust key might involve a ThingID if available at this layer.
	// For now, we use propertyName, assuming it's unique enough in the validator's context.
	compiledSchema, err := v.getCachedOrCompile(propertyName, propertySchema)
	if err != nil {
		// This error means schema compilation failed.
		return fmt.Errorf("schema compilation/retrieval error for property '%s': %w", propertyName, err)
	}
	if compiledSchema == nil {
		return nil // No schema defined, accept any value
	}

	documentLoader := gojsonschema.NewGoLoader(value)
	result, err := compiledSchema.Validate(documentLoader)
	if err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	if !result.Valid() {
		errors := ""
		for _, err := range result.Errors() {
			errors += fmt.Sprintf("- %s\n", err)
		}
		return fmt.Errorf("value does not match schema:\n%s", errors)
	}

	return nil
}

func (v *JSONSchemaValidator) ValidateActionInput(schema wot.DataSchema, input interface{}) error {
	if schema == nil {
		return nil // No schema to validate against
	}

	// Generate a cache key from the schema itself by marshalling it.
	schemaKeyBytes, err := json.Marshal(schema)
	if err != nil {
		return fmt.Errorf("failed to marshal action input schema for cache key generation: %w", err)
	}
	cacheKey := string(schemaKeyBytes)

	compiledSchema, err := v.getCachedOrCompile(cacheKey, schema)
	if err != nil {
		return fmt.Errorf("schema compilation/retrieval error for action input: %w", err)
	}
	documentLoader := gojsonschema.NewGoLoader(input)
	result, err := compiledSchema.Validate(documentLoader)
	if err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	if !result.Valid() {
		errors := ""
		for _, err := range result.Errors() {
			errors += fmt.Sprintf("- %s\n", err)
		}
		return fmt.Errorf("input does not match schema:\n%s", errors)
	}

	return nil
}

func (v *JSONSchemaValidator) ValidateEventData(schema wot.DataSchema, data interface{}) error {
	if schema == nil {
		return nil // No schema to validate against
	}

	// Generate a cache key from the schema itself
	schemaKeyBytes, err := json.Marshal(schema)
	if err != nil {
		return fmt.Errorf("failed to marshal event data schema for cache key generation: %w", err)
	}
	cacheKey := string(schemaKeyBytes)

	compiledSchema, err := v.getCachedOrCompile(cacheKey, schema)
	if err != nil {
		return fmt.Errorf("schema compilation/retrieval error for event data: %w", err)
	}
	documentLoader := gojsonschema.NewGoLoader(data)
	result, err := compiledSchema.Validate(documentLoader)
	if err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	if !result.Valid() {
		errors := ""
		for _, err := range result.Errors() {
			errors += fmt.Sprintf("- %s\n", err)
		}
		return fmt.Errorf("event data does not match schema:\n%s", errors)
	}

	return nil
}

// MetricsCollector collects metrics for monitoring
type MetricsCollector struct {
	propertyReads  uint64
	propertyWrites uint64
	actionInvokes  uint64
	eventEmissions uint64
	errors         uint64
}

func (m *MetricsCollector) IncrementPropertyReads()  { atomic.AddUint64(&m.propertyReads, 1) }
func (m *MetricsCollector) IncrementPropertyWrites() { atomic.AddUint64(&m.propertyWrites, 1) }
func (m *MetricsCollector) IncrementActionInvokes()  { atomic.AddUint64(&m.actionInvokes, 1) }
func (m *MetricsCollector) IncrementEventEmissions() { atomic.AddUint64(&m.eventEmissions, 1) }
func (m *MetricsCollector) IncrementErrors()         { atomic.AddUint64(&m.errors, 1) }

func (m *MetricsCollector) GetMetrics() map[string]uint64 {
	return map[string]uint64{
		"property_reads":  atomic.LoadUint64(&m.propertyReads),
		"property_writes": atomic.LoadUint64(&m.propertyWrites),
		"action_invokes":  atomic.LoadUint64(&m.actionInvokes),
		"event_emissions": atomic.LoadUint64(&m.eventEmissions),
		"errors":          atomic.LoadUint64(&m.errors),
	}
}
