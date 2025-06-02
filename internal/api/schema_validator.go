// internal/api/schema_validator.go
package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/wot"
	"github.com/xeipuuv/gojsonschema"
)

// JSONSchemaValidator implements SchemaValidator using JSON Schema
type JSONSchemaValidator struct {
	schemaCache map[string]*gojsonschema.Schema
	// logger logrus.FieldLogger // No longer storing logger in struct, passed via methods
}

func NewJSONSchemaValidator() *JSONSchemaValidator {
	// Logger is no longer initialized here
	return &JSONSchemaValidator{
		schemaCache: make(map[string]*gojsonschema.Schema),
	}
}

// getCachedOrCompile attempts to retrieve a compiled schema from cache.
// If not found, it compiles the provided dataSchema, caches it, and returns it.
// The cacheKey must uniquely identify the schema.
func (v *JSONSchemaValidator) getCachedOrCompile(logger logrus.FieldLogger, cacheKey string, dataSchema wot.DataSchema) (*gojsonschema.Schema, error) {
	logger = logger.WithFields(logrus.Fields{"internal_method": "getCachedOrCompile", "cache_key": cacheKey})

	if compiled, ok := v.schemaCache[cacheKey]; ok {
		logger.Debug("Schema found in cache")
		return compiled, nil
	}
	logger.Debug("Schema not in cache, compiling")

	schemaJSON, err := json.Marshal(dataSchema)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal schema to JSON for cache key")
		return nil, fmt.Errorf("failed to marshal schema to JSON for key '%s': %w", cacheKey, err)
	}

	schemaLoader := gojsonschema.NewStringLoader(string(schemaJSON))
	compiledSchema, err := gojsonschema.NewSchema(schemaLoader)
	if err != nil {
		logger.WithError(err).Error("Failed to compile schema from loader")
		return nil, fmt.Errorf("failed to compile schema for key '%s': %w", cacheKey, err)
	}

	v.schemaCache[cacheKey] = compiledSchema
	logger.Debug("Schema compiled and cached successfully")
	return compiledSchema, nil
}

func (v *JSONSchemaValidator) ValidateProperty(logger logrus.FieldLogger, propertyName string, propertySchema wot.DataSchema, value interface{}) error {
	logger = logger.WithFields(logrus.Fields{"validator_method": "ValidateProperty", "property_name": propertyName})
	logger.Debug("Performing schema validation for property")

	// Note: propertyName as a cache key might not be globally unique. Consider ThingID if available.
	compiledSchema, err := v.getCachedOrCompile(logger, propertyName, propertySchema)
	if err != nil {
		// Error already logged by getCachedOrCompile if it's from there
		return fmt.Errorf("schema compilation/retrieval error for property '%s': %w", propertyName, err)
	}
	// A nil compiledSchema is not expected from getCachedOrCompile if err is nil.
	// If propertySchema was empty, it would compile to a permissive schema.

	documentLoader := gojsonschema.NewGoLoader(value)
	result, err := compiledSchema.Validate(documentLoader)
	if err != nil { // This is an error during the validation process itself, not validation failure
		logger.WithError(err).Error("Error during schema validation process")
		return fmt.Errorf("validation error: %w", err)
	}

	if !result.Valid() {
		var errors []string
		for _, desc := range result.Errors() {
			errors = append(errors, fmt.Sprintf("- %s", desc))
		}
		logger.WithField("validation_errors", errors).Warn("Schema validation failed for property")
		return fmt.Errorf("value does not match schema: %s", strings.Join(errors, "; "))
	}

	logger.Debug("Schema validation successful for property")
	return nil
}

func (v *JSONSchemaValidator) ValidateActionInput(logger logrus.FieldLogger, schema wot.DataSchema, input interface{}) error {
	logger = logger.WithFields(logrus.Fields{"validator_method": "ValidateActionInput"})
	logger.Debug("Performing schema validation for action input")

	schemaKeyBytes, err := json.Marshal(schema)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal action input schema for cache key generation")
		return fmt.Errorf("failed to marshal action input schema for cache key generation: %w", err)
	}
	cacheKey := string(schemaKeyBytes)
	logger = logger.WithField("schema_cache_key_hash", cacheKey) // Log hash or part of it if too long

	compiledSchema, err := v.getCachedOrCompile(logger, cacheKey, schema)
	if err != nil {
		return fmt.Errorf("schema compilation/retrieval error for action input: %w", err)
	}
	documentLoader := gojsonschema.NewGoLoader(input)
	result, err := compiledSchema.Validate(documentLoader)
	if err != nil {
		logger.WithError(err).Error("Error during schema validation process for action input")
		return fmt.Errorf("validation error: %w", err)
	}

	if !result.Valid() {
		var errors []string
		for _, desc := range result.Errors() {
			errors = append(errors, fmt.Sprintf("- %s", desc))
		}
		logger.WithField("validation_errors", errors).Warn("Schema validation failed for action input")
		return fmt.Errorf("input does not match schema: %s", strings.Join(errors, "; "))
	}

	logger.Debug("Schema validation successful for action input")
	return nil
}

func (v *JSONSchemaValidator) ValidateEventData(logger logrus.FieldLogger, schema wot.DataSchema, data interface{}) error {
	logger = logger.WithFields(logrus.Fields{"validator_method": "ValidateEventData"})
	logger.Debug("Performing schema validation for event data")

	schemaKeyBytes, err := json.Marshal(schema)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal event data schema for cache key generation")
		return fmt.Errorf("failed to marshal event data schema for cache key generation: %w", err)
	}
	cacheKey := string(schemaKeyBytes)
	logger = logger.WithField("schema_cache_key_hash", cacheKey)

	compiledSchema, err := v.getCachedOrCompile(logger, cacheKey, schema)
	if err != nil {
		return fmt.Errorf("schema compilation/retrieval error for event data: %w", err)
	}
	documentLoader := gojsonschema.NewGoLoader(data)
	result, err := compiledSchema.Validate(documentLoader)
	if err != nil {
		logger.WithError(err).Error("Error during schema validation process for event data")
		return fmt.Errorf("validation error: %w", err)
	}

	if !result.Valid() {
		var errors []string
		for _, desc := range result.Errors() {
			errors = append(errors, fmt.Sprintf("- %s", desc))
		}
		logger.WithField("validation_errors", errors).Warn("Schema validation failed for event data")
		return fmt.Errorf("event data does not match schema: %s", strings.Join(errors, "; "))
	}

	logger.Debug("Schema validation successful for event data")
	return nil
}

// MetricsCollector collects metrics for monitoring

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
