// internal/api/schema_validator.go
package api

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/wot"
	"github.com/xeipuuv/gojsonschema"
)

// Embed the WoT TD 1.1 JSON Schema for validation
//
//go:embed schema/td-json-schema-validation.json
var wotTDSchema []byte

// JSONSchemaValidator implements SchemaValidator using JSON Schema
type JSONSchemaValidator struct {
	schemaCache map[string]*gojsonschema.Schema
	tdSchema    *gojsonschema.Schema // Compiled TD schema for validation
	// logger logrus.FieldLogger // No longer storing logger in struct, passed via methods
}

func NewJSONSchemaValidator() *JSONSchemaValidator {
	// Logger is no longer initialized here
	validator := &JSONSchemaValidator{
		schemaCache: make(map[string]*gojsonschema.Schema),
	}

	// Compile the embedded TD schema
	schemaLoader := gojsonschema.NewBytesLoader(wotTDSchema)
	if compiledSchema, err := gojsonschema.NewSchema(schemaLoader); err == nil {
		validator.tdSchema = compiledSchema
	} else {
		// Log error but continue - validator can still work for property/action/event validation
		// The TD validation will just be less comprehensive
		validator.tdSchema = nil
	}

	return validator
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

func (v *JSONSchemaValidator) ValidateProperty(logger logrus.FieldLogger, propertyName string, propertySchema wot.DataSchema, value any) error {
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

func (v *JSONSchemaValidator) ValidateActionInput(logger logrus.FieldLogger, schema wot.DataSchema, input any) error {
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

func (v *JSONSchemaValidator) ValidateEventData(logger logrus.FieldLogger, schema wot.DataSchema, data any) error {
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

// ValidateThingDescription validates a complete Thing Description against WoT TD 1.1 specification
func (v *JSONSchemaValidator) ValidateThingDescription(logger logrus.FieldLogger, td *wot.ThingDescription) error {
	logger = logger.WithFields(logrus.Fields{"validator_method": "ValidateThingDescription", "thing_id": td.ID})
	logger.Debug("Performing Thing Description validation")

	// Layer 1: Fast basic compliance check (mandatory fields, basic structure)
	if issues := td.ValidateBasicCompliance(); len(issues) > 0 {
		logger.WithField("compliance_issues", issues).Warn("Basic compliance validation failed")
		return fmt.Errorf("Thing Description validation failed: %s", strings.Join(issues, "; "))
	}

	// Layer 2: Comprehensive JSON Schema validation (if available)
	if v.tdSchema != nil {
		// Marshal the TD to JSON for validation
		tdJSON, err := json.Marshal(td)
		if err != nil {
			logger.WithError(err).Error("Failed to marshal Thing Description for validation")
			return fmt.Errorf("failed to marshal Thing Description: %w", err)
		}

		// Validate against the JSON Schema
		documentLoader := gojsonschema.NewBytesLoader(tdJSON)
		result, err := v.tdSchema.Validate(documentLoader)
		if err != nil {
			logger.WithError(err).Error("Error during Thing Description schema validation")
			return fmt.Errorf("schema validation error: %w", err)
		}

		if !result.Valid() {
			var errors []string
			for _, desc := range result.Errors() {
				errors = append(errors, fmt.Sprintf("- %s", desc))
			}
			logger.WithField("validation_errors", errors).Warn("Thing Description schema validation failed")
			return fmt.Errorf("Thing Description does not match schema: %s", strings.Join(errors, "; "))
		}
	} else {
		logger.Warn("TD schema not available, using basic validation only")
	}

	// Layer 3: Semantic validation beyond JSON Schema
	if err := v.validateSemanticRules(logger, td); err != nil {
		return fmt.Errorf("semantic validation failed: %w", err)
	}

	logger.Debug("Thing Description validation successful")
	return nil
}

// validateSemanticRules performs semantic validation beyond what JSON Schema can provide
func (v *JSONSchemaValidator) validateSemanticRules(logger logrus.FieldLogger, td *wot.ThingDescription) error {
	// Validate security references
	if err := v.validateSecurityReferences(logger, td); err != nil {
		return err
	}

	// Validate operation types for all affordances
	if err := v.validateOperationTypes(logger, td); err != nil {
		return err
	}

	return nil
}

// validateSecurityReferences ensures all security references are defined
func (v *JSONSchemaValidator) validateSecurityReferences(logger logrus.FieldLogger, td *wot.ThingDescription) error {
	// Check each security declaration has a corresponding definition
	for _, secName := range td.Security {
		if secName == "nosec" {
			continue // nosec doesn't need a definition
		}

		if _, exists := td.SecurityDefinitions[secName]; !exists {
			return fmt.Errorf("security scheme '%s' is not defined in securityDefinitions", secName)
		}
	}

	// Check security references in forms
	var checkFormSecurity func(forms []wot.Form) error
	checkFormSecurity = func(forms []wot.Form) error {
		for _, form := range forms {
			if secRefs := form.GetSecurity(); len(secRefs) > 0 {
				for _, secRef := range secRefs {
					if secRef != "nosec" && td.SecurityDefinitions != nil {
						if _, exists := td.SecurityDefinitions[secRef]; !exists {
							return fmt.Errorf("form references undefined security scheme '%s'", secRef)
						}
					}
				}
			}
		}
		return nil
	}

	// Check properties
	for _, prop := range td.Properties {
		if err := checkFormSecurity(prop.Forms); err != nil {
			return err
		}
	}

	// Check actions
	for _, action := range td.Actions {
		if err := checkFormSecurity(action.Forms); err != nil {
			return err
		}
	}

	// Check events
	for _, event := range td.Events {
		if err := checkFormSecurity(event.Forms); err != nil {
			return err
		}
	}

	// Check root forms
	if err := checkFormSecurity(td.Forms); err != nil {
		return err
	}

	return nil
}

// validateOperationTypes ensures operation types match their affordance context
func (v *JSONSchemaValidator) validateOperationTypes(logger logrus.FieldLogger, td *wot.ThingDescription) error {
	// Validate properties
	for propName, prop := range td.Properties {
		if issues := prop.ValidateOperationTypes(); len(issues) > 0 {
			logger.WithField("property", propName).WithField("operation_issues", issues).Warn("Invalid operation types for property")
			return fmt.Errorf("property '%s': %s", propName, issues[0])
		}
	}

	// Validate actions
	for actionName, action := range td.Actions {
		if issues := action.ValidateOperationTypes(); len(issues) > 0 {
			logger.WithField("action", actionName).WithField("operation_issues", issues).Warn("Invalid operation types for action")
			return fmt.Errorf("action '%s': %s", actionName, issues[0])
		}
	}

	// Validate events
	for eventName, event := range td.Events {
		if issues := event.ValidateOperationTypes(); len(issues) > 0 {
			logger.WithField("event", eventName).WithField("operation_issues", issues).Warn("Invalid operation types for event")
			return fmt.Errorf("event '%s': %s", eventName, issues[0])
		}
	}

	return nil
}

// GetTDSchema returns the compiled WoT TD schema for external use
func (v *JSONSchemaValidator) GetTDSchema() *gojsonschema.Schema {
	return v.tdSchema
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
