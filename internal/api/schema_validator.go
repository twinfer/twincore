// internal/api/schema_validator.go
package api

import (
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

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

func (v *JSONSchemaValidator) ValidateProperty(property wot.PropertyAffordance, value interface{}) error {
	schema := v.getOrCompileSchema(property.GetName(), property)
	if schema == nil {
		return nil // No schema defined, accept any value
	}

	documentLoader := gojsonschema.NewGoLoader(value)
	result, err := schema.Validate(documentLoader)
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
		return nil
	}

	jsonSchema, err := v.compileSchema(schema)
	if err != nil {
		return err
	}

	documentLoader := gojsonschema.NewGoLoader(input)
	result, err := jsonSchema.Validate(documentLoader)
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
		return nil
	}

	jsonSchema, err := v.compileSchema(schema)
	if err != nil {
		return err
	}

	documentLoader := gojsonschema.NewGoLoader(data)
	result, err := jsonSchema.Validate(documentLoader)
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

func (v *JSONSchemaValidator) getOrCompileSchema(key string, property wot.PropertyAffordance) *gojsonschema.Schema {
	if schema, ok := v.schemaCache[key]; ok {
		return schema
	}

	// This depends on how the property schema is structured
	// For now, return nil if no schema
	return nil
}

func (v *JSONSchemaValidator) compileSchema(schema interface{}) (*gojsonschema.Schema, error) {
	schemaJSON, err := json.Marshal(schema)
	if err != nil {
		return nil, err
	}

	schemaLoader := gojsonschema.NewStringLoader(string(schemaJSON))
	return gojsonschema.NewSchema(schemaLoader)
}

// StreamIntegration handles bidirectional communication between HTTP and streams
type StreamIntegration struct {
	stateManager StateManager
	streamBridge StreamBridge
	eventBroker  *EventBroker
}

func NewStreamIntegration(stateManager StateManager, streamBridge StreamBridge, eventBroker *EventBroker) *StreamIntegration {
	return &StreamIntegration{
		stateManager: stateManager,
		streamBridge: streamBridge,
		eventBroker:  eventBroker,
	}
}

// ProcessStreamUpdate handles property updates from streams
func (s *StreamIntegration) ProcessStreamUpdate(update PropertyUpdate) error {
	// Update state
	if err := s.stateManager.SetProperty(update.ThingID, update.PropertyName, update.Value); err != nil {
		return err
	}

	// Don't republish to stream if it came from stream
	if update.Source == "stream" {
		return nil
	}

	// Publish to stream for other consumers
	return s.streamBridge.PublishPropertyUpdate(update.ThingID, update.PropertyName, update.Value)
}

// ProcessStreamEvent handles events from streams
func (s *StreamIntegration) ProcessStreamEvent(event Event) error {
	// Publish to SSE subscribers
	s.eventBroker.Publish(event)
	return nil
}

// ProcessActionResult handles action results from streams
func (s *StreamIntegration) ProcessActionResult(result map[string]interface{}) error {
	actionID, ok := result["actionId"].(string)
	if !ok {
		return fmt.Errorf("missing actionId in result")
	}

	output := result["output"]
	errorMsg, hasError := result["error"].(string)

	// Update database
	if hasError {
		_, err := s.streamBridge.(*BenthosStreamBridge).db.Exec(`
            UPDATE action_state 
            SET status = 'failed', error = ?, completed_at = ?
            WHERE action_id = ?
        `, errorMsg, time.Now(), actionID)
		return err
	}

	outputJSON, _ := json.Marshal(output)
	_, err := s.streamBridge.(*BenthosStreamBridge).db.Exec(`
        UPDATE action_state 
        SET status = 'completed', output = ?, completed_at = ?
        WHERE action_id = ?
    `, string(outputJSON), time.Now(), actionID)

	if err != nil {
		return err
	}

	// Notify waiter
	if waiter, ok := s.streamBridge.(*BenthosStreamBridge).actionWaiters.Load(actionID); ok {
		resultChan := waiter.(chan ActionResult)
		if hasError {
			resultChan <- ActionResult{Error: fmt.Errorf(errorMsg)}
		} else {
			resultChan <- ActionResult{Output: output}
		}
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
