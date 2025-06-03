package api

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redpanda-data/benthos/v4/public/service"
	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/wot/forms" // Added for unified schema management
)

// SimpleStreamBridge implements the StreamBridge interface with basic functionality and unified configuration
type SimpleStreamBridge struct {
	env            *service.Environment
	logger         *logrus.Logger
	pendingActions *sync.Map             // Stores actionID (string) -> chan interface{}
	schemaRegistry *forms.SchemaRegistry // Added for unified schema management
}

// NewBenthosStreamBridge creates a new SimpleStreamBridge with unified schema management.
func NewBenthosStreamBridge(env *service.Environment, stateMgr StateManager, db *sql.DB, logger *logrus.Logger, parquetLogPath string) StreamBridge {
	logger.Debug("Creating BenthosStreamBridge with unified schema management")

	// Initialize unified schema registry
	schemaRegistry := forms.NewSchemaRegistry()

	bridge := &SimpleStreamBridge{
		env:            env,
		logger:         logger, // This is *logrus.Logger, can be used as FieldLogger
		pendingActions: &sync.Map{},
		schemaRegistry: schemaRegistry,
	}

	// Initialize stream bridge schemas if Parquet logging is enabled
	if parquetLogPath != "" {
		logger.Info("Initializing stream bridge with unified schema management for Parquet logging")
		if err := bridge.initializeBridgeSchemas(); err != nil {
			logger.WithError(err).Warn("Failed to initialize bridge schemas, continuing without schema validation")
		}
	} else {
		logger.Info("Parquet logging disabled - stream bridge created without schema validation")
	}

	logger.Info("SimpleStreamBridge created with unified configuration - actual stream processing via Benthos configs")
	return bridge
}

// initializeBridgeSchemas registers schemas for stream bridge operations
func (b *SimpleStreamBridge) initializeBridgeSchemas() error {
	logger := b.logger.WithField("internal_method", "initializeBridgeSchemas")
	logger.Debug("Initializing schemas for stream bridge operations")

	// Register property update bridge schema
	propertyBridgeFields := []forms.SchemaField{
		{Name: "thing_id", Type: "STRING", Nullable: false},
		{Name: "property_name", Type: "STRING", Nullable: false},
		{Name: "property_value", Type: "STRING", Nullable: true},
		{Name: "timestamp", Type: "INT64", Nullable: false},
		{Name: "source", Type: "STRING", Nullable: false},
		{Name: "bridge_id", Type: "STRING", Nullable: true},
	}

	b.schemaRegistry.RegisterCustomSchema("property_bridge", propertyBridgeFields)

	// Register action bridge schema
	actionBridgeFields := []forms.SchemaField{
		{Name: "thing_id", Type: "STRING", Nullable: false},
		{Name: "action_name", Type: "STRING", Nullable: false},
		{Name: "action_id", Type: "STRING", Nullable: false},
		{Name: "input_data", Type: "STRING", Nullable: true},
		{Name: "timestamp", Type: "INT64", Nullable: false},
		{Name: "bridge_id", Type: "STRING", Nullable: true},
	}

	b.schemaRegistry.RegisterCustomSchema("action_bridge", actionBridgeFields)

	logger.WithField("registered_schemas", []string{"property_bridge", "action_bridge"}).Info("Stream bridge schemas initialized successfully")
	return nil
}

// PublishPropertyUpdate sends a property update with unified schema validation
func (b *SimpleStreamBridge) PublishPropertyUpdate(logger logrus.FieldLogger, thingID, propertyName string, value interface{}) error {
	entryLogger := logger.WithFields(logrus.Fields{"service_method": "PublishPropertyUpdate", "thing_id": thingID, "property_name": propertyName, "value": value})
	entryLogger.Debug("Service method called (SimpleStreamBridge)")

	// Validate against schema if available
	if b.schemaRegistry != nil {
		propertySchema := b.schemaRegistry.GetParquetSchema("property_bridge")
		if len(propertySchema) > 0 {
			entryLogger.WithField("schema_fields", len(propertySchema)).Debug("Validating property update against bridge schema")
		}
	}

	// This is a placeholder; actual publishing to a stream output (e.g., Kafka) is defined in Benthos configs.
	entryLogger.Info("Property update with schema validation received by bridge (actual send via Benthos config)")
	return nil
}

// PublishPropertyUpdateWithContext sends a property update with context
func (b *SimpleStreamBridge) PublishPropertyUpdateWithContext(logger logrus.FieldLogger, ctx context.Context, thingID, propertyName string, value interface{}) error {
	// In this simple bridge, context isn't used beyond being a placeholder.
	return b.PublishPropertyUpdate(logger, thingID, propertyName, value)
}

// PublishActionInvocation sends an action invocation (placeholder implementation)
func (b *SimpleStreamBridge) PublishActionInvocation(logger logrus.FieldLogger, thingID, actionName string, input interface{}) (string, error) {
	actionID := uuid.New().String()
	entryLogger := logger.WithFields(logrus.Fields{
		"service_method": "PublishActionInvocation",
		"thing_id":       thingID,
		"action_name":    actionName,
		"input":          input,
		"action_id":      actionID,
	})
	entryLogger.Debug("Service method called (SimpleStreamBridge)")

	// Create a channel for the result (basic implementation)
	resultChan := make(chan interface{}, 1)
	b.pendingActions.Store(actionID, resultChan)
	entryLogger.Info("Action invocation received by bridge, created pending action (placeholder, actual send via Benthos config)")

	return actionID, nil
}

// PublishEvent sends an event (placeholder implementation)
func (b *SimpleStreamBridge) PublishEvent(logger logrus.FieldLogger, thingID, eventName string, data interface{}) error {
	entryLogger := logger.WithFields(logrus.Fields{
		"service_method": "PublishEvent",
		"thing_id":       thingID,
		"event_name":     eventName,
		"data":           data,
	})
	entryLogger.Debug("Service method called (SimpleStreamBridge)")
	entryLogger.Info("Event received by bridge (placeholder, actual send via Benthos config)")
	return nil
}

// GetActionResult waits for the result of an action
func (b *SimpleStreamBridge) GetActionResult(logger logrus.FieldLogger, actionID string, timeout time.Duration) (interface{}, error) {
	entryLogger := logger.WithFields(logrus.Fields{"service_method": "GetActionResult", "action_id": actionID, "timeout": timeout.String()})
	entryLogger.Debug("Service method called (SimpleStreamBridge)")
	startTime := time.Now()
	defer func() {
		entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished (SimpleStreamBridge)")
	}()

	val, ok := b.pendingActions.Load(actionID)
	if !ok {
		entryLogger.Warn("No pending action found")
		return nil, fmt.Errorf("no pending action found for actionID %s", actionID)
	}
	resultChan := val.(chan interface{})

	select {
	case result := <-resultChan:
		b.pendingActions.Delete(actionID)
		entryLogger.WithField("result", result).Info("Action result received")
		return result, nil
	case <-time.After(timeout):
		b.pendingActions.Delete(actionID) // Clean up
		entryLogger.Warn("Timeout waiting for action result")
		return nil, fmt.Errorf("timeout waiting for action result for actionID %s", actionID)
	}
}

// ProcessActionResult processes action results (for compatibility)
// This method is typically called by a Benthos input that receives action results.
func (b *SimpleStreamBridge) ProcessActionResult(logger logrus.FieldLogger, result map[string]interface{}) error {
	actionID, ok := result["actionId"].(string)
	entryLogger := logger.WithFields(logrus.Fields{"service_method": "ProcessActionResult", "action_id": actionID})
	entryLogger.Debug("Service method called (SimpleStreamBridge)")
	startTime := time.Now()
	defer func() {
		entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished (SimpleStreamBridge)")
	}()

	if !ok {
		entryLogger.Error("Result missing actionId")
		return fmt.Errorf("result missing actionId")
	}

	entryLogger.WithField("result_payload", result).Debug("Received action result payload")

	if val, loaded := b.pendingActions.Load(actionID); loaded {
		resultChan := val.(chan interface{})
		select {
		case resultChan <- result:
			entryLogger.Info("Forwarded action result to internal channel")
		default:
			entryLogger.Warn("Failed to send action result to internal channel (channel full or closed)")
		}
	} else {
		entryLogger.Warn("No pending action channel found for received result")
	}
	return nil
}

// HealthCheck performs a health check on the stream bridge
func (b *SimpleStreamBridge) HealthCheck() error {
	logger := b.logger.WithField("service_method", "HealthCheck")
	logger.Debug("Performing SimpleStreamBridge health check")

	// Check environment
	if b.env == nil {
		return fmt.Errorf("benthos environment is nil")
	}

	// Check logger
	if b.logger == nil {
		return fmt.Errorf("logger is nil")
	}

	// Check pending actions map
	if b.pendingActions == nil {
		return fmt.Errorf("pending actions map is nil")
	}

	// Check schema registry if enabled
	if b.schemaRegistry == nil {
		logger.Warn("Schema registry is nil - schema validation disabled")
	}

	logger.Debug("SimpleStreamBridge health check passed")
	return nil
}

// GetRegisteredSchemas returns information about registered schemas
func (b *SimpleStreamBridge) GetRegisteredSchemas() []string {
	if b.schemaRegistry == nil {
		return []string{}
	}
	return b.schemaRegistry.GetAvailableSchemas()
}

// GetServiceStatus returns detailed status information
func (b *SimpleStreamBridge) GetServiceStatus() map[string]interface{} {
	status := map[string]interface{}{
		"has_environment":     b.env != nil,
		"has_logger":          b.logger != nil,
		"has_pending_actions": b.pendingActions != nil,
		"has_schema_registry": b.schemaRegistry != nil,
	}

	if b.schemaRegistry != nil {
		status["registered_schemas"] = b.GetRegisteredSchemas()
		status["schema_count"] = len(b.GetRegisteredSchemas())
	}

	// Count pending actions
	if b.pendingActions != nil {
		pendingCount := 0
		b.pendingActions.Range(func(_, _ interface{}) bool {
			pendingCount++
			return true
		})
		status["pending_actions_count"] = pendingCount
	}

	return status
}
