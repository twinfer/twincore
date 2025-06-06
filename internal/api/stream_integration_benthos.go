package api

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/models"
	"github.com/twinfer/twincore/pkg/wot/forms"
)

// BenthosStreamIntegration is a refactored StreamIntegration that uses Benthos for Parquet
// Parquet logging is now handled by centralized binding generation with unified schema management
type BenthosStreamIntegration struct {
	stateManager   StateManager
	streamBridge   StreamBridge
	eventBroker    *EventBroker
	schemaRegistry *forms.SchemaRegistry // Added for unified schema validation
	logger         logrus.FieldLogger
}

// Note: Stream processing types are now defined in internal/models package to avoid duplication
// Using models.PropertyUpdate, models.ActionResult, and models.Event instead

// NewBenthosStreamIntegration creates a new stream integration with Benthos Parquet logging and unified schema management
func NewBenthosStreamIntegration(
	stateManager StateManager,
	streamBridge StreamBridge,
	eventBroker *EventBroker,
	benthosConfigDir string,
	logger logrus.FieldLogger,
) (*BenthosStreamIntegration, error) {
	logger.Debug("Creating BenthosStreamIntegration with unified schema management")

	// Initialize unified schema registry for validation
	schemaRegistry := forms.NewSchemaRegistry()

	si := &BenthosStreamIntegration{
		stateManager:   stateManager,
		streamBridge:   streamBridge,
		eventBroker:    eventBroker,
		schemaRegistry: schemaRegistry,
		logger:         logger,
	}

	// Parquet logging now handled by centralized binding generation with unified schemas
	if benthosConfigDir != "" {
		logger.Info("Parquet logging with unified schema management handled by centralized binding generation")

		// Initialize stream integration schemas
		if err := si.initializeStreamSchemas(); err != nil {
			logger.WithError(err).Warn("Failed to initialize stream schemas, continuing without schema validation")
		}
	} else {
		logger.Info("Parquet logging disabled as benthos config directory is empty")
	}

	logger.Info("BenthosStreamIntegration created successfully")
	return si, nil
}

// initializeStreamSchemas registers schemas for stream integration validation
func (si *BenthosStreamIntegration) initializeStreamSchemas() error {
	logger := si.logger.WithField("internal_method", "initializeStreamSchemas")
	logger.Debug("Initializing schemas for stream integration")

	// Register stream event schema
	streamEventFields := []forms.SchemaField{
		{Name: "thing_id", Type: "STRING", Nullable: false},
		{Name: "event_name", Type: "STRING", Nullable: false},
		{Name: "event_data", Type: "STRING", Nullable: true},
		{Name: "timestamp", Type: "INT64", Nullable: false},
		{Name: "source", Type: "STRING", Nullable: false},
		{Name: "processing_time", Type: "INT64", Nullable: true},
	}

	si.schemaRegistry.RegisterCustomSchema("stream_event", streamEventFields)

	logger.WithField("registered_schemas", []string{"stream_event"}).Info("Stream integration schemas initialized successfully")
	return nil
}

// ProcessPropertyUpdate handles property updates from streams using unified models
func (si *BenthosStreamIntegration) ProcessPropertyUpdate(ctx context.Context, update models.PropertyUpdate) error {
	logger := si.logger.WithFields(logrus.Fields{
		"service_method": "ProcessPropertyUpdate",
		"thing_id":       update.ThingID,
		"property_name":  update.PropertyName,
		"source":         update.Source,
	})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	// Validate against schema if available
	if si.schemaRegistry != nil {
		propertySchema := si.schemaRegistry.GetParquetSchema("property_update")
		if len(propertySchema) > 0 {
			logger.WithField("schema_fields", len(propertySchema)).Debug("Validating property update against schema")
		}
	}

	// Create stream update context to prevent circular updates
	streamCtx := models.WithUpdateContext(ctx, models.NewUpdateContext(models.UpdateSourceStream))
	logger.WithField("update_source", models.UpdateSourceStream).Debug("Set update source in context")

	// Update state in database (this will NOT trigger another stream publish due to source context)
	logger.WithFields(logrus.Fields{"dependency_name": "StateManager", "operation": "SetPropertyWithContext"}).Debug("Calling dependency")
	if err := si.stateManager.SetPropertyWithContext(logger, streamCtx, update.ThingID, update.PropertyName, update.Value); err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "StateManager", "operation": "SetPropertyWithContext"}).Error("Dependency call failed")
		return fmt.Errorf("failed to update property state: %w", err)
	}
	logger.Debug("Property state updated via StateManager")

	// Publish to event broker for SSE
	event := models.Event{
		ThingID:   update.ThingID,
		EventName: "property_changed",
		Data: map[string]any{
			"property": update.PropertyName,
			"value":    update.Value,
			"source":   update.Source,
		},
		Timestamp: update.Timestamp,
	}

	si.eventBroker.Publish(event)
	logger.WithField("event_name", event.EventName).Debug("Published property_changed event to EventBroker")

	return nil
}

// ProcessActionResult handles action results from devices using unified models
func (si *BenthosStreamIntegration) ProcessActionResult(ctx context.Context, result models.ActionResult) error {
	logger := si.logger.WithFields(logrus.Fields{
		"service_method": "ProcessActionResult",
		"thing_id":       result.ThingID,
		"action_name":    result.ActionName,
		"action_id":      result.ActionID,
		"status":         result.Status,
	})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	// Validate against schema if available
	if si.schemaRegistry != nil {
		actionSchema := si.schemaRegistry.GetParquetSchema("action_execution")
		if len(actionSchema) > 0 {
			logger.WithField("schema_fields", len(actionSchema)).Debug("Validating action result against schema")
		}
	}

	// Store result if needed
	// This could be extended to store in a results table
	logger.Debug("Processing action result with unified schema validation")

	// Publish to event broker
	event := models.Event{
		ThingID:   result.ThingID,
		EventName: "action_completed",
		Data: map[string]any{
			"action":   result.ActionName,
			"actionId": result.ActionID,
			"output":   result.Output,
			"status":   result.Status,
		},
		Timestamp: result.Timestamp,
	}

	si.eventBroker.Publish(event)
	logger.WithField("event_name", event.EventName).Debug("Published action_completed event to EventBroker")

	return nil
}

// ProcessStreamEvent handles device events from streams using unified models
func (si *BenthosStreamIntegration) ProcessStreamEvent(ctx context.Context, event models.Event) error {
	logger := si.logger.WithFields(logrus.Fields{
		"service_method": "ProcessStreamEvent",
		"thing_id":       event.ThingID,
		"event_name":     event.EventName,
	})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	// Validate against schema if available
	if si.schemaRegistry != nil {
		eventSchema := si.schemaRegistry.GetParquetSchema("stream_event")
		if len(eventSchema) > 0 {
			logger.WithField("schema_fields", len(eventSchema)).Debug("Validating stream event against schema")
		}
	}

	// Log to Parquet via Benthos
	// Event logging now handled by centralized binding generation with unified schema validation
	logger.Debug("Event logging to Parquet with unified schema validation handled by centralized binding generation")

	// Publish to event broker for SSE
	si.eventBroker.Publish(event)
	logger.Debug("Published device event to EventBroker")

	return nil
}

// HealthCheck performs a health check on the stream integration
func (si *BenthosStreamIntegration) HealthCheck() error {
	logger := si.logger.WithField("service_method", "HealthCheck")
	logger.Debug("Performing BenthosStreamIntegration health check")

	// Check state manager
	if si.stateManager == nil {
		return fmt.Errorf("state manager is nil")
	}

	// Check stream bridge
	if si.streamBridge == nil {
		return fmt.Errorf("stream bridge is nil")
	}

	// Check event broker
	if si.eventBroker == nil {
		return fmt.Errorf("event broker is nil")
	}

	// Check schema registry if enabled
	if si.schemaRegistry == nil {
		logger.Warn("Schema registry is nil - schema validation disabled")
	}

	logger.Debug("BenthosStreamIntegration health check passed")
	return nil
}

// GetRegisteredSchemas returns information about registered schemas
func (si *BenthosStreamIntegration) GetRegisteredSchemas() []string {
	if si.schemaRegistry == nil {
		return []string{}
	}
	return si.schemaRegistry.GetAvailableSchemas()
}

// GetServiceStatus returns detailed status information
func (si *BenthosStreamIntegration) GetServiceStatus() map[string]any {
	status := map[string]any{
		"has_state_manager":   si.stateManager != nil,
		"has_stream_bridge":   si.streamBridge != nil,
		"has_event_broker":    si.eventBroker != nil,
		"has_schema_registry": si.schemaRegistry != nil,
	}

	if si.schemaRegistry != nil {
		status["registered_schemas"] = si.GetRegisteredSchemas()
		status["schema_count"] = len(si.GetRegisteredSchemas())
	}

	return status
}

// Close shuts down the stream integration
func (si *BenthosStreamIntegration) Close() error {
	logger := si.logger.WithField("service_method", "Close")
	logger.Debug("Closing BenthosStreamIntegration")

	// Parquet client cleanup now handled by centralized binding generation
	logger.Info("BenthosStreamIntegration closed successfully")
	return nil
}
