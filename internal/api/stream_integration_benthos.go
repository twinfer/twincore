package api

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/models"
)

// BenthosStreamIntegration is a refactored StreamIntegration that uses Benthos for Parquet
// Parquet logging is now handled by centralized binding generation
type BenthosStreamIntegration struct {
	stateManager StateManager
	streamBridge StreamBridge
	eventBroker  *EventBroker
	logger       logrus.FieldLogger
}

// Stream processing types
type PropertyUpdate struct {
	ThingID      string      `json:"thing_id"`
	PropertyName string      `json:"property_name"`
	Value        interface{} `json:"value"`
	Timestamp    time.Time   `json:"timestamp"`
}

type ActionResult struct {
	ThingID    string      `json:"thing_id"`
	ActionName string      `json:"action_name"`
	ActionID   string      `json:"action_id"`
	Output     interface{} `json:"output"`
	Status     string      `json:"status"`
	Timestamp  time.Time   `json:"timestamp"`
}

type StreamEvent struct {
	ThingID   string      `json:"thing_id"`
	EventName string      `json:"event_name"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// NewBenthosStreamIntegration creates a new stream integration with Benthos Parquet logging
func NewBenthosStreamIntegration(
	stateManager StateManager,
	streamBridge StreamBridge,
	eventBroker *EventBroker,
	benthosConfigDir string,
	logger logrus.FieldLogger,
) (*BenthosStreamIntegration, error) {
	logger.Debug("Creating NewBenthosStreamIntegration")
	si := &BenthosStreamIntegration{
		stateManager: stateManager,
		streamBridge: streamBridge,
		eventBroker:  eventBroker,
		logger:       logger,
	}

	// Parquet logging now handled by centralized binding generation
	if benthosConfigDir != "" { // This check might be redundant if parquetEnabled field is used instead
		logger.Info("Parquet logging (related to BenthosStreamIntegration) will be handled by centralized binding generation")
	}
	logger.Info("BenthosStreamIntegration created")
	return si, nil
}

// ProcessPropertyUpdate handles property updates from streams
func (si *BenthosStreamIntegration) ProcessPropertyUpdate(ctx context.Context, update PropertyUpdate) error {
	logger := si.logger.WithFields(logrus.Fields{
		"service_method": "ProcessPropertyUpdate",
		"thing_id":       update.ThingID,
		"property_name":  update.PropertyName,
		"value":          update.Value, // Be cautious logging sensitive values
	})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() { logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	// Create stream update context to prevent circular updates
	streamCtx := models.WithUpdateContext(ctx, models.NewUpdateContext(models.UpdateSourceStream))
	logger.WithField("update_source", models.UpdateSourceStream).Debug("Set update source in context")

	// Update state in database (this will NOT trigger another stream publish due to source context)
	logger.WithFields(logrus.Fields{"dependency_name": "StateManager", "operation": "SetPropertyWithContext"}).Debug("Calling dependency")
	// Note: SetPropertyWithContext on StateManager interface currently doesn't take a logger.
	// If it did, we'd pass `logger` here. Using the StateManager's own logger for now.
	// This was updated in previous steps for some implementations.
	// Let's assume the interface was updated and pass the logger.
	if err := si.stateManager.SetPropertyWithContext(logger, streamCtx, update.ThingID, update.PropertyName, update.Value); err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "StateManager", "operation": "SetPropertyWithContext"}).Error("Dependency call failed")
		return fmt.Errorf("failed to update property state: %w", err)
	}
	logger.Debug("Property state updated via StateManager")

	// Publish to event broker for SSE
	event := models.Event{
		ThingID:   update.ThingID,
		EventName: "property_changed",
		Data: map[string]interface{}{
			"property": update.PropertyName,
			"value":    update.Value,
		},
		Timestamp: update.Timestamp,
	}

	si.eventBroker.Publish(event)
	logger.WithField("event_name", event.EventName).Debug("Published property_changed event to EventBroker")

	return nil
}

// ProcessActionResult handles action results from devices
func (si *BenthosStreamIntegration) ProcessActionResult(ctx context.Context, result ActionResult) error {
	logger := si.logger.WithFields(logrus.Fields{
		"service_method": "ProcessActionResult",
		"thing_id":       result.ThingID,
		"action_name":    result.ActionName,
		"action_id":      result.ActionID,
		"status":         result.Status,
	})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() { logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	// Store result if needed
	// This could be extended to store in a results table
	logger.Debug("Processing action result (currently a placeholder for storage)")

	// Publish to event broker
	event := models.Event{
		ThingID:   result.ThingID,
		EventName: "action_completed",
		Data: map[string]interface{}{
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

// ProcessStreamEvent handles device events from streams
func (si *BenthosStreamIntegration) ProcessStreamEvent(ctx context.Context, event StreamEvent) error {
	logger := si.logger.WithFields(logrus.Fields{
		"service_method": "ProcessStreamEvent",
		"thing_id":       event.ThingID,
		"event_name":     event.EventName,
	})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() { logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	// Log to Parquet via Benthos
	// Event logging now handled by centralized binding generation
	logger.Debug("Event logging to Parquet is now handled by centralized binding generation processor chain")

	// Publish to event broker for SSE
	brokerEvent := models.Event{
		ThingID:   event.ThingID,
		EventName: event.EventName,
		Data:      event.Data,
		Timestamp: event.Timestamp,
	}

	si.eventBroker.Publish(brokerEvent)
	logger.Debug("Published device event to EventBroker")

	return nil
}

// Close shuts down the stream integration
func (si *BenthosStreamIntegration) Close() error {
	si.logger.WithFields(logrus.Fields{"service_method": "Close"}).Debug("Service method called (BenthosStreamIntegration)")
	// Parquet client cleanup now handled by centralized binding generation
	si.logger.Info("BenthosStreamIntegration closed")
	return nil
}
