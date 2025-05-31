package api

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/models"
)

// BenthosStreamIntegration is a refactored StreamIntegration that uses Benthos for Parquet
type BenthosStreamIntegration struct {
	stateManager  StateManager
	streamBridge  StreamBridge
	eventBroker   *EventBroker
	logger        logrus.FieldLogger
	parquetClient *SimpleBenthosParquetClient
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
	si := &BenthosStreamIntegration{
		stateManager: stateManager,
		streamBridge: streamBridge,
		eventBroker:  eventBroker,
		logger:       logger,
	}

	// Initialize Benthos Parquet client
	if benthosConfigDir != "" {
		client, err := NewSimpleBenthosParquetClient(benthosConfigDir, "", logger)
		if err != nil {
			logger.WithError(err).Warn("Failed to initialize Benthos Parquet client")
		} else {
			si.parquetClient = client
		}
	}

	return si, nil
}

// ProcessPropertyUpdate handles property updates from streams
func (si *BenthosStreamIntegration) ProcessPropertyUpdate(ctx context.Context, update PropertyUpdate) error {
	// Create stream update context to prevent circular updates
	streamCtx := models.WithUpdateContext(ctx, models.NewUpdateContext(models.UpdateSourceStream))

	// Update state in database (this will NOT trigger another stream publish due to source context)
	if err := si.stateManager.SetPropertyWithContext(streamCtx, update.ThingID, update.PropertyName, update.Value); err != nil {
		return fmt.Errorf("failed to update property state: %w", err)
	}

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

	return nil
}

// ProcessActionResult handles action results from devices
func (si *BenthosStreamIntegration) ProcessActionResult(ctx context.Context, result ActionResult) error {
	// Store result if needed
	// This could be extended to store in a results table

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

	return nil
}

// ProcessStreamEvent handles device events from streams
func (si *BenthosStreamIntegration) ProcessStreamEvent(ctx context.Context, event StreamEvent) error {
	// Log to Parquet via Benthos
	if si.parquetClient != nil {
		if err := si.parquetClient.LogEvent(event.ThingID, event.EventName, event.Data); err != nil {
			si.logger.WithError(err).Error("Failed to log event to Parquet")
		}
	}

	// Publish to event broker for SSE
	brokerEvent := models.Event{
		ThingID:   event.ThingID,
		EventName: event.EventName,
		Data:      event.Data,
		Timestamp: event.Timestamp,
	}

	si.eventBroker.Publish(brokerEvent)

	return nil
}

// Close shuts down the stream integration
func (si *BenthosStreamIntegration) Close() error {
	if si.parquetClient != nil {
		return si.parquetClient.Close()
	}
	return nil
}
