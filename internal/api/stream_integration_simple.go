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
	model "github.com/twinfer/twincore/internal/models"
)

// SimpleStreamBridge implements the StreamBridge interface with basic functionality
type SimpleStreamBridge struct {
	env            *service.Environment
	logger         *logrus.Logger
	pendingActions *sync.Map // Stores actionID (string) -> chan interface{}
}

// NewBenthosStreamBridge creates a new SimpleStreamBridge.
func NewBenthosStreamBridge(env *service.Environment, stateMgr StateManager, db *sql.DB, logger *logrus.Logger, parquetLogPath string) StreamBridge {
	logger.Debug("Creating NewBenthosStreamBridge (SimpleStreamBridge)")
	bridge := &SimpleStreamBridge{
		env:            env,
		logger:         logger, // This is *logrus.Logger, can be used as FieldLogger
		pendingActions: &sync.Map{},
	}
	logger.Info("SimpleStreamBridge created - message publishing is illustrative as actual stream processing is via Benthos stream configs")
	return bridge
}

// PublishPropertyUpdate sends a property update (placeholder implementation)
func (b *SimpleStreamBridge) PublishPropertyUpdate(logger logrus.FieldLogger, thingID, propertyName string, value interface{}) error {
	entryLogger := logger.WithFields(logrus.Fields{"service_method": "PublishPropertyUpdate", "thing_id": thingID, "property_name": propertyName, "value": value})
	entryLogger.Debug("Service method called (SimpleStreamBridge)")
	// This is a placeholder; actual publishing to a stream output (e.g., Kafka) is defined in Benthos configs.
	entryLogger.Info("Property update received by bridge (placeholder, actual send via Benthos config)")
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
		"thing_id": thingID,
		"action_name": actionName,
		"input": input,
		"action_id": actionID,
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
		"thing_id": thingID,
		"event_name": eventName,
		"data": data,
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
	defer func() { entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished (SimpleStreamBridge)") }()

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
	defer func() { entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished (SimpleStreamBridge)") }()

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