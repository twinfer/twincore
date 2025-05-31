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

// StreamIntegration provides methods for Benthos processors to interact with core WoT logic.
type StreamIntegration struct {
	stateManager   StateManager
	eventBroker    *EventBroker
	streamBridge   StreamBridge
	logger         *logrus.Logger
	parquetLogPath string // Deprecated: Logging now handled by processor chains
}

// NewStreamIntegration creates a new StreamIntegration handler.
func NewStreamIntegration(sm StateManager, eb *EventBroker, sb StreamBridge, logger *logrus.Logger, parquetLogPath string) *StreamIntegration {
	si := &StreamIntegration{
		stateManager:   sm,
		eventBroker:    eb,
		streamBridge:   sb,
		logger:         logger,
		parquetLogPath: parquetLogPath,
	}
	if parquetLogPath != "" {
		logger.Info("Parquet logging will be handled by centralized binding generation")
	}
	return si
}

// ProcessStreamUpdate handles property updates received from a Benthos stream.
func (si *StreamIntegration) ProcessStreamUpdate(update model.PropertyUpdate) error {
	si.logger.Debugf("StreamIntegration: Processing stream update for %s/%s", update.ThingID, update.PropertyName)
	if si.stateManager == nil {
		si.logger.Error("StreamIntegration: StateManager is nil in ProcessStreamUpdate")
		return fmt.Errorf("StreamIntegration: StateManager not initialized")
	}
	err := si.stateManager.SetProperty(update.ThingID, update.PropertyName, update.Value)
	if err != nil {
		si.logger.WithError(err).Errorf("StreamIntegration: Failed to set property for %s/%s", update.ThingID, update.PropertyName)
		return err
	}
	return nil
}

// ProcessStreamEvent handles events received from a Benthos stream and publishes them via the EventBroker.
func (si *StreamIntegration) ProcessStreamEvent(event model.Event) error {
	si.logger.Debugf("StreamIntegration: Processing stream event %s for %s", event.EventName, event.ThingID)

	if si.eventBroker == nil {
		si.logger.Error("StreamIntegration: EventBroker is nil in ProcessStreamEvent, cannot publish event to subscribers")
		return fmt.Errorf("StreamIntegration: EventBroker not initialized")
	}

	si.eventBroker.Publish(event)
	return nil
}

// SimpleStreamBridge implements the StreamBridge interface with basic functionality
type SimpleStreamBridge struct {
	env            *service.Environment
	logger         *logrus.Logger
	pendingActions *sync.Map // Stores actionID (string) -> chan interface{}
}

// NewBenthosStreamBridge creates a new SimpleStreamBridge.
func NewBenthosStreamBridge(env *service.Environment, stateMgr StateManager, db *sql.DB, logger *logrus.Logger, parquetLogPath string) StreamBridge {
	bridge := &SimpleStreamBridge{
		env:            env,
		logger:         logger,
		pendingActions: &sync.Map{},
	}
	logger.Info("SimpleStreamBridge created - stream management handled by centralized binding generator")
	return bridge
}

// PublishPropertyUpdate sends a property update (placeholder implementation)
func (b *SimpleStreamBridge) PublishPropertyUpdate(thingID, propertyName string, value interface{}) error {
	b.logger.Debugf("Property update for %s/%s: %v (handled by centralized binding generation)", thingID, propertyName, value)
	return nil
}

// PublishPropertyUpdateWithContext sends a property update with context
func (b *SimpleStreamBridge) PublishPropertyUpdateWithContext(ctx context.Context, thingID, propertyName string, value interface{}) error {
	return b.PublishPropertyUpdate(thingID, propertyName, value)
}

// PublishActionInvocation sends an action invocation (placeholder implementation)
func (b *SimpleStreamBridge) PublishActionInvocation(thingID, actionName string, input interface{}) (string, error) {
	actionID := uuid.New().String()
	b.logger.Debugf("Action invocation for %s/%s (ID: %s): %v (handled by centralized binding generation)", thingID, actionName, actionID, input)
	
	// Create a channel for the result (basic implementation)
	resultChan := make(chan interface{}, 1)
	b.pendingActions.Store(actionID, resultChan)
	
	return actionID, nil
}

// PublishEvent sends an event (placeholder implementation)
func (b *SimpleStreamBridge) PublishEvent(thingID, eventName string, data interface{}) error {
	b.logger.Debugf("Event for %s/%s: %v (handled by centralized binding generation)", thingID, eventName, data)
	return nil
}

// GetActionResult waits for the result of an action
func (b *SimpleStreamBridge) GetActionResult(actionID string, timeout time.Duration) (interface{}, error) {
	val, ok := b.pendingActions.Load(actionID)
	if !ok {
		return nil, fmt.Errorf("no pending action found for actionID %s", actionID)
	}
	resultChan := val.(chan interface{})

	select {
	case result := <-resultChan:
		b.pendingActions.Delete(actionID)
		return result, nil
	case <-time.After(timeout):
		b.pendingActions.Delete(actionID)
		return nil, fmt.Errorf("timeout waiting for action result for actionID %s", actionID)
	}
}

// ProcessActionResult processes action results (for compatibility)
func (b *SimpleStreamBridge) ProcessActionResult(result map[string]interface{}) error {
	actionID, ok := result["actionId"].(string)
	if !ok {
		return fmt.Errorf("result missing actionId")
	}

	if val, loaded := b.pendingActions.Load(actionID); loaded {
		resultChan := val.(chan interface{})
		select {
		case resultChan <- result:
			b.logger.Debugf("Forwarded action result for actionID %s", actionID)
		default:
			b.logger.Warnf("Failed to send action result for actionID %s", actionID)
		}
	}
	return nil
}