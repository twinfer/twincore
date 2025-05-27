// internal/api/wot_benthos_integration.go
package api

import (
	"context"
	"encoding/json"
	"fmt"

	"database/sql"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redpanda-data/benthos/v4/public/service"
	"github.com/sirupsen/logrus"
	// Placeholder for actual Kafka client. In a real scenario, you'd use a library like
	// "github.com/segmentio/kafka-go" or "github.com/confluentinc/confluent-kafka-go/kafka"
	// "github.com/twincore/commons/pkg/kafka" // Example placeholder
)

// Local type definitions, assuming these would ideally come from wot_handler.go or a shared model package.
// These are needed because the methods in StreamIntegration struct and processors use them.
// If wot_handler.go exported these types, they could be used directly.

// PropertyUpdate represents a property change.
type PropertyUpdate struct {
	ThingID      string      `json:"thingId"`
	PropertyName string      `json:"propertyName"`
	Value        interface{} `json:"value"`
	Timestamp    time.Time   `json:"timestamp"`
}

// Event represents a WoT event.
type Event struct {
	ThingID   string      `json:"thingId"`
	EventName string      `json:"eventName"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// StreamIntegration provides methods for Benthos processors to interact with core WoT logic.
// This is a struct that holds references to core components.
type StreamIntegration struct {
	stateManager StateManager // Interface defined in wot_handler.go
	eventBroker  *EventBroker // Defined in wot_handler.go
	streamBridge StreamBridge // Interface defined in wot_handler.go, implemented by BenthosStreamBridge
	logger       *logrus.Logger
}

// NewStreamIntegration creates a new StreamIntegration handler.
func NewStreamIntegration(sm StateManager, eb *EventBroker, sb StreamBridge, logger *logrus.Logger) *StreamIntegration {
	return &StreamIntegration{
		stateManager: sm,
		eventBroker:  eb,
		streamBridge: sb,
		logger:       logger,
	}
}

// ProcessStreamUpdate handles property updates received from a Benthos stream.
func (si *StreamIntegration) ProcessStreamUpdate(update PropertyUpdate) error {
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
	// Optional: Publish property updates as generic events if needed
	// si.eventBroker.Publish(Event{
	// 	ThingID:   update.ThingID,
	// 	EventName: update.PropertyName + "_changed", // Or a more generic event type
	// 	Data:      update.Value,
	// 	Timestamp: update.Timestamp,
	// })
	return nil
}

// ProcessStreamEvent handles events received from a Benthos stream and publishes them via the EventBroker.
func (si *StreamIntegration) ProcessStreamEvent(event Event) error {
	si.logger.Debugf("StreamIntegration: Processing stream event %s for %s", event.EventName, event.ThingID)
	if si.eventBroker == nil {
		si.logger.Error("StreamIntegration: EventBroker is nil in ProcessStreamEvent")
		return fmt.Errorf("StreamIntegration: EventBroker not initialized")
	}
	// Assuming event structure from stream is compatible with EventBroker's Event type
	si.eventBroker.Publish(event) // Event struct is defined in wot_handler.go
	return nil
}

// BenthosStreamBridge implements the StreamBridge interface using Benthos and Kafka.
type BenthosStreamBridge struct {
	env            *service.Environment
	logger         *logrus.Logger
	kafkaProducer  interface{} // Placeholder for an actual Kafka producer instance
	pendingActions *sync.Map   // Stores actionID (string) -> chan interface{}
	// stateManager StateManager // Removed as per simplified constructor for now
	// db *sql.DB // Removed as per simplified constructor for now
}

// NewBenthosStreamBridge creates a new BenthosStreamBridge.
// The stateMgr and db parameters are included to match a potential original signature from container.go,
// but they are not used in this simplified bridge which focuses on Kafka interaction.
// They can be removed if not needed by the bridge's direct responsibilities.
func NewBenthosStreamBridge(env *service.Environment, stateMgr StateManager, db *sql.DB, logger *logrus.Logger) StreamBridge {
	bridge := &BenthosStreamBridge{
		env:            env,
		logger:         logger,
		pendingActions: &sync.Map{},
		// kafkaProducer: kafka.NewProducer(...), // Actual Kafka producer initialization would go here
	}
	// If the bridge itself needs to consume (e.g. action results not via ProcessActionResult),
	// a Kafka consumer would be started here in a goroutine.
	// For now, we assume ProcessActionResult is called by the Benthos processor.
	logger.Info("BenthosStreamBridge created. Kafka producer would be initialized here.")
	return bridge
}

// PublishPropertyUpdate sends a property update to the appropriate Benthos/Kafka topic.
func (b *BenthosStreamBridge) PublishPropertyUpdate(thingID, propertyName string, value interface{}) error {
	msg := map[string]interface{}{
		"deviceId":   thingID, // Matching the 'property-updates' stream's Bloblang
		"property":   propertyName,
		"value":      value,
		"timestamp":  time.Now().UTC().Format(time.RFC3339Nano), // Consistent timestamp format
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		b.logger.WithError(err).Error("BenthosStreamBridge: Failed to marshal property update")
		return fmt.Errorf("failed to marshal property update: %w", err)
	}

	b.logger.Infof("BenthosStreamBridge: Publishing property update for %s/%s. Payload: %s", thingID, propertyName, string(payload))
	// In a real implementation, this would publish to Kafka topic "device.property.updates"
	// e.g., b.kafkaProducer.Publish("device.property.updates", thingID, payload)
	// For now, this is a placeholder. The Benthos stream 'property-updates' consumes this.
	// This method is called by WoTHandler when a property is written via HTTP PUT.
	// The Benthos stream then uses 'wot_property_update' processor which calls integration.ProcessStreamUpdate().
	return nil
}

// PublishActionInvocation sends an action invocation to the Benthos/Kafka topic.
func (b *BenthosStreamBridge) PublishActionInvocation(thingID, actionName string, input interface{}) (string, error) {
	actionID := uuid.New().String()
	msg := map[string]interface{}{
		"thingId":    thingID,    // Matching 'action-invocations' stream's Bloblang
		"actionName": actionName,
		"actionId":   actionID,
		"input":      input,
		"timestamp":  time.Now().UTC().Format(time.RFC3339Nano),
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		b.logger.WithError(err).Error("BenthosStreamBridge: Failed to marshal action invocation")
		return "", fmt.Errorf("failed to marshal action invocation: %w", err)
	}

	// Create a channel to receive the result for this actionID
	resultChan := make(chan interface{}, 1)
	b.pendingActions.Store(actionID, resultChan)

	b.logger.Infof("BenthosStreamBridge: Publishing action invocation for %s/%s (actionID: %s). Payload: %s", thingID, actionName, actionID, string(payload))
	// In a real implementation, this would publish to Kafka topic "wot.action.invocations"
	// e.g., b.kafkaProducer.Publish("wot.action.invocations", thingID, payload)
	// The Benthos stream 'action-invocations' consumes this.
	return actionID, nil
}

// PublishEvent sends an event to the Benthos/Kafka topic.
// This is for application-generated WoT events.
func (b *BenthosStreamBridge) PublishEvent(thingID, eventName string, data interface{}) error {
	msg := map[string]interface{}{
		"deviceId":  thingID, // Matching 'device-events' stream's Bloblang (if this is the target)
		"event":     eventName,
		"data":      data,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		b.logger.WithError(err).Error("BenthosStreamBridge: Failed to marshal event")
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	b.logger.Infof("BenthosStreamBridge: Publishing event for %s/%s. Payload: %s", thingID, eventName, string(payload))
	// This would publish to a Kafka topic, e.g., "app.events" or "device.events" if it's mimicking a device.
	// If it's "device.events", the 'device-events' Benthos stream would consume it.
	// e.g., b.kafkaProducer.Publish("device.events", thingID, payload)
	return nil
}

// GetActionResult waits for the result of an action identified by actionID.
func (b *BenthosStreamBridge) GetActionResult(actionID string, timeout time.Duration) (interface{}, error) {
	b.logger.Infof("BenthosStreamBridge: Waiting for action result for actionID %s (timeout: %s)", actionID, timeout.String())

	val, ok := b.pendingActions.Load(actionID)
	if !ok {
		b.logger.Warnf("BenthosStreamBridge: No pending action found for actionID %s", actionID)
		return nil, fmt.Errorf("no pending action found for actionID %s", actionID)
	}
	resultChan := val.(chan interface{})

	select {
	case result := <-resultChan:
		b.logger.Infof("BenthosStreamBridge: Received result for actionID %s", actionID)
		b.pendingActions.Delete(actionID) // Clean up
		// The result here is expected to be the map[string]interface{} from ProcessActionResult
		return result, nil
	case <-time.After(timeout):
		b.logger.Warnf("BenthosStreamBridge: Timeout waiting for action result for actionID %s", actionID)
		b.pendingActions.Delete(actionID) // Clean up to prevent memory leaks
		return nil, fmt.Errorf("timeout waiting for action result for actionID %s", actionID)
	}
}

// Helper method for WoTActionResultProcessor to call
// This assumes WoTActionResultProcessor has a reference to BenthosStreamBridge or StreamIntegration.
// If StreamIntegration is implemented by BenthosStreamBridge itself, this method can be part of it.
// For now, this is a conceptual link. The WoTActionResultProcessor directly calls integration.ProcessActionResult.
// The BenthosStreamBridge needs to ensure results make it to the GetActionResult method.
// This is achieved if the component calling ProcessActionResult (from WoTActionResultProcessor)
// is the BenthosStreamBridge, or if BSB itself is the StreamIntegration.
// Let's assume WoTActionResultProcessor calls integration.ProcessActionResult, and that
// integration is BenthosStreamBridge. So, BSB needs a ProcessActionResult method.

// ProcessActionResult is called by the Benthos pipeline (WoTActionResultProcessor)
// when an action result is received.
func (b *BenthosStreamBridge) ProcessActionResult(result map[string]interface{}) error {
	actionID, ok := result["actionId"].(string)
	if !ok {
		b.logger.Error("BenthosStreamBridge: ProcessActionResult received result with missing or invalid actionId")
		return fmt.Errorf("result missing actionId")
	}

	if val, loaded := b.pendingActions.Load(actionID); loaded {
		resultChan := val.(chan interface{})
		select {
		case resultChan <- result:
			b.logger.Infof("BenthosStreamBridge: Forwarded action result for actionID %s to pending channel", actionID)
		default:
			// This case should ideally not happen if channel is buffered and GetActionResult is waiting or has timed out.
			// If it happens, it means GetActionResult might have timed out and deleted the channel just before this.
			b.logger.Warnf("BenthosStreamBridge: Failed to send action result for actionID %s to channel, perhaps it was already closed or removed", actionID)
			// The action result is lost for the synchronous caller if this happens after timeout.
		}
	} else {
		b.logger.Warnf("BenthosStreamBridge: ProcessActionResult received result for unknown or timed-out actionID %s", actionID)
		// This can happen if GetActionResult timed out and removed the pending action.
	}
	return nil
}


// CreateWoTStreams creates all necessary Benthos streams for WoT
// The original 'builder *service.StreamBuilder' parameter is also removed as each stream now gets its own builder.
// The 'integration' parameter was for the old StreamIntegration interface/struct, which is no longer directly used by CreateWoTStreams.
// Benthos processors are registered with the new StreamIntegration struct in RegisterWoTProcessors.
func CreateWoTStreams(env *service.Environment) error {
	// Stream configurations remain the same
	streamConfigs := map[string]string{
		"property-updates": `
input:
  kafka:
    addresses: ["localhost:9092"]
    topics: ["device.property.updates"]
    consumer_group: "twincore-property-processor"

pipeline:
  processors:
    - bloblang: |
        # Extract and validate property update
        let thing_id = this.deviceId
        let property_name = this.property
        let value = this.value
        
        root.type = "property_update"
        root.thingId = $thing_id
        root.propertyName = $property_name
        root.value = $value
        root.timestamp = now()
        root.source = "device"

output:
  switch:
    cases:
      - check: this.type == "property_update"
        output:
          processors:
            - type: "wot_property_update"
      - output:
          drop: {}
`,
		"action-invocations": `
input:
  kafka:
    addresses: ["localhost:9092"]
    topics: ["wot.action.invocations"]
    consumer_group: "twincore-action-processor"

pipeline:
  processors:
    - bloblang: |
        # Prepare action for device
        root.deviceId = this.thingId
        root.action = this.actionName
        root.actionId = this.actionId
        root.input = this.input
        root.timestamp = now()

output:
  kafka:
    addresses: ["localhost:9092"]
    topic: "device.action.requests"
    key: ${! json("deviceId") }
`,
		"action-results": `
input:
  kafka:
    addresses: ["localhost:9092"]
    topics: ["device.action.results"]
    consumer_group: "twincore-result-processor"

pipeline:
  processors:
    - bloblang: |
        # Process action result
        root.actionId = this.actionId
        root.status = if this.error != null { "failed" } else { "completed" }
        root.output = this.output
        root.error = this.error
        root.timestamp = now()

output:
  processors:
    - type: "wot_action_result"
`,
		"device-events": `
input:
  kafka:
    addresses: ["localhost:9092"]
    topics: ["device.events"]
    consumer_group: "twincore-event-processor"

pipeline:
  processors:
    - bloblang: |
        # Process device event
        root.type = "event"
        root.thingId = this.deviceId
        root.eventName = this.event
        root.data = this.data
        root.timestamp = now()

output:
  processors:
    - type: "wot_event"
`,
	}

	ctx := context.Background() // Or a more sophisticated context for lifecycle management

	for name, configYAML := range streamConfigs {
		builder := service.NewStreamBuilderFromEnvironment(env) // Use the provided environment
		if err := builder.SetYAML(configYAML); err != nil {
			return fmt.Errorf("failed to set YAML for stream %s: %w", name, err)
		}

		stream, err := builder.Build()
		if err != nil {
			return fmt.Errorf("failed to build stream %s: %w", name, err)
		}

		// TODO: Store the 'stream' object if it needs to be managed later (e.g., for stopping by name).
		// For this function, it seems we just run them. If they need to be stopped individually by this
		// package, they would need to be stored, e.g., in a map.

		go func(sName string, s *service.Stream) {
			if err := s.Run(ctx); err != nil {
				// TODO: Proper logging and error handling for a long-running stream exiting.
				fmt.Printf("Stream %s exited with error: %v\n", sName, err)
			}
		}(name, stream)
		fmt.Printf("Stream %s started\n", name) // Basic logging
	}

	return nil
}

// Custom Benthos processors for WoT

// WoTPropertyUpdateProcessor processes property updates.
type WoTPropertyUpdateProcessor struct {
	integration *StreamIntegration // Changed to the new StreamIntegration struct type
	logger      *logrus.Logger
}

// NewWoTPropertyUpdateProcessor creates a new processor for property updates.
func NewWoTPropertyUpdateProcessor(integration *StreamIntegration, logger *logrus.Logger) *WoTPropertyUpdateProcessor {
	return &WoTPropertyUpdateProcessor{integration: integration, logger: logger}
}

func (p *WoTPropertyUpdateProcessor) Process(ctx context.Context, msg *service.Message) ([]*service.Message, error) {
	if p.integration == nil {
		p.logger.Error("WoTPropertyUpdateProcessor: integration is nil")
		return nil, fmt.Errorf("WoTPropertyUpdateProcessor: integration not initialized")
	}
	content, err := msg.AsBytes()
	if err != nil {
		p.logger.WithError(err).Error("WoTPropertyUpdateProcessor: Failed to get message as bytes")
		return nil, err
	}

	var update PropertyUpdate // Assuming PropertyUpdate is defined elsewhere (e.g. wot_handler.go or a models package)
	if err := json.Unmarshal(content, &update); err != nil {
		p.logger.WithError(err).Errorf("WoTPropertyUpdateProcessor: Failed to unmarshal property update: %s", string(content))
		return nil, err
	}

	// Process through integration
	if err := p.integration.ProcessStreamUpdate(update); err != nil {
		p.logger.WithError(err).Error("WoTPropertyUpdateProcessor: Error processing stream update")
		return nil, err // Propagate error, Benthos might retry or send to dead-letter queue
	}
	p.logger.Debugf("WoTPropertyUpdateProcessor: Successfully processed property update for %s/%s", update.ThingID, update.PropertyName)
	return []*service.Message{msg}, nil
}

// Close is called by Benthos when the processor is shutting down.
func (p *WoTPropertyUpdateProcessor) Close(ctx context.Context) error {
	p.logger.Info("WoTPropertyUpdateProcessor closing.")
	return nil
}

// WoTActionResultProcessor processes action results.
type WoTActionResultProcessor struct {
	integration *StreamIntegration // Changed to the new StreamIntegration struct type
	logger      *logrus.Logger
}

// NewWoTActionResultProcessor creates a new processor for action results.
func NewWoTActionResultProcessor(integration *StreamIntegration, logger *logrus.Logger) *WoTActionResultProcessor {
	return &WoTActionResultProcessor{integration: integration, logger: logger}
}

func (p *WoTActionResultProcessor) Process(ctx context.Context, msg *service.Message) ([]*service.Message, error) {
	if p.integration == nil {
		p.logger.Error("WoTActionResultProcessor: integration is nil")
		return nil, fmt.Errorf("WoTActionResultProcessor: integration not initialized")
	}
	if p.integration.streamBridge == nil {
		p.logger.Error("WoTActionResultProcessor: streamBridge on integration is nil")
		return nil, fmt.Errorf("WoTActionResultProcessor: streamBridge not configured on integration")
	}

	content, err := msg.AsBytes()
	if err != nil {
		p.logger.WithError(err).Error("WoTActionResultProcessor: Failed to get message as bytes")
		return nil, err
	}

	var result map[string]interface{} // Standard map for action results
	if err := json.Unmarshal(content, &result); err != nil {
		p.logger.WithError(err).Errorf("WoTActionResultProcessor: Failed to unmarshal action result: %s", string(content))
		return nil, err
	}

	actionID, _ := result["actionId"].(string) // Used for logging.
	p.logger.Debugf("WoTActionResultProcessor: Received action result for actionID %s", actionID)

	// Call ProcessActionResult on the streamBridge field of the StreamIntegration struct.
	// The streamBridge field should be a *BenthosStreamBridge instance.
	if bridge, ok := p.integration.streamBridge.(*BenthosStreamBridge); ok {
		if err := bridge.ProcessActionResult(result); err != nil {
			p.logger.WithError(err).Errorf("WoTActionResultProcessor: Error processing action result via BenthosStreamBridge for actionID %s", actionID)
			return nil, err
		}
	} else {
		err := fmt.Errorf("WoTActionResultProcessor: streamBridge is not of type *BenthosStreamBridge for actionID %s", actionID)
		p.logger.Error(err.Error())
		return nil, err
	}

	p.logger.Debugf("WoTActionResultProcessor: Successfully processed action result for actionID %s", actionID)
	return []*service.Message{msg}, nil
}

// Close is called by Benthos when the processor is shutting down.
func (p *WoTActionResultProcessor) Close(ctx context.Context) error {
	p.logger.Info("WoTActionResultProcessor closing.")
	return nil
}

// WoTEventProcessor processes events.
type WoTEventProcessor struct {
	integration *StreamIntegration // Changed to the new StreamIntegration struct type
	logger      *logrus.Logger
}

// NewWoTEventProcessor creates a new processor for events.
func NewWoTEventProcessor(integration *StreamIntegration, logger *logrus.Logger) *WoTEventProcessor {
	return &WoTEventProcessor{integration: integration, logger: logger}
}

func (p *WoTEventProcessor) Process(ctx context.Context, msg *service.Message) ([]*service.Message, error) {
	if p.integration == nil {
		p.logger.Error("WoTEventProcessor: integration is nil")
		return nil, fmt.Errorf("WoTEventProcessor: integration not initialized")
	}
	content, err := msg.AsBytes()
	if err != nil {
		p.logger.WithError(err).Error("WoTEventProcessor: Failed to get message as bytes")
		return nil, err
	}

	var event Event // Assuming Event is defined elsewhere (e.g. wot_handler.go or a models package)
	if err := json.Unmarshal(content, &event); err != nil {
		p.logger.WithError(err).Errorf("WoTEventProcessor: Failed to unmarshal event: %s", string(content))
		return nil, err
	}

	// Process through integration
	if err := p.integration.ProcessStreamEvent(event); err != nil {
		p.logger.WithError(err).Error("WoTEventProcessor: Error processing stream event")
		return nil, err
	}
	p.logger.Debugf("WoTEventProcessor: Successfully processed event %s for thing %s", event.EventName, event.ThingID)
	return []*service.Message{msg}, nil
}

// Close is called by Benthos when the processor is shutting down.
func (p *WoTEventProcessor) Close(ctx context.Context) error {
	p.logger.Info("WoTEventProcessor closing.")
	return nil
}

// RegisterWoTProcessors registers custom Benthos processors.
// The 'integration' parameter is now the *StreamIntegration struct.
func RegisterWoTProcessors(env *service.Environment, integration *StreamIntegration, logger *logrus.Logger) error {
	if integration == nil {
		return fmt.Errorf("RegisterWoTProcessors: integration parameter cannot be nil")
	}
	if logger == nil {
		// Fallback logger if none provided, though ideally it should always be provided.
		logger = logrus.New()
		logger.SetLevel(logrus.InfoLevel)
	}

	// Register property update processor
	err := env.RegisterProcessor(
		"wot_property_update",
		service.NewConfigSpec(),
		func(conf *service.ParsedConfig, mgr *service.Resources) (service.Processor, error) {
			return NewWoTPropertyUpdateProcessor(integration, logger.WithField("processor", "wot_property_update")), nil
		},
	)
	if err != nil {
		return fmt.Errorf("failed to register wot_property_update processor: %w", err)
	}

	// Register action result processor
	err = env.RegisterProcessor(
		"wot_action_result",
		service.NewConfigSpec(),
		func(conf *service.ParsedConfig, mgr *service.Resources) (service.Processor, error) {
			return NewWoTActionResultProcessor(integration, logger.WithField("processor", "wot_action_result")), nil
		},
	)
	if err != nil {
		return fmt.Errorf("failed to register wot_action_result processor: %w", err)
	}

	// Register event processor
	err = env.RegisterProcessor(
		"wot_event",
		service.NewConfigSpec(),
		func(conf *service.ParsedConfig, mgr *service.Resources) (service.Processor, error) {
			return NewWoTEventProcessor(integration, logger.WithField("processor", "wot_event")), nil
		},
	)
	if err != nil {
		return fmt.Errorf("failed to register wot_event processor: %w", err)
	}

	logger.Info("Custom WoT Benthos processors registered successfully.")
	return nil
}

// Note: The duplicate RegisterWoTProcessors function signature has been removed.
// The one taking *StreamIntegration (struct) and *logrus.Logger is kept.

// Example Thing Description with forms showing the complete integration
var exampleTD = `{
    "@context": "https://www.w3.org/2019/wot/td/v1",
    "id": "urn:dev:ops:32473-WoTLamp-1234",
    "title": "Smart Lamp",
    "securityDefinitions": {
        "bearer": {
            "scheme": "bearer",
            "in": "header",
            "name": "Authorization"
        }
    },
    "security": ["bearer"],
    "properties": {
        "brightness": {
            "type": "integer",
            "minimum": 0,
            "maximum": 100,
            "observable": true,
            "forms": [{
                "href": "kafka://localhost:9092",
                "contentType": "application/json",
                "op": ["readproperty", "writeproperty", "observeproperty"],
                "kafka:topic": "lamp.brightness"
            }, {
                "href": "/things/lamp/properties/brightness",
                "contentType": "application/json",
                "op": ["readproperty", "writeproperty"]
            }]
        }
    },
    "actions": {
        "fade": {
            "input": {
                "type": "object",
                "properties": {
                    "target": {"type": "integer", "minimum": 0, "maximum": 100},
                    "duration": {"type": "integer", "minimum": 0}
                }
            },
            "forms": [{
                "href": "kafka://localhost:9092",
                "contentType": "application/json",
                "op": ["invokeaction"],
                "kafka:topic": "lamp.actions"
            }]
        }
    },
    "events": {
        "motion": {
            "data": {
                "type": "object",
                "properties": {
                    "detected": {"type": "boolean"}
                }
            },
            "forms": [{
                "href": "kafka://localhost:9092",
                "contentType": "application/json",
                "op": ["subscribeevent"],
                "kafka:topic": "lamp.events.motion"
            }]
        }
    }
}`
