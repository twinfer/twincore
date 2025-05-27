// internal/api/wot_benthos_integration.go
package api

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/redpanda-data/benthos/v4/public/service"
)

// WoTBenthosProcessor creates Benthos processors for WoT interactions
type WoTBenthosProcessor struct {
	integration *StreamIntegration
}

// CreatePropertyUpdateProcessor creates a Benthos processor for property updates from devices
func (p *WoTBenthosProcessor) CreatePropertyUpdateProcessor() *service.ProcessorConfig {
	return &service.ProcessorConfig{
		Type: "bloblang",
		Bloblang: `
            # Extract property update from device message
            let thing_id = this.deviceId
            let property_name = this.property
            let value = this.value
            
            # Add metadata
            root.type = "property_update"
            root.thingId = $thing_id
            root.propertyName = $property_name
            root.value = $value
            root.timestamp = now()
            root.source = "device"
        `,
	}
}

// CreateActionResultProcessor creates a Benthos processor for action results
func (p *WoTBenthosProcessor) CreateActionResultProcessor() *service.ProcessorConfig {
	return &service.ProcessorConfig{
		Type: "bloblang",
		Bloblang: `
            # Process action result from device
            root.actionId = this.actionId
            root.status = if this.error != null { "failed" } else { "completed" }
            root.output = this.output
            root.error = this.error
            root.timestamp = now()
        `,
	}
}

// CreateEventProcessor creates a Benthos processor for device events
func (p *WoTBenthosProcessor) CreateEventProcessor() *service.ProcessorConfig {
	return &service.ProcessorConfig{
		Type: "bloblang",
		Bloblang: `
            # Process event from device
            root.type = "event"
            root.thingId = this.deviceId
            root.eventName = this.event
            root.data = this.data
            root.timestamp = now()
        `,
	}
}

// CreateWoTStreams creates all necessary Benthos streams for WoT
func CreateWoTStreams(builder *service.StreamBuilder, integration *StreamIntegration) error {
	processor := &WoTBenthosProcessor{integration: integration}

	// Property update stream (from devices to state)
	propertyUpdateYAML := `
input:
  kafka:
    addresses: ["localhost:9092"]
    topics: ["device.property.updates"]
    consumer_group: "twinedge-property-processor"

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
`

	if err := builder.AddStreamFromConfig("property-updates", propertyUpdateYAML); err != nil {
		return fmt.Errorf("failed to create property update stream: %w", err)
	}

	// Action invocation stream (from HTTP to devices)
	actionInvocationYAML := `
input:
  kafka:
    addresses: ["localhost:9092"]
    topics: ["wot.action.invocations"]
    consumer_group: "twinedge-action-processor"

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
`

	if err := builder.AddStreamFromConfig("action-invocations", actionInvocationYAML); err != nil {
		return fmt.Errorf("failed to create action invocation stream: %w", err)
	}

	// Action result stream (from devices back to HTTP)
	actionResultYAML := `
input:
  kafka:
    addresses: ["localhost:9092"]
    topics: ["device.action.results"]
    consumer_group: "twinedge-result-processor"

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
`

	if err := builder.AddStreamFromConfig("action-results", actionResultYAML); err != nil {
		return fmt.Errorf("failed to create action result stream: %w", err)
	}

	// Event stream (from devices to SSE)
	eventYAML := `
input:
  kafka:
    addresses: ["localhost:9092"]
    topics: ["device.events"]
    consumer_group: "twinedge-event-processor"

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
`

	if err := builder.AddStreamFromConfig("device-events", eventYAML); err != nil {
		return fmt.Errorf("failed to create event stream: %w", err)
	}

	// Start all streams
	ctx := context.Background()
	for _, streamName := range []string{"property-updates", "action-invocations", "action-results", "device-events"} {
		if err := builder.RunStream(streamName); err != nil {
			return fmt.Errorf("failed to start stream %s: %w", streamName, err)
		}
	}

	return nil
}

// Custom Benthos processors for WoT

// WoTPropertyUpdateProcessor processes property updates
type WoTPropertyUpdateProcessor struct {
	integration *StreamIntegration
}

func (p *WoTPropertyUpdateProcessor) Process(ctx context.Context, msg *service.Message) ([]*service.Message, error) {
	content, err := msg.AsBytes()
	if err != nil {
		return nil, err
	}

	var update PropertyUpdate
	if err := json.Unmarshal(content, &update); err != nil {
		return nil, err
	}

	// Process through integration
	if err := p.integration.ProcessStreamUpdate(update); err != nil {
		return nil, err
	}

	return []*service.Message{msg}, nil
}

// WoTActionResultProcessor processes action results
type WoTActionResultProcessor struct {
	integration *StreamIntegration
}

func (p *WoTActionResultProcessor) Process(ctx context.Context, msg *service.Message) ([]*service.Message, error) {
	content, err := msg.AsBytes()
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(content, &result); err != nil {
		return nil, err
	}

	// Process through integration
	if err := p.integration.ProcessActionResult(result); err != nil {
		return nil, err
	}

	return []*service.Message{msg}, nil
}

// WoTEventProcessor processes events
type WoTEventProcessor struct {
	integration *StreamIntegration
}

func (p *WoTEventProcessor) Process(ctx context.Context, msg *service.Message) ([]*service.Message, error) {
	content, err := msg.AsBytes()
	if err != nil {
		return nil, err
	}

	var event Event
	if err := json.Unmarshal(content, &event); err != nil {
		return nil, err
	}

	// Process through integration
	if err := p.integration.ProcessStreamEvent(event); err != nil {
		return nil, err
	}

	return []*service.Message{msg}, nil
}

// RegisterWoTProcessors registers custom Benthos processors
func RegisterWoTProcessors(env *service.Environment, integration *StreamIntegration) error {
	// Register property update processor
	err := env.RegisterProcessor(
		"wot_property_update",
		service.NewConfigSpec(),
		func(conf *service.ParsedConfig, mgr *service.Resources) (service.Processor, error) {
			return &WoTPropertyUpdateProcessor{integration: integration}, nil
		},
	)
	if err != nil {
		return err
	}

	// Register action result processor
	err = env.RegisterProcessor(
		"wot_action_result",
		service.NewConfigSpec(),
		func(conf *service.ParsedConfig, mgr *service.Resources) (service.Processor, error) {
			return &WoTActionResultProcessor{integration: integration}, nil
		},
	)
	if err != nil {
		return err
	}

	// Register event processor
	err = env.RegisterProcessor(
		"wot_event",
		service.NewConfigSpec(),
		func(conf *service.ParsedConfig, mgr *service.Resources) (service.Processor, error) {
			return &WoTEventProcessor{integration: integration}, nil
		},
	)

	return err
}

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
