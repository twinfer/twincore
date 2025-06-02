package forms

import (
	"fmt"
	"github.com/twinfer/twincore/pkg/types"
)

// GenerateProcessorChain creates a processor chain based on interaction type and options
func GenerateProcessorChain(interactionType string, options map[string]interface{}) []map[string]interface{} {
	processors := []map[string]interface{}{}

	// Add WoT-specific processor based on interaction type
	switch interactionType {
	case "property":
		processors = append(processors, map[string]interface{}{
			"type": string(types.ProcessorBloblangWoTProperty),
			"config": map[string]interface{}{
				"mapping": "root = this", // Default passthrough, can be customized
			},
		})
	case "action":
		processors = append(processors, map[string]interface{}{
			"type": string(types.ProcessorBloblangWoTAction),
			"config": map[string]interface{}{
				"mapping": "root = this",
			},
		})
	case "event":
		processors = append(processors, map[string]interface{}{
			"type": string(types.ProcessorBloblangWoTEvent),
			"config": map[string]interface{}{
				"mapping": "root = this",
			},
		})
	}

	// Add JSON schema validation if schema is provided
	if schema, ok := options["schema"]; ok {
		processors = append(processors, map[string]interface{}{
			"type": string(types.ProcessorJSONSchema),
			"config": map[string]interface{}{
				"schema": schema,
			},
		})
	}

	// Handle persistence/logging configuration
	if persistenceConfig, ok := options["persistence"].(map[string]interface{}); ok {
		// Check if persistence is enabled
		if enabled, ok := persistenceConfig["enabled"].(bool); ok && enabled {
			// Get format from persistence config
			format := "parquet" // default
			if fmt, ok := persistenceConfig["format"].(string); ok {
				format = fmt
			}

			switch format {
			case "parquet":
				processors = append(processors, map[string]interface{}{
					"type": string(types.ProcessorParquetEncode),
					"config": map[string]interface{}{
						// Call to generateParquetSchema will be updated later if needed
						"schema": generateParquetSchema(interactionType),
					},
				})
			case "json":
				processors = append(processors, map[string]interface{}{
					"type":   string(types.ProcessorJSONEncode),
					"config": map[string]interface{}{},
				})
			case "avro":
				// Future: Add Avro encoding
				processors = append(processors, map[string]interface{}{
					"type":   string(types.ProcessorJSONEncode), // Fallback to JSON for now
					"config": map[string]interface{}{},
				})
			}
		}
	} else if enableParquet, ok := options["enable_parquet"].(bool); ok && enableParquet {
		// Legacy support for enable_parquet flag
		processors = append(processors, map[string]interface{}{
			"type": string(types.ProcessorParquetEncode),
			"config": map[string]interface{}{
				// Call to generateParquetSchema will be updated later if needed
				"schema": generateParquetSchema(interactionType),
			},
		})
	}

	// Add custom processors if provided
	if customProcessors, ok := options["processors"].([]map[string]interface{}); ok {
		processors = append(processors, customProcessors...)
	}

	return processors
}

func generatePropertyMapping(thingID, propName string) string {
	return fmt.Sprintf(`
root.thing_id = "%s"
root.property_name = "%s"
root.value = this.value
root.timestamp = timestamp_unix_nano()
root.source = this.source.or("stream")
`, thingID, propName)
}

func generatePropertyPersistenceMapping(thingID, propName string) string {
	return fmt.Sprintf(`
root.thing_id = "%s"
root.property_name = "%s"
root.value = this.value
root.timestamp = timestamp_unix_nano()
root.source = this.source.or("stream")
`, thingID, propName)
}

func generatePropertyObservationMapping(thingID, propName string) string {
	return fmt.Sprintf(`
# Format for real-time property observation
root.thing_id = "%s"
root.property_name = "%s"
root.value = this.value
root.timestamp = timestamp_unix_nano()
root.change_type = this.change_type.or("update")
root.previous_value = this.previous_value
root.source = this.source.or("device")

# Add metadata for observers
root.metadata = {
  "observable": true,
  "data_type": this.data_type.or("unknown"),
  "unit": this.unit.or(""),
  "quality": this.quality.or("good")
}
`, thingID, propName)
}

func generatePropertyLoggingMapping(thingID, propName string) string {
	// Legacy method - redirect to persistence mapping
	return generatePropertyPersistenceMapping(thingID, propName)
}

func generatePropertyCommandMapping(thingID, propName string) string {
	return fmt.Sprintf(`
# Process incoming property command
root.thing_id = "%s"
root.property_name = "%s"
root.value = this.value
root.command_id = uuid_v4()
root.timestamp = timestamp_unix_nano()
root.source = "http"
root.requester = this.requester.or("anonymous")
root.correlation_id = this.correlation_id.or(uuid_v4())

# Command metadata
root.command_type = "property_write"
root.target_device = "%s"
root.expected_response = true
`, thingID, propName, thingID)
}

func generateDeviceCommandMapping(thingID, propName string) string {
	return fmt.Sprintf(`
# Transform for device-specific protocol
root.device_id = "%s"
root.command = {
  "type": "set_property",
  "property": "%s",
  "value": this.value,
  "timestamp": this.timestamp,
  "command_id": this.command_id,
  "correlation_id": this.correlation_id
}

# Device protocol envelope
root.message_type = "command"
root.target = "%s"
root.reply_to = "twincore.responses." + this.correlation_id
root.expires_at = (timestamp_unix() + 30).ts_format("2006-01-02T15:04:05Z07:00")
`, thingID, propName, thingID)
}

func generateActionInvocationMapping(thingID, actionName string) string {
	return fmt.Sprintf(`
# Process incoming action invocation
root.thing_id = "%s"
root.action_name = "%s"
root.input = this.input
root.action_id = uuid_v4()
root.timestamp = timestamp_unix_nano()
root.source = "http"
root.requester = this.requester.or("anonymous")
root.correlation_id = this.correlation_id.or(uuid_v4())

# Action metadata
root.invocation_type = "action_invoke"
root.target_device = "%s"
root.expected_response = true
root.timeout = this.timeout.or(30)
`, thingID, actionName, thingID)
}

func generateDeviceActionMapping(thingID, actionName string) string {
	return fmt.Sprintf(`
# Transform for device-specific protocol
root.device_id = "%s"
root.command = {
  "type": "invoke_action",
  "action": "%s",
  "input": this.input,
  "timestamp": this.timestamp,
  "action_id": this.action_id,
  "correlation_id": this.correlation_id,
  "timeout": this.timeout
}

# Device protocol envelope
root.message_type = "action"
root.target = "%s"
root.reply_to = "twincore.responses." + this.correlation_id
root.expires_at = (timestamp_unix() + this.timeout).ts_format("2006-01-02T15:04:05Z07:00")
`, thingID, actionName, thingID)
}

func generateActionPersistenceMapping(thingID, actionName string) string {
	return fmt.Sprintf(`
# Normalize action data for persistence
root.thing_id = "%s"
root.action_name = "%s"
root.action_id = this.action_id
root.input = this.input
root.output = this.output
root.status = this.status.or("pending")
root.timestamp = timestamp_unix_nano()
root.duration_ms = this.duration_ms.or(0)
root.error = this.error
root.source = this.source.or("stream")
`, thingID, actionName)
}

func generateEventProcessingMapping(thingID, eventName string) string {
	return fmt.Sprintf(`
# Process incoming event for client distribution
root.thing_id = "%s"
root.event_name = "%s"
root.event_id = uuid_v4()
root.data = this.data
root.timestamp = timestamp_unix_nano()
root.source = this.source.or("device")
root.severity = this.severity.or("info")

# Event metadata for clients
root.event_type = "thing_event"
root.subscription_topic = "things.%s.events.%s"
`, thingID, eventName, thingID, eventName)
}

func generateEventEnrichmentMapping(thingID, eventName string) string {
	return fmt.Sprintf(`
# Enrich event data for client consumption
root.thing_id = "%s"
root.event_name = "%s"
root.event_id = this.event_id
root.data = this.data
root.timestamp = this.timestamp
root.source = this.source
root.severity = this.severity

# Client-specific enrichment
root.subscription_info = {
  "thing_id": "%s",
  "event_name": "%s",
  "client_format": "sse",
  "content_type": "application/json"
}

# Add SSE formatting for web clients
root.sse_data = "event: %s\\ndata: " + json.dumps(this) + "\\n\\n"
`, thingID, eventName, thingID, eventName, eventName)
}

func generateEventPersistenceMapping(thingID, eventName string) string {
	return fmt.Sprintf(`
# Normalize event data for persistence
root.thing_id = "%s"
root.event_name = "%s"
root.event_id = this.event_id.or(uuid_v4())
root.data = this.data
root.timestamp = timestamp_unix_nano()
root.severity = this.severity.or("info")
root.source = this.source.or("stream")
root.subscription_count = this.subscription_count.or(0)
`, thingID, eventName)
}
