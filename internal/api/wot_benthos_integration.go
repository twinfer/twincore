// internal/api/wot_benthos_integration.go
package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/apache/arrow/go/v18/arrow"
	"github.com/apache/arrow/go/v18/arrow/array"
	"github.com/apache/arrow/go/v18/arrow/memory"
	"github.com/apache/arrow/go/v18/parquet"
	"github.com/apache/arrow/go/v18/parquet/compress"
	"github.com/apache/arrow/go/v18/parquet/file" // Added for Parquet file reader
	"github.com/apache/arrow/go/v18/parquet/pqarrow"

	"github.com/google/uuid"
	"github.com/redpanda-data/benthos/v4/public/service"
	"github.com/sirupsen/logrus"
	model "github.com/twinfer/twincore/internal/models" // Assuming models package contains PropertyUpdate, Event, etc.
	// Placeholder for actual Kafka client
)

// Local type definitions
// These are needed because the methods in StreamIntegration struct and processors use them.
// If wot_handler.go exported these types, they could be used directly.

// StreamIntegration provides methods for Benthos processors to interact with core WoT logic.
// This is a struct that holds references to core components.
type StreamIntegration struct {
	stateManager   StateManager // Interface defined in wot_handler.go
	eventBroker    *EventBroker // Defined in wot_handler.go
	streamBridge   StreamBridge // Interface defined in wot_handler.go, implemented by BenthosStreamBridge
	logger         *logrus.Logger
	parquetLogPath string // Path for Parquet logs for events
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
	if parquetLogPath == "" {
		logger.Warn("StreamIntegration: Parquet logging path for events is empty, Parquet logging will be disabled.")
	} else {
		logger.Infof("StreamIntegration: Parquet logging for events enabled at: %s", parquetLogPath)
	}
	return si
}

// logEventToParquet writes an event record to a daily Parquet file.
func (si *StreamIntegration) logEventToParquet(record model.EventParquetRecord) error {
	if si.parquetLogPath == "" {
		return nil // Parquet logging is disabled
	}

	today := time.Now().Format("2006-01-02")
	dirPath := filepath.Join(si.parquetLogPath, "events")
	filePath := filepath.Join(dirPath, fmt.Sprintf("events_%s.parquet", today))

	if err := os.MkdirAll(dirPath, 0755); err != nil {
		si.logger.WithError(err).Errorf("Failed to create Parquet log directory for events: %s", dirPath)
		return err
	}

	schema := arrow.NewSchema(
		[]arrow.Field{
			{Name: "thing_id", Type: arrow.BinaryTypes.String},
			{Name: "event_name", Type: arrow.BinaryTypes.String},
			{Name: "data", Type: arrow.BinaryTypes.String},
			{Name: "timestamp", Type: arrow.PrimitiveTypes.Int64},
		},
		nil,
	)

	mem := memory.DefaultAllocator
	recordBuilder := array.NewRecordBuilder(mem, schema)
	defer recordBuilder.Release()

	recordBuilder.Field(0).(*array.StringBuilder).Append(record.ThingID)
	recordBuilder.Field(1).(*array.StringBuilder).Append(record.EventName)
	recordBuilder.Field(2).(*array.StringBuilder).Append(record.Data)
	recordBuilder.Field(3).(*array.Int64Builder).Append(record.Timestamp)

	arrowRecord := recordBuilder.NewRecord()
	defer arrowRecord.Release()

	f, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE, 0644)
	// Error handling for OpenFile should be immediate
	if err != nil {
		si.logger.WithError(err).Errorf("Failed to open Parquet file for events: %s", filePath)
		return err
	}
	defer f.Close()

	// Read existing table logic, similar to state_manager.go
	var existingTable arrow.Table
	fi, statErr := f.Stat()
	if statErr == nil && fi.Size() > 0 { // File exists and is not empty
		// Attempt to read it as a Parquet file.
		// NewParquetReader takes an io.ReadSeeker, so f should be fine.
		// Ensure file pointer is at the beginning for reading after open
		if _, seekErr := f.Seek(0, 0); seekErr != nil {
			si.logger.WithError(seekErr).Errorf("Failed to seek Parquet file for reading events: %s", filePath)
			return seekErr
		}
		pf, errReader := file.NewParquetReader(f)
		if errReader == nil {
			existingTable, err = pqarrow.ReadTable(context.Background(), pf, pqarrow.ArrowReadProperties{})
			if err != nil {
				si.logger.WithError(err).Warnf("Could not read existing Parquet table from %s for events, will overwrite.", filePath)
				existingTable = nil // Ensure it's nil so a new table is created
			} else {
				defer existingTable.Release()
			}
		} else {
			si.logger.WithError(errReader).Warnf("File %s for events is not a valid parquet file but has size > 0. A new one will be created (overwrite).", filePath)
			existingTable = nil
		}
	} // If statErr is os.IsNotExist or fi.Size() is 0, existingTable remains nil.

	// Create an Arrow Table from the new record.
	newRecordAsTable := array.NewTableFromRecords(schema, []arrow.Record{arrowRecord})
	defer newRecordAsTable.Release()

	var tableToWrite arrow.Table
	if existingTable != nil && existingTable.NumRows() > 0 {
		if !existingTable.Schema().Equal(newRecordAsTable.Schema()) {
			si.logger.Warnf("Schema mismatch between existing event table and new record for %s. Overwriting with new record only.", filePath)
			tableToWrite = newRecordAsTable
			tableToWrite.Retain()
		} else {
			mergedTable, concatErr := array.ConcatenateTables(mem, []arrow.Table{existingTable, newRecordAsTable})
			if concatErr != nil {
				si.logger.WithError(concatErr).Errorf("Failed to concatenate new event record to existing Parquet table data for: %s", filePath)
				return concatErr
			}
			tableToWrite = mergedTable // mergedTable is a new table
		}
	} else {
		tableToWrite = newRecordAsTable
		tableToWrite.Retain() // Retain because newRecordAsTable is deferred for release
	}
	defer tableToWrite.Release()

	if err := f.Truncate(0); err != nil {
		si.logger.WithError(err).Errorf("Failed to truncate Parquet file for events: %s", filePath)
		return err
	}
	if _, err := f.Seek(0, 0); err != nil {
		si.logger.WithError(err).Errorf("Failed to seek Parquet file for events: %s", filePath)
		return err
	}

	props := parquet.NewWriterProperties(parquet.WithCompression(compress.Codecs.Snappy))
	err = pqarrow.WriteTable(tableToWrite, f, tableToWrite.NumRows(), props, pqarrow.NewFileWriterProperties(props))
	if err != nil {
		si.logger.WithError(err).Errorf("Failed to write event Parquet table to file: %s", filePath)
		return err
	}
	si.logger.Debugf("Successfully wrote/appended event record to Parquet file: %s", filePath)
	return nil
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
func (si *StreamIntegration) ProcessStreamEvent(event model.Event) error {
	si.logger.Debugf("StreamIntegration: Processing stream event %s for %s", event.EventName, event.ThingID)

	// Log to Parquet
	if si.parquetLogPath != "" {
		var dataJSON string
		if event.Data != nil {
			dataBytes, marshalErr := json.Marshal(event.Data)
			if marshalErr != nil {
				si.logger.WithError(marshalErr).Error("StreamIntegration: Failed to marshal event data for Parquet logging")
				dataJSON = `{"error": "failed to marshal data"}`
			} else {
				dataJSON = string(dataBytes)
			}
		} else {
			dataJSON = "{}" // Or "null"
		}

		parquetRecord := model.EventParquetRecord{
			ThingID:   event.ThingID,
			EventName: event.EventName,
			Data:      dataJSON,
			Timestamp: event.Timestamp.UnixNano(),
		}
		if err := si.logEventToParquet(parquetRecord); err != nil {
			si.logger.WithError(err).Error("StreamIntegration: Failed to log event to Parquet")
			// Do not fail the main operation
		}
	}

	if si.eventBroker == nil {
		si.logger.Error("StreamIntegration: EventBroker is nil in ProcessStreamEvent, cannot publish event to subscribers")
		return fmt.Errorf("StreamIntegration: EventBroker not initialized")
	}

	si.eventBroker.Publish(event)
	return nil
}

// BenthosStreamBridge implements the StreamBridge interface using Benthos and Kafka.
type BenthosStreamBridge struct {
	env            *service.Environment
	logger         *logrus.Logger
	kafkaProducer  interface{} // Placeholder
	pendingActions *sync.Map   // Stores actionID (string) -> chan interface{}
	parquetLogPath string      // Path for Parquet logs
}

// NewBenthosStreamBridge creates a new BenthosStreamBridge.
func NewBenthosStreamBridge(env *service.Environment, stateMgr StateManager, db *sql.DB, logger *logrus.Logger, parquetLogPath string) StreamBridge {
	bridge := &BenthosStreamBridge{
		env:            env,
		logger:         logger,
		pendingActions: &sync.Map{},
		parquetLogPath: parquetLogPath,
		// kafkaProducer: kafka.NewProducer(...),
	}
	if parquetLogPath == "" {
		logger.Warn("BenthosStreamBridge: Parquet logging path for actions is empty, Parquet logging will be disabled.")
	} else {
		logger.Infof("BenthosStreamBridge: Parquet logging for action invocations enabled at: %s", parquetLogPath)
	}
	logger.Info("BenthosStreamBridge created.")
	return bridge
}

// logActionInvocationToParquet writes an action invocation record to a daily Parquet file.
func (b *BenthosStreamBridge) logActionInvocationToParquet(record model.ActionInvocationParquetRecord) error {
	if b.parquetLogPath == "" {
		return nil // Parquet logging is disabled
	}

	today := time.Now().Format("2006-01-02")
	dirPath := filepath.Join(b.parquetLogPath, "actions")
	filePath := filepath.Join(dirPath, fmt.Sprintf("actions_%s.parquet", today))

	if err := os.MkdirAll(dirPath, 0755); err != nil {
		b.logger.WithError(err).Errorf("Failed to create Parquet log directory for actions: %s", dirPath)
		return err
	}

	schema := arrow.NewSchema(
		[]arrow.Field{
			{Name: "thing_id", Type: arrow.BinaryTypes.String},
			{Name: "action_name", Type: arrow.BinaryTypes.String},
			{Name: "action_id", Type: arrow.BinaryTypes.String},
			{Name: "input", Type: arrow.BinaryTypes.String},
			{Name: "timestamp", Type: arrow.PrimitiveTypes.Int64},
		},
		nil,
	)

	mem := memory.DefaultAllocator
	recordBuilder := array.NewRecordBuilder(mem, schema)
	defer recordBuilder.Release()

	recordBuilder.Field(0).(*array.StringBuilder).Append(record.ThingID)
	recordBuilder.Field(1).(*array.StringBuilder).Append(record.ActionName)
	recordBuilder.Field(2).(*array.StringBuilder).Append(record.ActionID)
	recordBuilder.Field(3).(*array.StringBuilder).Append(record.Input)
	recordBuilder.Field(4).(*array.Int64Builder).Append(record.Timestamp)

	arrowRecord := recordBuilder.NewRecord()
	defer arrowRecord.Release()

	f, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE, 0644)
	// Error handling for OpenFile should be immediate
	if err != nil {
		b.logger.WithError(err).Errorf("Failed to open Parquet file for actions: %s", filePath)
		return err
	}
	defer f.Close()

	// Read existing table logic
	var existingTable arrow.Table
	fi, statErr := f.Stat()
	if statErr == nil && fi.Size() > 0 { // File exists and is not empty
		// Ensure file pointer is at the beginning for reading
		if _, seekErr := f.Seek(0, 0); seekErr != nil {
			b.logger.WithError(seekErr).Errorf("Failed to seek Parquet file for reading actions: %s", filePath)
			return seekErr
		}
		pf, errReader := file.NewParquetReader(f)
		if errReader == nil {
			existingTable, err = pqarrow.ReadTable(context.Background(), pf, pqarrow.ArrowReadProperties{})
			if err != nil {
				b.logger.WithError(err).Warnf("Could not read existing Parquet table from %s for actions, will overwrite.", filePath)
				existingTable = nil
			} else {
				defer existingTable.Release()
			}
		} else {
			b.logger.WithError(errReader).Warnf("File %s for actions is not a valid parquet file but has size > 0. A new one will be created (overwrite).", filePath)
			existingTable = nil
		}
	}

	// Create an Arrow Table from the new record.
	newRecordAsTable := array.NewTableFromRecords(schema, []arrow.Record{arrowRecord})
	defer newRecordAsTable.Release()

	var tableToWrite arrow.Table
	if existingTable != nil && existingTable.NumRows() > 0 {
		mergedTable, concatErr := array.ConcatenateTables(mem, []arrow.Table{existingTable, newRecordAsTable})
		if concatErr != nil {
			b.logger.WithError(concatErr).Errorf("Failed to concatenate new action record to existing Parquet table data for: %s", filePath)
			return concatErr
		}
		tableToWrite = mergedTable
	} else {
		tableToWrite = newRecordAsTable
		tableToWrite.Retain() // Retain because newRecordAsTable is deferred for release
	}
	defer tableToWrite.Release()

	if err := f.Truncate(0); err != nil {
		b.logger.WithError(err).Errorf("Failed to truncate Parquet file for actions: %s", filePath)
		return err
	}
	if _, err := f.Seek(0, 0); err != nil {
		b.logger.WithError(err).Errorf("Failed to seek Parquet file for actions: %s", filePath)
		return err
	}

	props := parquet.NewWriterProperties(parquet.WithCompression(compress.Codecs.Snappy))
	err = pqarrow.WriteTable(tableToWrite, f, tableToWrite.NumRows(), props, pqarrow.NewFileWriterProperties(props))
	if err != nil {
		b.logger.WithError(err).Errorf("Failed to write action invocation Parquet table to file: %s", filePath)
		return err
	}
	b.logger.Debugf("Successfully wrote/appended action invocation record to Parquet file: %s", filePath)
	return nil
}

// PublishPropertyUpdate sends a property update to the appropriate Benthos/Kafka topic.
func (b *BenthosStreamBridge) PublishPropertyUpdate(thingID, propertyName string, value interface{}) error {
	msg := map[string]interface{}{
		"deviceId":  thingID, // Matching the 'property-updates' stream's Bloblang
		"property":  propertyName,
		"value":     value,
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano), // Consistent timestamp format
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
	now := time.Now()

	// Log to Parquet first
	if b.parquetLogPath != "" {
		var inputJSON string
		if input != nil {
			inputBytes, marshalErr := json.Marshal(input)
			if marshalErr != nil {
				b.logger.WithError(marshalErr).Error("BenthosStreamBridge: Failed to marshal action input for Parquet logging")
				// Continue without input in Parquet log, or handle as critical error? For now, log and continue.
				inputJSON = `{"error": "failed to marshal input"}`
			} else {
				inputJSON = string(inputBytes)
			}
		} else {
			inputJSON = "{}" // Or "null" if preferred for nil input
		}

		parquetRecord := model.ActionInvocationParquetRecord{
			ThingID:    thingID,
			ActionName: actionName,
			ActionID:   actionID,
			Input:      inputJSON,
			Timestamp:  now.UnixNano(),
		}
		if err := b.logActionInvocationToParquet(parquetRecord); err != nil {
			b.logger.WithError(err).Error("BenthosStreamBridge: Failed to log action invocation to Parquet")
			// Do not fail the main operation
		}
	}

	// Prepare message for Kafka/Benthos stream
	msg := map[string]interface{}{
		"thingId":    thingID,
		"actionName": actionName,
		"actionId":   actionID,
		"input":      input,
		"timestamp":  now.UTC().Format(time.RFC3339Nano),
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		b.logger.WithError(err).Error("BenthosStreamBridge: Failed to marshal action invocation for Kafka")
		return "", fmt.Errorf("failed to marshal action invocation for Kafka: %w", err)
	}

	// Create a channel to receive the result for this actionID
	resultChan := make(chan interface{}, 1)
	b.pendingActions.Store(actionID, resultChan)

	b.logger.Infof("BenthosStreamBridge: Publishing action invocation for %s/%s (actionID: %s). Payload: %s", thingID, actionName, actionID, string(payload))
	// In a real implementation, this would publish to Kafka topic "wot.action.invocations"
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
	integration *StreamIntegration
	logger      logrus.FieldLogger // Changed to interface
}

// NewWoTPropertyUpdateProcessor creates a new processor for property updates.
func NewWoTPropertyUpdateProcessor(integration *StreamIntegration, logger logrus.FieldLogger) *WoTPropertyUpdateProcessor {
	return &WoTPropertyUpdateProcessor{integration: integration, logger: logger}
}

func (p *WoTPropertyUpdateProcessor) Process(ctx context.Context, msg *service.Message) (service.MessageBatch, error) {
	if p.integration == nil {
		p.logger.Error("WoTPropertyUpdateProcessor: integration is nil")
		return nil, fmt.Errorf("WoTPropertyUpdateProcessor: integration not initialized")
	}
	content, err := msg.AsBytes()
	if err != nil {
		p.logger.WithError(err).Error("WoTPropertyUpdateProcessor: Failed to get message as bytes")
		return nil, err
	}

	var update model.PropertyUpdate // Assuming PropertyUpdate is defined elsewhere (e.g. wot_handler.go or a models package)
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
	return service.MessageBatch{msg}, nil
}

// Close is called by Benthos when the processor is shutting down.
func (p *WoTPropertyUpdateProcessor) Close(ctx context.Context) error {
	p.logger.Info("WoTPropertyUpdateProcessor closing.")
	return nil
}

// WoTActionResultProcessor processes action results.
type WoTActionResultProcessor struct {
	integration *StreamIntegration
	logger      logrus.FieldLogger // Changed to interface
}

// NewWoTActionResultProcessor creates a new processor for action results.
func NewWoTActionResultProcessor(integration *StreamIntegration, logger logrus.FieldLogger) *WoTActionResultProcessor {
	return &WoTActionResultProcessor{integration: integration, logger: logger}
}

func (p *WoTActionResultProcessor) Process(ctx context.Context, msg *service.Message) (service.MessageBatch, error) {
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
	return service.MessageBatch{msg}, nil
}

// Close is called by Benthos when the processor is shutting down.
func (p *WoTActionResultProcessor) Close(ctx context.Context) error {
	p.logger.Info("WoTActionResultProcessor closing.")
	return nil
}

// WoTEventProcessor processes events.
type WoTEventProcessor struct {
	integration *StreamIntegration
	logger      logrus.FieldLogger // Changed to interface
}

// NewWoTEventProcessor creates a new processor for events.
func NewWoTEventProcessor(integration *StreamIntegration, logger logrus.FieldLogger) *WoTEventProcessor {
	return &WoTEventProcessor{integration: integration, logger: logger}
}

func (p *WoTEventProcessor) Process(ctx context.Context, msg *service.Message) (service.MessageBatch, error) {
	if p.integration == nil {
		p.logger.Error("WoTEventProcessor: integration is nil")
		return nil, fmt.Errorf("WoTEventProcessor: integration not initialized")
	}
	content, err := msg.AsBytes()
	if err != nil {
		p.logger.WithError(err).Error("WoTEventProcessor: Failed to get message as bytes")
		return nil, err
	}

	var event model.Event // Using the model.Event type
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
	return service.MessageBatch{msg}, nil
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
