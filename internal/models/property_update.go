// internal/models/property_update.go
package models

import (
	"time"
)

// PropertyUpdate defines the structure for property change notifications.
// It is used across different parts of the application, such as API and integrations.
type PropertyUpdate struct {
	ThingID      string      `json:"thingId"`
	PropertyName string      `json:"propertyName"`
	Value        interface{} `json:"value"`
	Timestamp    time.Time   `json:"timestamp"`
	Source       string      `json:"source,omitempty"` // "http", "stream", "device"
}

// Event represents a WoT event.
type Event struct {
	ThingID   string      `json:"thingId"`
	EventName string      `json:"eventName"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// ActionResult represents the result of an action invocation.
type ActionResult struct {
	ThingID    string      `json:"thingId"`
	ActionName string      `json:"actionName"`
	ActionID   string      `json:"actionId"`
	Output     interface{} `json:"output"`
	Status     string      `json:"status"`
	Timestamp  time.Time   `json:"timestamp"`
}

// EventParquetRecord defines the schema for Parquet logging of WoT events.
type EventParquetRecord struct {
	ThingID   string `parquet:"name=thing_id,type=BYTE_ARRAY,convertedtype=UTF8,logicaltype=STRING"`
	EventName string `parquet:"name=event_name,type=BYTE_ARRAY,convertedtype=UTF8,logicaltype=STRING"`
	Data      string `parquet:"name=data,type=BYTE_ARRAY,convertedtype=UTF8,logicaltype=STRING"` // JSON string of the event data
	Timestamp int64  `parquet:"name=timestamp,type=INT64"`                                       // Unix nanoseconds
}

// ActionResultParquetRecord defines the schema for Parquet logging of action results.
type ActionResultParquetRecord struct {
	ThingID    string `parquet:"name=thing_id,type=BYTE_ARRAY,convertedtype=UTF8,logicaltype=STRING"`
	ActionName string `parquet:"name=action_name,type=BYTE_ARRAY,convertedtype=UTF8,logicaltype=STRING"`
	ActionID   string `parquet:"name=action_id,type=BYTE_ARRAY,convertedtype=UTF8,logicaltype=STRING"`
	Output     string `parquet:"name=output,type=BYTE_ARRAY,convertedtype=UTF8,logicaltype=STRING"` // JSON string of the output
	Status     string `parquet:"name=status,type=BYTE_ARRAY,convertedtype=UTF8,logicaltype=STRING"`
	Timestamp  int64  `parquet:"name=timestamp,type=INT64"` // Unix nanoseconds
}
