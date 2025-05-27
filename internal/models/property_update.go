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

// EventParquetRecord defines the schema for Parquet logging of WoT events.
type EventParquetRecord struct {
	ThingID   string `parquet:"name=thing_id,type=BYTE_ARRAY,convertedtype=UTF8,logicaltype=STRING"`
	EventName string `parquet:"name=event_name,type=BYTE_ARRAY,convertedtype=UTF8,logicaltype=STRING"`
	Data      string `parquet:"name=data,type=BYTE_ARRAY,convertedtype=UTF8,logicaltype=STRING"` // JSON string of the event data
	Timestamp int64  `parquet:"name=timestamp,type=INT64"`                                       // Unix nanoseconds
}
