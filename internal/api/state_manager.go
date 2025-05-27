// internal/api/state_manager.go
package api

import (
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
	"github.com/apache/arrow/go/v18/parquet/pqarrow"
	"github.com/apache/arrow/go/v18/parquet/file" // For managing Parquet file reader/writer if needed more granularly


	_ "github.com/marcboeker/go-duckdb"
	"github.com/sirupsen/logrus"
)

// DuckDBStateManager implements StateManager using DuckDB
type DuckDBStateManager struct {
	db             *sql.DB
	logger         *logrus.Logger
	subscribers    sync.Map // map[string][]chan PropertyUpdate
	mu             sync.RWMutex
	parquetLogPath string
}

// PropertyStateParquetRecord defines the schema for Parquet logging of property states.
type PropertyStateParquetRecord struct {
	ThingID      string `parquet:"name=thing_id,type=BYTE_ARRAY,convertedtype=UTF8,logicaltype=STRING"`
	PropertyName string `parquet:"name=property_name,type=BYTE_ARRAY,convertedtype=UTF8,logicaltype=STRING"`
	Value        string `parquet:"name=value,type=BYTE_ARRAY,convertedtype=UTF8,logicaltype=STRING"` // JSON string of the value
	Timestamp    int64  `parquet:"name=timestamp,type=INT64"`                                      // Unix nanoseconds
	Source       string `parquet:"name=source,type=BYTE_ARRAY,convertedtype=UTF8,logicaltype=STRING"`
}


type PropertyUpdate struct {
	ThingID      string      `json:"thingId"`
	PropertyName string      `json:"propertyName"`
	Value        interface{} `json:"value"`
	Timestamp    time.Time   `json:"timestamp"`
	Source       string      `json:"source"` // "http", "stream", "device"
}

func NewDuckDBStateManager(db *sql.DB, logger *logrus.Logger, parquetLogPath string) (*DuckDBStateManager, error) {
	logger.Debug("Creating DuckDB state manager")
	if parquetLogPath == "" {
		logger.Warn("Parquet logging path is empty, Parquet logging will be disabled.")
	} else {
		logger.Infof("Parquet logging for property updates enabled at: %s", parquetLogPath)
	}

	return &DuckDBStateManager{
		db:             db,
		logger:         logger,
		parquetLogPath: parquetLogPath,
	}, nil
}

// logPropertyToParquet writes a property state record to a daily Parquet file.
func (m *DuckDBStateManager) logPropertyToParquet(record PropertyStateParquetRecord) error {
	if m.parquetLogPath == "" {
		return nil // Parquet logging is disabled
	}

	today := time.Now().Format("2006-01-02")
	dirPath := filepath.Join(m.parquetLogPath, "properties")
	filePath := filepath.Join(dirPath, fmt.Sprintf("props_%s.parquet", today))

	if err := os.MkdirAll(dirPath, 0755); err != nil {
		m.logger.WithError(err).Errorf("Failed to create Parquet log directory: %s", dirPath)
		return err
	}
	
	// Define Arrow Schema
	schema := arrow.NewSchema(
		[]arrow.Field{
			{Name: "thing_id", Type: arrow.BinaryTypes.String},
			{Name: "property_name", Type: arrow.BinaryTypes.String},
			{Name: "value", Type: arrow.BinaryTypes.String},
			{Name: "timestamp", Type: arrow.PrimitiveTypes.Int64},
			{Name: "source", Type: arrow.BinaryTypes.String},
		},
		nil, // No metadata
	)

	// Create Arrow Record Builder
	mem := memory.DefaultAllocator
	recordBuilder := array.NewRecordBuilder(mem, schema)
	defer recordBuilder.Release()

	recordBuilder.Field(0).(*array.StringBuilder).Append(record.ThingID)
	recordBuilder.Field(1).(*array.StringBuilder).Append(record.PropertyName)
	recordBuilder.Field(2).(*array.StringBuilder).Append(record.Value)
	recordBuilder.Field(3).(*array.Int64Builder).Append(record.Timestamp)
	recordBuilder.Field(4).(*array.StringBuilder).Append(record.Source)
	
	arrowRecord := recordBuilder.NewRecord()
	defer arrowRecord.Release()

	var fw *file.Writer // Parquet file writer
	var f *os.File
	var err error

	if _, statErr := os.Stat(filePath); os.IsNotExist(statErr) {
		// File does not exist, create it and write new table
		f, err = os.Create(filePath)
		if err != nil {
			m.logger.WithError(err).Errorf("Failed to create Parquet file: %s", filePath)
			return err
		}
		defer f.Close()

		props := parquet.NewWriterProperties(parquet.WithCompression(compress.Codecs.Snappy))
		err = pqarrow.WriteTable(arrowRecord, f, arrowRecord.NumRows(), props, pqarrow.NewFileWriterProperties(props))
		if err != nil {
			m.logger.WithError(err).Errorf("Failed to write new Parquet table to file: %s", filePath)
			return err
		}
		m.logger.Debugf("Successfully wrote initial record to new Parquet file: %s", filePath)
	} else {
		// File exists, attempt to append. This is complex with WriteTable.
		// A robust append involves reading, merging, and rewriting, or using lower-level Parquet APIs.
		// For simplicity here, as per note, we'll log that appending is desired but not fully implemented.
		// Or, we can re-write the file with the new record added to an in-memory representation of existing data.
		// Given the constraint "writing the single record is acceptable", we will overwrite for now by creating a new writer.
		// A more robust append would be:
		// 1. Open existing file with parquet.OpenFile(...)
		// 2. Read all row groups / records into an Arrow table.
		// 3. Append new record to this table.
		// 4. Write the new combined table to a new temp file.
		// 5. Rename temp file to original file.
		// This is too complex for this step.
		// So, we will create a new file or effectively overwrite for this single record.
		// For a daily file, the "append" scenario means adding more records to today's file.
		// The pqarrow.WriteTable is not designed for appending to an existing file directly.
		// We'll open the file in append mode, but this won't work correctly with WriteTable without more logic.
		// Instead, let's use a strategy of reading the existing content if any, appending the new record, and writing back.
		
		// Simplified: For now, we'll just log and not append to avoid complexity.
		// To truly append, one would need to read the existing file, merge records, and write a new file.
		// For this exercise, each call to logPropertyToParquet will create a parquet file with one record if we use WriteTable naively on an opened file.
		// This is not ideal.
		// A better approach for "appending" a single record using pqarrow might involve creating a new file each time or batching.
		// Let's try to use parquet.NewWriterProperties and pqarrow.NewFileWriter to append row groups.

		f, err = os.OpenFile(filePath, os.O_RDWR|os.O_CREATE, 0644) // Open R/W or create
		if err != nil {
			m.logger.WithError(err).Errorf("Failed to open Parquet file for append: %s", filePath)
			return err
		}
		defer f.Close()

		// Read existing table (if any schema is compatible)
        var existingTable arrow.Table
        pf, err := file.NewParquetReader(f)
        if err == nil { // If file is a valid parquet file
            existingTable, err = pqarrow.ReadTable(context.Background(), pf, pqarrow.ArrowReadProperties{})
            if err != nil {
                m.logger.WithError(err).Warnf("Could not read existing Parquet table from %s, will overwrite. This might happen if file is empty or corrupt.", filePath)
				existingTable = nil // Ensure it's nil
            } else {
				defer existingTable.Release()
			}
        } else {
			 m.logger.WithError(err).Warnf("File %s is not a valid parquet file or is empty. A new one will be created.", filePath)
		}


		var finalTable arrow.Table
		if existingTable != nil && existingTable.NumRows() > 0 {
			// Concatenate existing table with new record
			mergedTable, err := array.ConcatenateTables(mem, []arrow.Table{existingTable, arrowRecord})
			if err != nil {
				m.logger.WithError(err).Errorf("Failed to concatenate new record to existing Parquet table data for: %s", filePath)
				return err
			}
			finalTable = mergedTable
			defer finalTable.Release()
		} else {
			finalTable = arrowRecord
			// Retain the new record, it will be written as the first/only table
			finalTable.Retain() // since arrowRecord is deferred released, retain for finalTable
		}
		
		// Need to write to a new temp file and then rename, or truncate and write.
		// Truncating and writing is simpler for this context.
		f.Truncate(0)
		f.Seek(0,0)

		props := parquet.NewWriterProperties(parquet.WithCompression(compress.Codecs.Snappy))
		err = pqarrow.WriteTable(finalTable, f, finalTable.NumRows(), props, pqarrow.NewFileWriterProperties(props))
		if err != nil {
			m.logger.WithError(err).Errorf("Failed to write appended Parquet table to file: %s", filePath)
			return err
		}
		m.logger.Debugf("Successfully wrote/appended record to Parquet file: %s", filePath)

	}
	return nil
}


func (m *DuckDBStateManager) GetProperty(thingID, propertyName string) (interface{}, error) {
	m.logger.Debugf("Getting property: %s/%s", thingID, propertyName)

	var valueJSON string
	err := m.db.QueryRow(`
        SELECT value FROM property_state 
        WHERE thing_id = ? AND property_name = ?
    `, thingID, propertyName).Scan(&valueJSON)

	if err == sql.ErrNoRows {
		m.logger.Debugf("Property not found: %s/%s", thingID, propertyName)
		return nil, fmt.Errorf("property not found")
	}
	if err != nil {
		m.logger.Errorf("Database error getting property: %v", err)
		return nil, err
	}

	var value interface{}
	if err := json.Unmarshal([]byte(valueJSON), &value); err != nil {
		m.logger.Errorf("Failed to unmarshal property value: %v", err)
		return nil, err
	}

	m.logger.Debugf("Retrieved property %s/%s: %v", thingID, propertyName, value)
	return value, nil
}

func (m *DuckDBStateManager) SetProperty(thingID, propertyName string, value interface{}) error {
	m.logger.Debugf("Setting property: %s/%s = %v", thingID, propertyName, value)

	valueJSON, err := json.Marshal(value)
	if err != nil {
		m.logger.Errorf("Failed to marshal property value: %v", err)
		return err
	}

	_, err = m.db.Exec(`
        INSERT OR REPLACE INTO property_state 
        (thing_id, property_name, value, updated_at)
        VALUES (?, ?, ?, ?)
    `, thingID, propertyName, string(valueJSON), time.Now())

	if err != nil {
		m.logger.Errorf("Database error setting property: %v", err)
		return err
	}

	m.logger.Infof("Property updated in DB: %s/%s", thingID, propertyName)

	// Log to Parquet
	if m.parquetLogPath != "" {
		parquetRecord := PropertyStateParquetRecord{
			ThingID:      thingID,
			PropertyName: propertyName,
			Value:        string(valueJSON), // Already marshaled
			Timestamp:    time.Now().UnixNano(),
			Source:       "database_update", // Or determine source more dynamically if available
		}
		if err := m.logPropertyToParquet(parquetRecord); err != nil {
			// Log error but do not fail the SetProperty operation
			m.logger.WithError(err).Error("Failed to log property update to Parquet")
		}
	}

	// Notify subscribers
	m.notifySubscribers(thingID, propertyName, value)

	return nil
}

func (m *DuckDBStateManager) SubscribeProperty(thingID, propertyName string) (<-chan PropertyUpdate, error) {
	ch := make(chan PropertyUpdate, 10)
	key := fmt.Sprintf("%s/%s", thingID, propertyName)

	m.logger.Debugf("New subscription for property: %s", key)

	m.mu.Lock()
	defer m.mu.Unlock()

	if subs, ok := m.subscribers.Load(key); ok {
		channels := subs.([]chan PropertyUpdate)
		channels = append(channels, ch)
		m.subscribers.Store(key, channels)
		m.logger.Debugf("Added subscriber to existing list (total: %d)", len(channels))
	} else {
		m.subscribers.Store(key, []chan PropertyUpdate{ch})
		m.logger.Debugf("Created new subscriber list for %s", key)
	}

	return ch, nil
}

func (m *DuckDBStateManager) UnsubscribeProperty(thingID, propertyName string, ch <-chan PropertyUpdate) {
	key := fmt.Sprintf("%s/%s", thingID, propertyName)

	m.logger.Debugf("Removing subscription for property: %s", key)

	m.mu.Lock()
	defer m.mu.Unlock()

	if subs, ok := m.subscribers.Load(key); ok {
		channels := subs.([]chan PropertyUpdate)
		for i, c := range channels {
			if c == ch {
				channels = append(channels[:i], channels[i+1:]...)
				if len(channels) == 0 {
					m.subscribers.Delete(key)
					m.logger.Debugf("Removed last subscriber for %s", key)
				} else {
					m.subscribers.Store(key, channels)
					m.logger.Debugf("Removed subscriber (remaining: %d)", len(channels))
				}
				close(c.(chan PropertyUpdate))
				return // Exit after finding and removing the channel
			}
		}
	}
}

func (m *DuckDBStateManager) notifySubscribers(thingID, propertyName string, value interface{}) {
	key := fmt.Sprintf("%s/%s", thingID, propertyName)

	if subs, ok := m.subscribers.Load(key); ok {
		channels := subs.([]chan PropertyUpdate)

		m.logger.Debugf("Notifying %d subscribers for %s", len(channels), key)

		update := PropertyUpdate{
			ThingID:      thingID,
			PropertyName: propertyName,
			Value:        value,
			Timestamp:    time.Now(),
			Source:       "http",
		}

		for i, ch := range channels {
			select {
			case ch <- update:
				m.logger.Debugf("Notified subscriber %d", i)
			default:
				m.logger.Warnf("Subscriber %d channel full, skipping", i)
			}
		}
	} else {
		m.logger.Debugf("No subscribers for %s", key)
	}
}

// GetAllProperties returns all properties for a thing
func (m *DuckDBStateManager) GetAllProperties(thingID string) (map[string]interface{}, error) {
	m.logger.Debugf("Getting all properties for thing: %s", thingID)

	rows, err := m.db.Query(`
        SELECT property_name, value FROM property_state
        WHERE thing_id = ?
    `, thingID)
	if err != nil {
		m.logger.Errorf("Database error getting properties: %v", err)
		return nil, err
	}
	defer rows.Close()

	properties := make(map[string]interface{})
	for rows.Next() {
		var name, valueJSON string
		if err := rows.Scan(&name, &valueJSON); err != nil {
			m.logger.Errorf("Failed to scan property row: %v", err)
			continue
		}

		var value interface{}
		if err := json.Unmarshal([]byte(valueJSON), &value); err != nil {
			m.logger.Errorf("Failed to unmarshal property %s: %v", name, err)
			continue
		}

		properties[name] = value
	}

	m.logger.Debugf("Retrieved %d properties for thing %s", len(properties), thingID)
	return properties, nil
}
