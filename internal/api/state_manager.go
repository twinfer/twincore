// internal/api/state_manager.go
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
	"github.com/apache/arrow/go/v18/parquet/file"
	"github.com/apache/arrow/go/v18/parquet/pqarrow"

	"github.com/twinfer/twincore/internal/models"

	_ "github.com/marcboeker/go-duckdb"
	"github.com/sirupsen/logrus"
)

// DuckDBStateManager implements StateManager using DuckDB
type DuckDBStateManager struct {
	db             *sql.DB
	logger         *logrus.Logger
	subscribers    sync.Map     // map[string][]chan PropertyUpdate
	mu             sync.RWMutex // Protects subscribers map
	parquetLogPath string
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
func (m *DuckDBStateManager) logPropertyToParquet(record models.PropertyStateParquetRecord) error {
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

	// var fw *file.Writer // Parquet file writer
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
		// Convert the single Arrow record to an Arrow table for writing.
		tableFromRecord := array.NewTableFromRecords(schema, []arrow.Record{arrowRecord})
		defer tableFromRecord.Release()

		err = pqarrow.WriteTable(tableFromRecord, f, tableFromRecord.NumRows(), props, pqarrow.ArrowWriterProperties{})
		if err != nil {
			m.logger.WithError(err).Errorf("Failed to write new Parquet table to file: %s", filePath)
			return err
		}
		m.logger.Debugf("Successfully wrote initial record to new Parquet file: %s", filePath)
	} else if statErr == nil { // File exists and stat was successful
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
		// Get FileInfo from the opened file descriptor
		fileInfo, statCheckErr := f.Stat()
		if statCheckErr != nil {
			m.logger.WithError(statCheckErr).Errorf("Failed to stat opened Parquet file: %s", filePath)
			return statCheckErr
		}

		if fileInfo.Size() > 0 { // File exists and is not empty
			// Attempt to read it as a Parquet file.
			// NewParquetReader takes an io.ReadSeeker. f is already an *os.File which implements this.
			// If the file was just opened (O_RDWR), its offset is 0.
			// Seeking to 0,0 explicitly isn't strictly necessary but can be added for clarity if desired.
			pf, errReader := file.NewParquetReader(f)
			if errReader == nil { // Successfully created a low-level Parquet reader
				arrowPqReader, errArrowReader := pqarrow.NewFileReader(pf, pqarrow.ArrowReadProperties{}, memory.DefaultAllocator)
				if errArrowReader == nil {
					existingTable, err = arrowPqReader.ReadTable(context.Background())
					if err != nil {
						m.logger.WithError(err).Warnf("Could not read existing Parquet table using Arrow reader from %s. A new table will be written.", filePath)
						existingTable = nil
					} else {
						defer existingTable.Release()
					}
				} else {
					m.logger.WithError(errArrowReader).Warnf("Failed to create Arrow Parquet reader for %s. A new table will be written.", filePath)
					existingTable = nil
				}
			} else {
				m.logger.WithError(errReader).Warnf("Failed to create low-level Parquet reader for %s (file might be invalid or empty). A new table will be written if applicable.", filePath)
				existingTable = nil
			}
		}

		// Create an Arrow Table from the new record. This table will be used for merging or writing directly.
		newRecordAsTable := array.NewTableFromRecords(schema, []arrow.Record{arrowRecord})
		defer newRecordAsTable.Release()

		var tableToWrite arrow.Table
		if existingTable != nil && existingTable.NumRows() > 0 {
			if !existingTable.Schema().Equal(newRecordAsTable.Schema()) {
				m.logger.Warnf("Schema mismatch between existing table and new record for %s. Overwriting with new record only.", filePath)
				tableToWrite = newRecordAsTable
				tableToWrite.Retain() // Retain because newRecordAsTable is deferred for release, and tableToWrite now shares its data
			} else {
				// Concatenate existing table with the new record
				// Convert both tables to records and combine them
				existingRecords := make([]arrow.Record, 0, existingTable.NumCols())
				tr := array.NewTableReader(existingTable, 0)
				defer tr.Release()

				for tr.Next() {
					rec := tr.Record()
					rec.Retain() // Keep reference to avoid early release
					existingRecords = append(existingRecords, rec)
				}

				// Add the new record
				arrowRecord.Retain() // Keep reference for the combined table
				allRecords := append(existingRecords, arrowRecord)

				// Create merged table from all records
				mergedTable := array.NewTableFromRecords(schema, allRecords)

				// Release all retained records since table now owns them
				for _, rec := range existingRecords {
					rec.Release()
				}
				arrowRecord.Release()

				tableToWrite = mergedTable
			}
		} else {
			// No valid existing data, or existing table was empty. Write only the new record.
			tableToWrite = newRecordAsTable
			tableToWrite.Retain() // Retain for the same reason as above
		}
		defer tableToWrite.Release() // Release the final table that will be written

		// Need to write to a new temp file and then rename, or truncate and write.
		// Truncating and writing is simpler for this context.
		f.Truncate(0)
		f.Seek(0, 0)

		props := parquet.NewWriterProperties(parquet.WithCompression(compress.Codecs.Snappy))
		err = pqarrow.WriteTable(tableToWrite, f, tableToWrite.NumRows(), props, pqarrow.ArrowWriterProperties{})
		if err != nil {
			m.logger.WithError(err).Errorf("Failed to write appended Parquet table to file: %s", filePath)
			return err
		}
		m.logger.Debugf("Successfully wrote/appended record to Parquet file: %s", filePath)
	} else { // statErr is not nil and not os.IsNotExist (i.e., another error occurred during stat)
		m.logger.WithError(statErr).Errorf("Failed to stat Parquet file: %s", filePath)
		return statErr
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
		parquetRecord := models.PropertyStateParquetRecord{
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

func (m *DuckDBStateManager) SubscribeProperty(thingID, propertyName string) (<-chan models.PropertyUpdate, error) {
	ch := make(chan models.PropertyUpdate, 10) // Use models.PropertyUpdate
	key := fmt.Sprintf("%s/%s", thingID, propertyName)

	m.logger.Debugf("New subscription for property: %s", key)

	m.mu.Lock()
	defer m.mu.Unlock()

	if subs, ok := m.subscribers.Load(key); ok {
		channels := subs.([]chan models.PropertyUpdate) // Use models.PropertyUpdate
		channels = append(channels, ch)
		m.subscribers.Store(key, channels)
		m.logger.Debugf("Added subscriber to existing list (total: %d)", len(channels))
	} else {
		m.subscribers.Store(key, []chan models.PropertyUpdate{ch}) // Use models.PropertyUpdate
		m.logger.Debugf("Created new subscriber list for %s", key)
	}

	return ch, nil
}

func (m *DuckDBStateManager) UnsubscribeProperty(thingID, propertyName string, ch <-chan models.PropertyUpdate) {
	key := fmt.Sprintf("%s/%s", thingID, propertyName)

	m.logger.Debugf("Removing subscription for property: %s", key)

	m.mu.Lock()
	defer m.mu.Unlock()

	if subs, ok := m.subscribers.Load(key); ok {
		channels := subs.([]chan models.PropertyUpdate) // Use models.PropertyUpdate
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
				close(c) // No need to cast if ch is already of the correct specific type
				return   // Exit after finding and removing the channel
			}
		}
	}
}

func (m *DuckDBStateManager) notifySubscribers(thingID, propertyName string, value interface{}) {
	key := fmt.Sprintf("%s/%s", thingID, propertyName)

	if subs, ok := m.subscribers.Load(key); ok {
		channels := subs.([]chan models.PropertyUpdate) // Use models.PropertyUpdate

		m.logger.Debugf("Notifying %d subscribers for %s", len(channels), key)

		update := models.PropertyUpdate{ // Use models.PropertyUpdate
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
