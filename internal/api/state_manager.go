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
	logger         logrus.FieldLogger // Changed to FieldLogger for consistency, though *logrus.Logger also works
	subscribers    sync.Map           // map[string][]chan PropertyUpdate
	mu             sync.RWMutex       // Protects subscribers map
	parquetLogPath string
}

func NewDuckDBStateManager(db *sql.DB, logger logrus.FieldLogger, parquetLogPath string) (*DuckDBStateManager, error) { // Changed logger type
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
	entryLogger := m.logger.WithFields(logrus.Fields{"service_method": "logPropertyToParquet", "thing_id": record.ThingID, "property_name": record.PropertyName})
	entryLogger.Debug("Service method called (internal)")
	startTime := time.Now()
	defer func() { entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished (internal)") }()

	today := time.Now().Format("2006-01-02")
	dirPath := filepath.Join(m.parquetLogPath, "properties")
	filePath := filepath.Join(dirPath, fmt.Sprintf("props_%s.parquet", today))

	entryLogger.WithField("parquet_file_path", filePath).Debug("Attempting to log property to parquet")

	if err := os.MkdirAll(dirPath, 0755); err != nil {
		entryLogger.WithError(err).Errorf("Failed to create Parquet log directory: %s", dirPath)
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
			entryLogger.WithError(err).Errorf("Failed to write new Parquet table to file: %s", filePath)
			return err
		}
		entryLogger.Debugf("Successfully wrote initial record to new Parquet file: %s", filePath)
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
			entryLogger.WithError(err).Errorf("Failed to write appended Parquet table to file: %s", filePath)
			return err
		}
		entryLogger.Debugf("Successfully wrote/appended record to Parquet file: %s", filePath)
	} else { // statErr is not nil and not os.IsNotExist (i.e., another error occurred during stat)
		entryLogger.WithError(statErr).Errorf("Failed to stat Parquet file: %s", filePath)
		return statErr
	}
	return nil
}

func (m *DuckDBStateManager) GetProperty(thingID, propertyName string) (interface{}, error) {
	logger := m.logger.WithFields(logrus.Fields{"service_method": "GetProperty", "thing_id": thingID, "property_name": propertyName})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() { logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	var valueJSON string
	logger.WithFields(logrus.Fields{"dependency_name": "Database", "operation": "QueryRow"}).Debug("Calling dependency")
	err := m.db.QueryRow(`
        SELECT value FROM property_state 
        WHERE thing_id = ? AND property_name = ?
    `, thingID, propertyName).Scan(&valueJSON)

	if err == sql.ErrNoRows {
		logger.Debug("Property not found in DB")
		return nil, fmt.Errorf("property not found")
	}
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "Database", "operation": "QueryRow"}).Error("Dependency call failed")
		return nil, err
	}

	var value interface{}
	if err := json.Unmarshal([]byte(valueJSON), &value); err != nil {
		logger.WithError(err).Error("Failed to unmarshal property value from DB")
		return nil, err
	}

	logger.WithField("retrieved_value", value).Debug("Retrieved property successfully")
	return value, nil
}

func (m *DuckDBStateManager) SetProperty(thingID, propertyName string, value interface{}) error {
	// Use default HTTP source for backward compatibility and a base logger
	ctx := models.WithUpdateContext(context.Background(), models.NewUpdateContext(models.UpdateSourceHTTP))
	// If request_id is needed here, it should be passed or m.logger should be request-scoped.
	// For now, using m.logger directly.
	return m.SetPropertyWithContext(m.logger, ctx, thingID, propertyName, value)
}

func (m *DuckDBStateManager) SetPropertyWithContext(logger logrus.FieldLogger, ctx context.Context, thingID, propertyName string, value interface{}) error {
	entryLogger := logger.WithFields(logrus.Fields{"service_method": "SetPropertyWithContext", "thing_id": thingID, "property_name": propertyName, "value": value})
	entryLogger.Debug("Service method called")
	startTime := time.Now()
	defer func() { entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	// Extract source from context
	source := "unknown"
	if updateCtx, ok := models.GetUpdateContext(ctx); ok {
		source = string(updateCtx.Source)
	}

	if updateCtx, ok := models.GetUpdateContext(ctx); ok {
		source = string(updateCtx.Source)
	}
	logger = logger.WithField("source", source)

	valueJSON, err := json.Marshal(value)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal property value")
		return err
	}

	logger.WithFields(logrus.Fields{"dependency_name": "Database", "operation": "ExecContext"}).Debug("Calling dependency to set property")
	_, err = m.db.ExecContext(ctx, `
        INSERT OR REPLACE INTO property_state 
        (thing_id, property_name, value, updated_at)
        VALUES (?, ?, ?, ?)
    `, thingID, propertyName, string(valueJSON), time.Now())

	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "Database", "operation": "ExecContext"}).Error("Dependency call failed")
		return err
	}

	logger.Info("Property updated in DB")

	// Log to Parquet with source context
	if m.parquetLogPath != "" {
		parquetRecord := models.PropertyStateParquetRecord{
			ThingID:      thingID,
			PropertyName: propertyName,
			Value:        string(valueJSON),
			Timestamp:    time.Now().UnixNano(),
			Source:       source,
		}
		logger.WithField("record", parquetRecord).Debug("Logging property update to Parquet")
		if errLTP := m.logPropertyToParquet(parquetRecord); errLTP != nil { // logPropertyToParquet uses m.logger internally
			logger.WithError(errLTP).Error("Failed to log property update to Parquet")
		}
	}

	// Notify subscribers
	m.notifySubscribers(logger, thingID, propertyName, value) // Pass logger

	return nil
}

func (m *DuckDBStateManager) SubscribeProperty(thingID, propertyName string) (<-chan models.PropertyUpdate, error) {
	// This method's logging can use m.logger as it's not directly in a request path needing a request_id from handler.
	// If request_id were important here, the signature would need to change.
	logger := m.logger.WithFields(logrus.Fields{"service_method": "SubscribeProperty", "thing_id": thingID, "property_name": propertyName})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() { logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	ch := make(chan models.PropertyUpdate, 10)
	key := fmt.Sprintf("%s/%s", thingID, propertyName)

	m.mu.Lock()
	defer m.mu.Unlock()

	if subs, ok := m.subscribers.Load(key); ok {
		channels := subs.([]chan models.PropertyUpdate)
		channels = append(channels, ch)
		m.subscribers.Store(key, channels)
		logger.WithField("total_subscribers", len(channels)).Debug("Added subscriber to existing list")
	} else {
		m.subscribers.Store(key, []chan models.PropertyUpdate{ch})
		logger.Debug("Created new subscriber list")
	}

	return ch, nil
}

func (m *DuckDBStateManager) UnsubscribeProperty(thingID, propertyName string, ch <-chan models.PropertyUpdate) {
	logger := m.logger.WithFields(logrus.Fields{"service_method": "UnsubscribeProperty", "thing_id": thingID, "property_name": propertyName})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() { logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	key := fmt.Sprintf("%s/%s", thingID, propertyName)

	m.mu.Lock()
	defer m.mu.Unlock()

	if subs, ok := m.subscribers.Load(key); ok {
		channels := subs.([]chan models.PropertyUpdate)
		for i, c := range channels {
			if c == ch {
				channels = append(channels[:i], channels[i+1:]...)
				if len(channels) == 0 {
					m.subscribers.Delete(key)
					logger.Debug("Removed last subscriber, deleting list")
				} else {
					m.subscribers.Store(key, channels)
					logger.WithField("remaining_subscribers", len(channels)).Debug("Removed subscriber")
				}
				close(c)
				return
			}
		}
		logger.Warn("Channel not found in subscriber list for key")
	} else {
		logger.Warn("No subscriber list found for key during unsubscribe")
	}
}

func (m *DuckDBStateManager) notifySubscribers(logger logrus.FieldLogger, thingID, propertyName string, value interface{}) {
	key := fmt.Sprintf("%s/%s", thingID, propertyName)
	logger = logger.WithFields(logrus.Fields{"internal_method": "notifySubscribers", "key": key})
	logger.Debug("Notifying subscribers")

	if subs, ok := m.subscribers.Load(key); ok {
		channels := subs.([]chan models.PropertyUpdate)
		logger.WithField("subscriber_count", len(channels)).Debug("Found subscribers to notify")

		update := models.PropertyUpdate{
			ThingID:      thingID,
			PropertyName: propertyName,
			Value:        value,
			Timestamp:    time.Now(),
			Source:       "http", // TODO: This source might not always be accurate if SetProperty is called internally
		}

		for i, ch := range channels {
			select {
			case ch <- update:
				logger.WithField("subscriber_index", i).Debug("Notified subscriber")
			default:
				logger.WithField("subscriber_index", i).Warn("Subscriber channel full, skipping notification")
			}
		}
	} else {
		logger.Debug("No subscribers for property")
	}
}

// GetAllProperties returns all properties for a thing
func (m *DuckDBStateManager) GetAllProperties(thingID string) (map[string]interface{}, error) {
	logger := m.logger.WithFields(logrus.Fields{"service_method": "GetAllProperties", "thing_id": thingID})
	logger.Debug("Service method called")
	startTime := time.Now()
	defer func() { logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished") }()

	logger.WithFields(logrus.Fields{"dependency_name": "Database", "operation": "Query"}).Debug("Calling dependency")
	rows, err := m.db.Query(`
        SELECT property_name, value FROM property_state
        WHERE thing_id = ?
    `, thingID)
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "Database", "operation": "Query"}).Error("Dependency call failed")
		return nil, err
	}
	defer rows.Close()

	properties := make(map[string]interface{})
	for rows.Next() {
		var name, valueJSON string
		if err := rows.Scan(&name, &valueJSON); err != nil {
			logger.WithError(err).Error("Failed to scan property row from DB")
			continue // Or handle more gracefully
		}

		var value interface{}
		if err := json.Unmarshal([]byte(valueJSON), &value); err != nil {
			logger.WithError(err).WithField("property_name", name).Error("Failed to unmarshal property value from DB")
			continue
		}

		properties[name] = value
	}
	if err = rows.Err(); err != nil { // Check for errors during iteration
		logger.WithError(err).Error("Error iterating over property rows from DB")
		return properties, err // Return what was processed so far, along with the error
	}

	logger.WithField("property_count", len(properties)).Debug("Retrieved properties successfully")
	return properties, nil
}
