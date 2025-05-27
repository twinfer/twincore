package api

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/apache/arrow/go/v18/arrow"
	"github.com/apache/arrow/go/v18/arrow/array"
	"github.com/apache/arrow/go/v18/parquet/pqarrow"
	"github.com/apache/arrow/go/v18/parquet/file"
	"github.com/redpanda-data/benthos/v4/public/service"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock StateManager for StreamIntegration tests
type MockStateManager struct{}

func (m *MockStateManager) GetProperty(thingID, propertyName string) (interface{}, error) { return nil, nil }
func (m *MockStateManager) SetProperty(thingID, propertyName string, value interface{}) error { return nil }
func (m *MockStateManager) SubscribeProperty(thingID, propertyName string) (<-chan PropertyUpdate, error) {
	return nil, nil
}
func (m *MockStateManager) UnsubscribeProperty(thingID, propertyName string, ch <-chan PropertyUpdate) {}
func (m *MockStateManager) GetAllProperties(thingID string) (map[string]interface{}, error) { return nil, nil}


// Helper function to read ActionInvocationParquetRecord from a Parquet file
func readActionInvocationParquetFile(t *testing.T, filePath string) []ActionInvocationParquetRecord {
	t.Helper()
	reader, err := os.Open(filePath)
	require.NoError(t, err, "Failed to open Parquet file for reading: %s", filePath)
	defer reader.Close()

	pf, err := file.NewParquetReader(reader)
	require.NoError(t, err, "Failed to create Parquet file reader for: %s", filePath)

	arrowReader, err := pqarrow.NewFileReader(pf, pqarrow.ArrowReadProperties{}, nil)
	require.NoError(t, err, "Failed to create Arrow reader from Parquet for: %s", filePath)

	var records []ActionInvocationParquetRecord
	numRowGroups := pf.NumRowGroups()
	require.True(t, numRowGroups > 0 || pf.NumRows() == 0, "Expected some row groups or zero rows if file is empty but valid")


	for i := 0; i < numRowGroups; i++ {
		rgReader, err := arrowReader.RowGroup(i).NewRecordReader(context.Background())
		require.NoError(t, err, "Failed to get record reader for row group %d in %s", i, filePath)
		defer rgReader.Release()

		for rgReader.Next() {
			rec := rgReader.Record()
			rec.Retain()
			defer rec.Release()

			thingIDs := rec.Column(0).(*array.String)
			actionNames := rec.Column(1).(*array.String)
			actionIDs := rec.Column(2).(*array.String)
			inputs := rec.Column(3).(*array.String)
			timestamps := rec.Column(4).(*array.Int64)

			for j := 0; j < int(rec.NumRows()); j++ {
				records = append(records, ActionInvocationParquetRecord{
					ThingID:    thingIDs.Value(j),
					ActionName: actionNames.Value(j),
					ActionID:   actionIDs.Value(j),
					Input:      inputs.Value(j),
					Timestamp:  timestamps.Value(j),
				})
			}
		}
		require.NoError(t, rgReader.Err(), "Error reading records from row group in %s", filePath)
	}
	return records
}

// Helper function to read EventParquetRecord from a Parquet file
func readEventParquetFile(t *testing.T, filePath string) []EventParquetRecord {
	t.Helper()
	reader, err := os.Open(filePath)
	require.NoError(t, err, "Failed to open Parquet file for reading: %s", filePath)
	defer reader.Close()

	pf, err := file.NewParquetReader(reader)
	require.NoError(t, err, "Failed to create Parquet file reader for: %s", filePath)

	arrowReader, err := pqarrow.NewFileReader(pf, pqarrow.ArrowReadProperties{}, nil)
	require.NoError(t, err, "Failed to create Arrow reader from Parquet for: %s", filePath)
	
	var records []EventParquetRecord
	numRowGroups := pf.NumRowGroups()
	require.True(t, numRowGroups > 0 || pf.NumRows() == 0, "Expected some row groups or zero rows if file is empty but valid")


	for i := 0; i < numRowGroups; i++ {
		rgReader, err := arrowReader.RowGroup(i).NewRecordReader(context.Background())
		require.NoError(t, err, "Failed to get record reader for row group %d in %s", i, filePath)
		defer rgReader.Release()

		for rgReader.Next() {
			rec := rgReader.Record()
			rec.Retain()
			defer rec.Release()
			
			thingIDs := rec.Column(0).(*array.String)
			eventNames := rec.Column(1).(*array.String)
			datas := rec.Column(2).(*array.String)
			timestamps := rec.Column(3).(*array.Int64)

			for j := 0; j < int(rec.NumRows()); j++ {
				records = append(records, EventParquetRecord{
					ThingID:   thingIDs.Value(j),
					EventName: eventNames.Value(j),
					Data:      datas.Value(j),
					Timestamp: timestamps.Value(j),
				})
			}
		}
		require.NoError(t, rgReader.Err(), "Error reading records from row group in %s", filePath)
	}
	return records
}

func TestBenthosStreamBridge_logActionInvocationToParquet(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(logrus.New().Out) 
	logger.SetLevel(logrus.DebugLevel)
	tempDir := t.TempDir()

	// BenthosStreamBridge constructor: env, stateMgr, db, logger, parquetLogPath
	// For this test, env, stateMgr, db can be nil as they are not used by logActionInvocationToParquet
	bridge := NewBenthosStreamBridge(nil, nil, nil, logger, tempDir).(*BenthosStreamBridge)

	today := time.Now().Format("2006-01-02")
	expectedFileName := fmt.Sprintf("actions_%s.parquet", today)
	expectedFilePath := filepath.Join(tempDir, "actions", expectedFileName)

	t.Run("single_action_record_write", func(t *testing.T) {
		_ = os.Remove(expectedFilePath) // Clean up from previous runs if any
		record1 := ActionInvocationParquetRecord{
			ThingID:    "actionThing1",
			ActionName: "startMotor",
			ActionID:   "uuid-action-1",
			Input:      `{"speed":100}`,
			Timestamp:  time.Now().UnixNano(),
		}
		err := bridge.logActionInvocationToParquet(record1)
		require.NoError(t, err)
		_, err = os.Stat(expectedFilePath)
		require.NoError(t, err, "Action Parquet file was not created: %s", expectedFilePath)
		
		readRecords := readActionInvocationParquetFile(t, expectedFilePath)
		require.Len(t, readRecords, 1)
		assert.Equal(t, record1, readRecords[0])
	})

	t.Run("append_multiple_action_records", func(t *testing.T) {
		_ = os.Remove(expectedFilePath) // Clean slate for this sub-test

		record1 := ActionInvocationParquetRecord{"thingX", "actionX", "idX1", `{}`, time.Now().UnixNano() - 2000}
		record2 := ActionInvocationParquetRecord{"thingY", "actionY", "idY2", `{"param":"val"}`, time.Now().UnixNano() - 1000}
		record3 := ActionInvocationParquetRecord{"thingZ", "actionZ", "idZ3", `null`, time.Now().UnixNano()}
		
		require.NoError(t, bridge.logActionInvocationToParquet(record1))
		require.NoError(t, bridge.logActionInvocationToParquet(record2))
		require.NoError(t, bridge.logActionInvocationToParquet(record3))

		_, err := os.Stat(expectedFilePath)
		require.NoError(t, err, "Action Parquet file was not created or was removed: %s", expectedFilePath)
		
		readRecords := readActionInvocationParquetFile(t, expectedFilePath)
		require.Len(t, readRecords, 3)
		assert.Equal(t, record1, readRecords[0])
		assert.Equal(t, record2, readRecords[1])
		assert.Equal(t, record3, readRecords[2])
	})
}

func TestStreamIntegration_logEventToParquet(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(logrus.New().Out)
	logger.SetLevel(logrus.DebugLevel)
	tempDir := t.TempDir()

	// StreamIntegration constructor: stateMgr, eventBroker, streamBridge, logger, parquetLogPath
	// For this test, stateMgr, eventBroker, streamBridge can be nil if not used by logEventToParquet.
	mockStateManager := &MockStateManager{}
	mockEventBroker := NewEventBroker()    // Assuming NewEventBroker is accessible and simple
	mockStreamBridge := NewBenthosStreamBridge(nil, nil, nil, logger, "") // Parquet path empty for mock bridge
	
	si := NewStreamIntegration(mockStateManager, mockEventBroker, mockStreamBridge, logger, tempDir)

	today := time.Now().Format("2006-01-02")
	expectedFileName := fmt.Sprintf("events_%s.parquet", today)
	expectedFilePath := filepath.Join(tempDir, "events", expectedFileName)

	t.Run("single_event_record_write", func(t *testing.T) {
		_ = os.Remove(expectedFilePath) 
		record1 := EventParquetRecord{
			ThingID:   "eventThing1",
			EventName: "overheat",
			Data:      `{"temperature":95.5}`,
			Timestamp: time.Now().UnixNano(),
		}
		err := si.logEventToParquet(record1)
		require.NoError(t, err)
		_, err = os.Stat(expectedFilePath)
		require.NoError(t, err, "Event Parquet file was not created: %s", expectedFilePath)
		
		readRecords := readEventParquetFile(t, expectedFilePath)
		require.Len(t, readRecords, 1)
		assert.Equal(t, record1, readRecords[0])
	})

	t.Run("append_multiple_event_records", func(t *testing.T) {
		_ = os.Remove(expectedFilePath) // Clean slate

		record1 := EventParquetRecord{"thingE1", "eventE1", `{}`, time.Now().UnixNano() - 2000}
		record2 := EventParquetRecord{"thingE2", "eventE2", `{"detail":"critical"}`, time.Now().UnixNano() - 1000}
		record3 := EventParquetRecord{"thingE3", "eventE3", `[1,2,3]`, time.Now().UnixNano()}

		require.NoError(t, si.logEventToParquet(record1))
		require.NoError(t, si.logEventToParquet(record2))
		require.NoError(t, si.logEventToParquet(record3))

		_, err := os.Stat(expectedFilePath)
		require.NoError(t, err, "Event Parquet file was not created or was removed: %s", expectedFilePath)

		readRecords := readEventParquetFile(t, expectedFilePath)
		require.Len(t, readRecords, 3)
		assert.Equal(t, record1, readRecords[0])
		assert.Equal(t, record2, readRecords[1])
		assert.Equal(t, record3, readRecords[2])
	})
}
