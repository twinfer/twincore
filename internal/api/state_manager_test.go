package api

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/apache/arrow/go/v18/arrow/array"
	"github.com/apache/arrow/go/v18/parquet/file"
	"github.com/apache/arrow/go/v18/parquet/pqarrow"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Helper function to read PropertyStateParquetRecord from a Parquet file
func readPropertyStateParquetFile(t *testing.T, filePath string) []PropertyStateParquetRecord {
	t.Helper()

	reader, err := os.Open(filePath)
	require.NoError(t, err, "Failed to open Parquet file for reading")
	defer reader.Close()

	pf, err := file.NewParquetReader(reader)
	require.NoError(t, err, "Failed to create Parquet file reader")

	arrowReader, err := pqarrow.NewFileReader(pf, pqarrow.ArrowReadProperties{}, nil)
	require.NoError(t, err, "Failed to create Arrow reader from Parquet")

	numRowGroups := pf.NumRowGroups()
	var records []PropertyStateParquetRecord

	for i := 0; i < numRowGroups; i++ {
		rgReader, err := arrowReader.RowGroup(i).NewRecordReader(context.Background())
		require.NoError(t, err, "Failed to get record reader for row group %d", i)
		defer rgReader.Release()

		for rgReader.Next() {
			rec := rgReader.Record()
			// Retain the record for safety if its underlying buffers are released by the reader
			rec.Retain()
			defer rec.Release()

			thingIDs := rec.Column(0).(*array.String)
			propNames := rec.Column(1).(*array.String)
			values := rec.Column(2).(*array.String)
			timestamps := rec.Column(3).(*array.Int64)
			sources := rec.Column(4).(*array.String)

			for j := 0; j < int(rec.NumRows()); j++ {
				records = append(records, PropertyStateParquetRecord{
					ThingID:      thingIDs.Value(j),
					PropertyName: propNames.Value(j),
					Value:        values.Value(j),
					Timestamp:    timestamps.Value(j),
					Source:       sources.Value(j),
				})
			}
		}
		require.NoError(t, rgReader.Err(), "Error reading records from row group")
	}
	return records
}

func TestDuckDBStateManager_logPropertyToParquet(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(logrus.New().Out) // Or io.Discard
	logger.SetLevel(logrus.DebugLevel)

	tempDir := t.TempDir()

	// Case 1: Parquet logging disabled (empty path)
	t.Run("logging_disabled", func(t *testing.T) {
		smNoLog, _ := NewDuckDBStateManager(nil, logger, "") // DB can be nil as logPropertyToParquet doesn't use it
		record := PropertyStateParquetRecord{
			ThingID:      "thing1",
			PropertyName: "prop1",
			Value:        `{"value":100}`,
			Timestamp:    time.Now().UnixNano(),
			Source:       "test",
		}
		err := smNoLog.logPropertyToParquet(record)
		assert.NoError(t, err, "logPropertyToParquet with empty path should not return error")
		// Check that no directory/file was created
		expectedDirPath := filepath.Join(tempDir, "properties") // Use tempDir here to ensure it's not created
		_, err = os.Stat(expectedDirPath)
		assert.True(t, os.IsNotExist(err), "Properties directory should not be created when logging is disabled")
	})

	sm, err := NewDuckDBStateManager(nil, logger, tempDir) // DB can be nil
	require.NoError(t, err, "NewDuckDBStateManager should not error")

	today := time.Now().Format("2006-01-02")
	expectedFileName := fmt.Sprintf("props_%s.parquet", today)
	expectedFilePath := filepath.Join(tempDir, "properties", expectedFileName)

	t.Run("single_record_write", func(t *testing.T) {
		record1 := PropertyStateParquetRecord{
			ThingID:      "thing1",
			PropertyName: "prop1",
			Value:        `{"value":100}`,
			Timestamp:    time.Now().UnixNano(),
			Source:       "test1",
		}

		err := sm.logPropertyToParquet(record1)
		require.NoError(t, err, "logPropertyToParquet failed for single record")

		_, err = os.Stat(expectedFilePath)
		require.NoError(t, err, "Parquet file was not created: %s", expectedFilePath)

		readRecords := readPropertyStateParquetFile(t, expectedFilePath)
		require.Len(t, readRecords, 1, "Expected 1 record in Parquet file")
		assert.Equal(t, record1, readRecords[0], "Record content mismatch")
	})

	t.Run("append_multiple_records", func(t *testing.T) {
		// This test relies on the file created in "single_record_write" if run sequentially
		// or may create its own if tests are isolated or parallel.
		// To ensure append, we can delete the file first if it exists from a previous run within this test function,
		// then write multiple. Or, rely on the state from previous sub-test.
		// For simplicity, let's assume the file from single_record_write might exist and we're appending.
		// The read-concatenate-rewrite logic in logPropertyToParquet should handle this.

		// Clean up file from previous sub-test if it exists, to test append from scratch for this sub-test
		// This makes sub-tests more independent for the append logic.
		_ = os.Remove(expectedFilePath)

		record1 := PropertyStateParquetRecord{ // This will be the first record in the new file for this sub-test
			ThingID:      "thingA",
			PropertyName: "propA",
			Value:        `{"value":"valA"}`,
			Timestamp:    time.Now().UnixNano() - 1000, // ensure different timestamp
			Source:       "testA",
		}
		err := sm.logPropertyToParquet(record1)
		require.NoError(t, err, "logPropertyToParquet failed for first append record")

		record2 := PropertyStateParquetRecord{
			ThingID:      "thingB",
			PropertyName: "propB",
			Value:        `{"value":200.5}`,
			Timestamp:    time.Now().UnixNano(),
			Source:       "testB",
		}
		err = sm.logPropertyToParquet(record2)
		require.NoError(t, err, "logPropertyToParquet failed for second append record")

		record3 := PropertyStateParquetRecord{
			ThingID:      "thingC",
			PropertyName: "propC",
			Value:        `true`,
			Timestamp:    time.Now().UnixNano() + 1000,
			Source:       "testC",
		}
		err = sm.logPropertyToParquet(record3)
		require.NoError(t, err, "logPropertyToParquet failed for third append record")

		_, err = os.Stat(expectedFilePath)
		require.NoError(t, err, "Parquet file was not created or was removed: %s", expectedFilePath)

		readRecords := readPropertyStateParquetFile(t, expectedFilePath)
		require.Len(t, readRecords, 3, "Expected 3 records in Parquet file after append")

		// Verify order and content
		assert.Equal(t, record1, readRecords[0], "Record 1 content mismatch")
		assert.Equal(t, record2, readRecords[1], "Record 2 content mismatch")
		assert.Equal(t, record3, readRecords[2], "Record 3 content mismatch")
	})
}
