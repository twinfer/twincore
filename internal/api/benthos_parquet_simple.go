package api

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
)

// SimpleBenthosParquetClient is a placeholder implementation that mimics Benthos
// This allows us to replace custom Parquet writers without requiring full Benthos integration
type SimpleBenthosParquetClient struct {
	configDir      string
	logger         logrus.FieldLogger
	enabled        bool
	parquetLogPath string
}

// NewSimpleBenthosParquetClient creates a simple Benthos-like Parquet client
func NewSimpleBenthosParquetClient(configDir, parquetLogPath string, logger logrus.FieldLogger) (*SimpleBenthosParquetClient, error) {
	return &SimpleBenthosParquetClient{
		configDir:      configDir,
		parquetLogPath: parquetLogPath,
		logger:         logger,
		enabled:        parquetLogPath != "",
	}, nil
}

// LogPropertyUpdate logs property updates (placeholder implementation)
func (c *SimpleBenthosParquetClient) LogPropertyUpdate(thingID, propertyName string, value interface{}, source string) error {
	if !c.enabled {
		return nil
	}

	// For now, log as JSON until Benthos is fully integrated
	record := map[string]interface{}{
		"thing_id":      thingID,
		"property_name": propertyName,
		"value":         value,
		"source":        source,
		"timestamp":     time.Now().UnixNano(),
	}

	return c.writeJSONRecord("properties", record)
}

// LogEvent logs events (placeholder implementation)
func (c *SimpleBenthosParquetClient) LogEvent(thingID, eventName string, data interface{}) error {
	if !c.enabled {
		return nil
	}

	record := map[string]interface{}{
		"thing_id":   thingID,
		"event_name": eventName,
		"data":       data,
		"timestamp":  time.Now().UnixNano(),
	}

	return c.writeJSONRecord("events", record)
}

// LogActionInvocation logs action invocations (placeholder implementation)
func (c *SimpleBenthosParquetClient) LogActionInvocation(thingID, actionName, actionID string, input interface{}) error {
	if !c.enabled {
		return nil
	}

	record := map[string]interface{}{
		"thing_id":    thingID,
		"action_name": actionName,
		"action_id":   actionID,
		"input":       input,
		"timestamp":   time.Now().UnixNano(),
	}

	return c.writeJSONRecord("actions", record)
}

// writeJSONRecord writes a record as JSON (temporary until Benthos integration)
func (c *SimpleBenthosParquetClient) writeJSONRecord(recordType string, record map[string]interface{}) error {
	today := time.Now().Format("2006-01-02")
	dirPath := filepath.Join(c.parquetLogPath, recordType)
	filePath := filepath.Join(dirPath, fmt.Sprintf("%s_%s.jsonl", recordType, today))

	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	jsonData, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal record: %w", err)
	}

	if _, err := file.Write(append(jsonData, '\n')); err != nil {
		return fmt.Errorf("failed to write record: %w", err)
	}

	return nil
}

// Close shuts down the client
func (c *SimpleBenthosParquetClient) Close() error {
	return nil
}

// IsEnabled checks if logging is enabled
func (c *SimpleBenthosParquetClient) IsEnabled(logType string) bool {
	return c.enabled
}
