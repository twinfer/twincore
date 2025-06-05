package api

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/marcboeker/go-duckdb"
	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/database"
	"github.com/twinfer/twincore/internal/database/repositories"
)

func TestBenthosStateManager_ParquetReplacement(t *testing.T) {
	// Create temporary directory for Parquet logs
	tmpDir := t.TempDir()

	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// Create database factory with test configuration
	config := database.DatabaseConfig{
		DBPath:      "", // In-memory DuckDB
		AutoMigrate: true,
	}
	
	factory, err := database.NewDatabaseFactoryWithConfig(config, logger)
	if err != nil {
		t.Fatalf("Failed to create database factory: %v", err)
	}
	defer factory.Close()
	
	// Get database manager and create stream repository
	dbManager := factory.GetManager()
	streamRepo := repositories.NewStreamRepository(dbManager, logger)

	// Create Benthos state manager
	sm, err := NewBenthosStateManager(streamRepo, "configs/benthos/streams", tmpDir, logger)
	if err != nil {
		t.Fatalf("Failed to create Benthos state manager: %v", err)
	}
	defer sm.Close()

	// Test property setting (this should log to Parquet)
	thingID := "test-sensor"
	propertyName := "temperature"
	value := 23.5

	err = sm.SetProperty(logger, thingID, propertyName, value)
	if err != nil {
		t.Fatalf("Failed to set property: %v", err)
	}

	// Verify property was stored in database
	retrievedValue, err := sm.GetProperty(thingID, propertyName)
	if err != nil {
		t.Fatalf("Failed to get property: %v", err)
	}

	if retrievedValue != value {
		t.Errorf("Expected value %v, got %v", value, retrievedValue)
	}

	// Give time for Parquet logging to complete
	time.Sleep(100 * time.Millisecond)

	// Verify Parquet log file was created
	today := time.Now().Format("2006-01-02")
	expectedFile := filepath.Join(tmpDir, "properties", "properties_"+today+".jsonl")

	if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
		t.Errorf("Expected Parquet log file %s was not created", expectedFile)
	}

	// Read and verify log content
	content, err := os.ReadFile(expectedFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	if len(content) == 0 {
		t.Error("Log file is empty")
	}

	// Verify content contains our property data
	contentStr := string(content)
	if !containsAll(contentStr, thingID, propertyName, "23.5") {
		t.Errorf("Log content does not contain expected data: %s", contentStr)
	}

	t.Logf("Successfully replaced custom Parquet writer with Benthos-based logging")
	t.Logf("Log file created: %s", expectedFile)
	t.Logf("Log content: %s", contentStr)
}

func containsAll(content string, items ...string) bool {
	for _, item := range items {
		if !contains(content, item) {
			return false
		}
	}
	return true
}

func contains(content, item string) bool {
	return len(content) > 0 && len(item) > 0 &&
		findInString(content, item) >= 0
}

func findInString(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
