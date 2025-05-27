// tests/integration/helpers_test.go
package integration

import (
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/elastic/go-elasticsearch/v8/typedapi/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/twinfer/twincore/internal/api"
	"github.com/twinfer/twincore/internal/config"
)

// MockLicenseManager for testing
type MockLicenseManager struct{}

func (m *MockLicenseManager) GenerateDeviceID() (string, error) {
	return "test-device-id", nil
}

func (m *MockLicenseManager) ValidateLicense(licenseData []byte, deviceID string) (*types.License, error) {
	return &types.License{
		ID:         "test-license",
		DeviceID:   deviceID,
		Features:   []string{"core", "http", "streaming", "wot"},
		Services:   []string{"http", "stream", "wot"},
		ValidUntil: time.Now().Add(365 * 24 * time.Hour),
	}, nil
}

func (m *MockLicenseManager) GetPermittedServices(license *types.License) []string {
	return license.Services
}

func (m *MockLicenseManager) IsFeatureEnabled(license *types.License, feature string) bool {
	for _, f := range license.Features {
		if f == feature {
			return true
		}
	}
	return false
}

// Mock Stream Bridge for testing without real Benthos
type MockStreamBridge struct {
	propertyUpdates map[string]interface{}
	actionResults   map[string]api.ActionResult
	mu              sync.Mutex
}

func NewMockStreamBridge() *MockStreamBridge {
	return &MockStreamBridge{
		propertyUpdates: make(map[string]interface{}),
		actionResults:   make(map[string]api.ActionResult),
	}
}

func (b *MockStreamBridge) PublishPropertyUpdate(thingID, propertyName string, value interface{}) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	key := fmt.Sprintf("%s/%s", thingID, propertyName)
	b.propertyUpdates[key] = value
	return nil
}

func (b *MockStreamBridge) PublishActionInvocation(thingID, actionName string, input interface{}) (string, error) {
	actionID := fmt.Sprintf("test-action-%d", time.Now().UnixNano())

	// Simulate async result
	go func() {
		time.Sleep(50 * time.Millisecond)
		b.mu.Lock()
		b.actionResults[actionID] = api.ActionResult{
			Output: map[string]interface{}{"result": "success"},
		}
		b.mu.Unlock()
	}()

	return actionID, nil
}

func (b *MockStreamBridge) PublishEvent(thingID, eventName string, data interface{}) error {
	return nil
}

func (b *MockStreamBridge) GetActionResult(actionID string, timeout time.Duration) (interface{}, error) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		b.mu.Lock()
		result, exists := b.actionResults[actionID]
		b.mu.Unlock()

		if exists {
			return result.Output, result.Error
		}

		time.Sleep(10 * time.Millisecond)
	}

	return nil, fmt.Errorf("action timeout")
}

// Setup test database
func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("duckdb", ":memory:")
	require.NoError(t, err)

	// Run migrations
	schema := `
    CREATE TABLE IF NOT EXISTS things (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        td_jsonld TEXT NOT NULL,
        td_parsed TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS property_state (
        thing_id TEXT NOT NULL,
        property_name TEXT NOT NULL,
        value TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (thing_id, property_name)
    );
    
    CREATE TABLE IF NOT EXISTS caddy_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        config TEXT NOT NULL,
        patches TEXT,
        version INTEGER,
        active BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    `

	_, err = db.Exec(schema)
	require.NoError(t, err)

	return db
}

// Benchmark tests
func BenchmarkPropertyUpdate(b *testing.B) {
	db := setupTestDB(&testing.T{})
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	sm, _ := api.NewDuckDBStateManager(db, logger)

	// Setup
	thingID := "test-thing"
	propertyName := "brightness"

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sm.SetProperty(thingID, propertyName, i%100)
	}
}

func BenchmarkThingRegistration(b *testing.B) {
	db := setupTestDB(&testing.T{})
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	registry := config.NewThingRegistry(db, logger)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		td := fmt.Sprintf(testTDTemplate, i)
		registry.RegisterThing(td)
	}
}

var testTDTemplate = `{
    "@context": "https://www.w3.org/2019/wot/td/v1",
    "id": "urn:dev:test:device-%d",
    "title": "Test Device %d",
    "security": ["bearer"],
    "securityDefinitions": {
        "bearer": {"scheme": "bearer"}
    },
    "properties": {
        "value": {
            "type": "number",
            "forms": [{"href": "/things/device-%d/properties/value"}]
        }
    }
}`
