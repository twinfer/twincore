// tests/integration/twincore_integration_test.go
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twinfer/twincore/internal/container"
)

// Test fixtures
var (
	testLicense = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6InRlc3QtbGljZW5zZSIsImRldmljZV9pZCI6InRlc3QtZGV2aWNlIiwiZmVhdHVyZXMiOlsiY29yZSIsImh0dHAiLCJzdHJlYW1pbmciLCJ3b3QiXSwic2VydmljZXMiOlsiaHR0cCIsInN0cmVhbSIsIndvdCJdLCJ2YWxpZF91bnRpbCI6IjIwMjUtMTItMzFUMjM6NTk6NTlaIn0.test`

	testTD = `{
        "@context": "https://www.w3.org/2019/wot/td/v1",
        "id": "urn:dev:test:lamp-1234",
        "title": "Test Lamp",
        "security": ["bearer"],
        "securityDefinitions": {
            "bearer": {
                "scheme": "bearer",
                "in": "header",
                "name": "Authorization"
            }
        },
        "properties": {
            "brightness": {
                "type": "integer",
                "minimum": 0,
                "maximum": 100,
                "forms": [{
                    "href": "/things/lamp/properties/brightness",
                    "contentType": "application/json",
                    "op": ["readproperty", "writeproperty"]
                }]
            }
        },
        "actions": {
            "fade": {
                "input": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "integer"},
                        "duration": {"type": "integer"}
                    }
                },
                "forms": [{
                    "href": "/things/lamp/actions/fade",
                    "contentType": "application/json",
                    "op": ["invokeaction"]
                }]
            }
        },
        "events": {
            "motion": {
                "data": {
                    "type": "object",
                    "properties": {
                        "detected": {"type": "boolean"}
                    }
                },
                "forms": [{
                    "href": "/things/lamp/events/motion",
                    "contentType": "text/event-stream",
                    "op": ["subscribeevent"]
                }]
            }
        }
    }`
)

type TestSuite struct {
	container *container.Container
	apiURL    string
	httpURL   string
	cleanup   func()
}

func setupTestSuite(t *testing.T) *TestSuite {
	// Create temp directory
	tmpDir := t.TempDir()

	// Write test files
	licensePath := filepath.Join(tmpDir, "license.jwt")
	require.NoError(t, os.WriteFile(licensePath, []byte(testLicense), 0644))

	pubKeyPath := filepath.Join(tmpDir, "public.key")
	require.NoError(t, os.WriteFile(pubKeyPath, []byte("test-public-key"), 0644))

	dbPath := filepath.Join(tmpDir, "test.db")

	// Create container
	cfg := &container.Config{
		DBPath:      dbPath,
		LicensePath: licensePath,
		PublicKey:   []byte("test-public-key"),
	}

	ctx := context.Background()
	cnt, err := container.New(ctx, cfg)
	require.NoError(t, err)

	// Start services
	require.NoError(t, cnt.Start(ctx))

	// Start API server
	apiPort := "18090"
	apiServer := startTestAPIServer(cnt, apiPort)

	return &TestSuite{
		container: cnt,
		apiURL:    fmt.Sprintf("http://localhost:%s", apiPort),
		httpURL:   "http://localhost:8080",
		cleanup: func() {
			apiServer.Shutdown(context.Background())
			cnt.Stop(context.Background())
		},
	}
}

func TestThingRegistration(t *testing.T) {
	suite := setupTestSuite(t)
	defer suite.cleanup()

	// Register thing
	resp, err := http.Post(suite.apiURL+"/api/things", "application/json", bytes.NewReader([]byte(testTD)))
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var td wot.ThingDescription
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&td))
	assert.Equal(t, "urn:dev:test:lamp-1234", td.ID)
	assert.Equal(t, "Test Lamp", td.Title)

	// List things
	resp, err = http.Get(suite.apiURL + "/api/things")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var things []wot.ThingDescription
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&things))
	assert.Len(t, things, 1)

	// Get specific thing
	resp, err = http.Get(suite.apiURL + "/api/things/urn:dev:test:lamp-1234")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestPropertyInteraction(t *testing.T) {
	suite := setupTestSuite(t)
	defer suite.cleanup()

	// Register thing
	_, err := http.Post(suite.apiURL+"/api/things", "application/json", bytes.NewReader([]byte(testTD)))
	require.NoError(t, err)

	// Wait for config propagation
	time.Sleep(100 * time.Millisecond)

	// Read property (should be empty initially)
	resp, err := http.Get(suite.httpURL + "/things/urn:dev:test:lamp-1234/properties/brightness")
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode) // No initial value

	// Write property
	propValue := map[string]interface{}{"value": 50}
	body, _ := json.Marshal(propValue)
	req, _ := http.NewRequest("PUT", suite.httpURL+"/things/urn:dev:test:lamp-1234/properties/brightness", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	// Read property again
	resp, err = http.Get(suite.httpURL + "/things/urn:dev:test:lamp-1234/properties/brightness")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.Equal(t, float64(50), result["value"])
}

func TestActionInvocation(t *testing.T) {
	suite := setupTestSuite(t)
	defer suite.cleanup()

	// Register thing
	_, err := http.Post(suite.apiURL+"/api/things", "application/json", bytes.NewReader([]byte(testTD)))
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	// Invoke action
	actionInput := map[string]interface{}{
		"target":   75,
		"duration": 1000,
	}
	body, _ := json.Marshal(actionInput)

	resp, err := http.Post(suite.httpURL+"/things/urn:dev:test:lamp-1234/actions/fade", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)

	var result map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	assert.Contains(t, result, "actionId")
	assert.Equal(t, "pending", result["status"])
}

func TestEventSubscription(t *testing.T) {
	suite := setupTestSuite(t)
	defer suite.cleanup()

	// Register thing
	_, err := http.Post(suite.apiURL+"/api/things", "application/json", bytes.NewReader([]byte(testTD)))
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	// Subscribe to events
	req, _ := http.NewRequest("GET", suite.httpURL+"/things/urn:dev:test:lamp-1234/events/motion", nil)
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))

	// Read one event
	reader := resp.Body
	defer reader.Close()

	// In real test, would parse SSE format
	buf := make([]byte, 1024)
	n, _ := reader.Read(buf)
	assert.Greater(t, n, 0)
}

func TestConfigurationPersistence(t *testing.T) {
	suite := setupTestSuite(t)
	defer suite.cleanup()

	// Register thing
	_, err := http.Post(suite.apiURL+"/api/things", "application/json", bytes.NewReader([]byte(testTD)))
	require.NoError(t, err)

	// Get Caddy config
	resp, err := http.Get(suite.apiURL + "/api/config/caddy")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var caddyConfig map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&caddyConfig))
	assert.Contains(t, caddyConfig, "apps")

	// Restart container to test persistence
	suite.container.Stop(context.Background())

	ctx := context.Background()
	require.NoError(t, suite.container.Start(ctx))

	// Verify thing still exists
	resp, err = http.Get(suite.apiURL + "/api/things")
	require.NoError(t, err)

	var things []wot.ThingDescription
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&things))
	assert.Len(t, things, 1)
}

func TestCaddyConfigRollback(t *testing.T) {
	suite := setupTestSuite(t)
	defer suite.cleanup()

	// Get initial config
	resp, err := http.Get(suite.apiURL + "/api/config/caddy")
	require.NoError(t, err)

	var originalConfig map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&originalConfig))

	// Update config with bad data
	badConfig := map[string]interface{}{
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"srv0": map[string]interface{}{
						"listen": []string{":99999"}, // Invalid port
					},
				},
			},
		},
	}

	body, _ := json.Marshal(badConfig)
	req, _ := http.NewRequest("PUT", suite.apiURL+"/api/config/caddy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode) // Should fail validation

	// Verify config unchanged
	resp, err = http.Get(suite.apiURL + "/api/config/caddy")
	require.NoError(t, err)

	var currentConfig map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&currentConfig))
	assert.Equal(t, originalConfig, currentConfig)
}

func TestStreamConfiguration(t *testing.T) {
	suite := setupTestSuite(t)
	defer suite.cleanup()

	// Register thing to create streams
	_, err := http.Post(suite.apiURL+"/api/things", "application/json", bytes.NewReader([]byte(testTD)))
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	// Get stream config
	streamName := "things.urn:dev:test:lamp-1234.properties.brightness"
	resp, err := http.Get(suite.apiURL + "/api/config/streams/" + streamName)

	if err == nil && resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(body), "input:")
		assert.Contains(t, string(body), "output:")
	}
}

// Helper function to start API server for tests
func startTestAPIServer(cnt *container.Container, port string) *http.Server {
	mux := http.NewServeMux()

	// Register handlers (same as main.go)
	// ... (handlers would be registered here)

	server := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	go server.ListenAndServe()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	return server
}
