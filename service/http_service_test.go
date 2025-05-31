package service_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/service"
)

func TestHTTPServiceSimple(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// Create service
	httpService := service.NewHTTPServiceSimple(logger)

	// Test configuration
	config := types.ServiceConfig{
		Name: "http",
		Type: "http",
		Config: map[string]interface{}{
			"http": types.HTTPConfig{
				Routes: []types.HTTPRoute{
					{
						Path:    "/health",
						Methods: []string{"GET"},
						Handler: "static",
						Metadata: map[string]interface{}{
							"body": `{"status": "healthy"}`,
						},
					},
					{
						Path:         "/api/protected",
						Methods:      []string{"GET"},
						Handler:      "static",
						RequiresAuth: true,
						Metadata: map[string]interface{}{
							"body": `{"message": "authenticated"}`,
						},
					},
				},
			},
			"security": map[string]interface{}{
				"enabled":       true,
				"bearer_tokens": []string{"test-token-123"},
			},
		},
	}

	// Start service
	ctx := context.Background()
	err := httpService.Start(ctx, config)
	require.NoError(t, err)
	defer httpService.Stop(ctx)

	// Wait for Caddy to start
	time.Sleep(1 * time.Second)

	// Test public endpoint
	t.Run("PublicEndpoint", func(t *testing.T) {
		resp, err := http.Get("http://localhost:8080/health")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	// Test protected endpoint without auth
	t.Run("ProtectedEndpointNoAuth", func(t *testing.T) {
		resp, err := http.Get("http://localhost:8080/api/protected")
		require.NoError(t, err)
		defer resp.Body.Close()
		// Should not match route due to missing Authorization header
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	})

	// Test protected endpoint with auth
	t.Run("ProtectedEndpointWithAuth", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:8080/api/protected", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer test-token-123")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	// Test health check
	t.Run("HealthCheck", func(t *testing.T) {
		err := httpService.HealthCheck()
		assert.NoError(t, err)
	})
}

func TestHTTPServiceV2(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// Create service
	httpService := service.NewHTTPServiceV2(logger)

	// Test configuration
	config := types.ServiceConfig{
		Name: "http",
		Type: "http",
		Config: map[string]interface{}{
			"http": types.HTTPConfig{
				Routes: []types.HTTPRoute{
					{
						Path:    "/v2/health",
						Methods: []string{"GET"},
						Handler: "static_response",
						Metadata: map[string]interface{}{
							"body":        `{"status": "healthy", "version": "v2"}`,
							"status_code": 200.0,
						},
					},
				},
			},
		},
	}

	// Start service
	ctx := context.Background()
	err := httpService.Start(ctx, config)
	require.NoError(t, err)
	defer httpService.Stop(ctx)

	// Wait for Caddy to start
	time.Sleep(1 * time.Second)

	// Test endpoint
	t.Run("V2Endpoint", func(t *testing.T) {
		resp, err := http.Get("http://localhost:8080/v2/health")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
