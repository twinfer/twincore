package service

import (
	"context"
	"io"
	"testing"

	// Import standard Caddy modules to ensure they are registered
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twinfer/twincore/internal/api"
	"github.com/twinfer/twincore/pkg/types"
)

func TestHTTPServiceUnified_Interface(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	configManager := api.NewConfigManager(logger)

	service := NewHTTPService(configManager, logger)

	// Verify it implements the Service interface
	assert.Implements(t, (*types.Service)(nil), service)

	// Test basic properties
	assert.Equal(t, "http-unified", service.Name())
	assert.Equal(t, []string{"core", "http"}, service.RequiredLicense())
	assert.Empty(t, service.Dependencies())
}

func TestHTTPServiceUnified_BasicLifecycle(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel) // Enable debug logging to see what's happening
	configManager := api.NewConfigManager(logger)

	service := NewHTTPService(configManager, logger)
	ctx := context.Background()

	// Create minimal valid config
	// Convert HTTPConfig to map for proper serialization
	config := types.ServiceConfig{
		Name: "http-unified",
		Config: map[string]any{
			"http": map[string]any{
				"listen": []string{":0"}, // Use port 0 for testing to avoid conflicts
				"routes": []types.HTTPRoute{},
				"security": map[string]any{
					"enabled": false,
				},
			},
		},
	}

	// Test health check when not running
	err := service.HealthCheck()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service not running")

	// Test start
	err = service.Start(ctx, config)
	require.NoError(t, err)

	// Test health check when running
	err = service.HealthCheck()
	assert.NoError(t, err)

	// Test start when already running
	err = service.Start(ctx, config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")

	// Test stop
	err = service.Stop(ctx)
	assert.NoError(t, err)

	// Test stop when not running
	err = service.Stop(ctx)
	assert.NoError(t, err) // Should not error
}

func TestHTTPServiceUnified_ConfigValidation(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	configManager := api.NewConfigManager(logger)
	service := NewHTTPService(configManager, logger)
	ctx := context.Background()

	tests := []struct {
		name        string
		config      types.ServiceConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "missing_http_config",
			config: types.ServiceConfig{
				Name:   "http-unified",
				Config: map[string]any{},
			},
			expectError: true,
			errorMsg:    "missing HTTP configuration",
		},
		{
			name: "invalid_http_config_type",
			config: types.ServiceConfig{
				Name: "http-unified",
				Config: map[string]any{
					"http": "invalid",
				},
			},
			expectError: true,
			errorMsg:    "invalid HTTP configuration type",
		},
		{
			name: "valid_minimal_config",
			config: types.ServiceConfig{
				Name: "http-unified",
				Config: map[string]any{
					"http": map[string]any{
						"listen": []string{":0"},
						"routes": []types.HTTPRoute{},
						"security": map[string]any{
							"enabled": false,
						},
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.Start(ctx, tt.config)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				// Clean up
				_ = service.Stop(ctx)
			}
		})
	}
}

// TestHTTPServiceUnified_RouteBuilding tests route building functionality
// NOTE: This test is disabled as buildRoute is no longer a public method
// Route building is now handled internally by the HTTP service
/*
func TestHTTPServiceUnified_RouteBuilding(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	configManager := api.NewConfigManager(logger)
	service := NewHTTPService(configManager, logger).(*HTTPService)

	tests := []struct {
		name  string
		route types.HTTPRoute
	}{
		{
			name: "reverse_proxy_route",
			route: types.HTTPRoute{
				Path:    "/api/*",
				Methods: []string{"GET", "POST"},
				Handler: "reverse_proxy",
				Config: map[string]any{
					"upstream": "localhost:3000",
				},
			},
		},
		{
			name: "static_response_route",
			route: types.HTTPRoute{
				Path:    "/health",
				Methods: []string{"GET"},
				Handler: "static_response",
				Config: map[string]any{
					"body":        `{"status": "ok"}`,
					"status_code": 200,
				},
			},
		},
		{
			name: "unknown_handler_route",
			route: types.HTTPRoute{
				Path:    "/unknown",
				Methods: []string{"GET"},
				Handler: "unknown_handler",
				Config:  map[string]any{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This should not panic and should return a valid route
			route := service.buildRoute(tt.route)

			assert.NotNil(t, route.MatcherSetsRaw)
			assert.NotNil(t, route.HandlersRaw)
			assert.Len(t, route.MatcherSetsRaw, 1)
			assert.Len(t, route.HandlersRaw, 1)
		})
	}
}
*/

func TestHTTPServiceUnified_UpdateConfig(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	configManager := api.NewConfigManager(logger)
	service := NewHTTPService(configManager, logger)
	ctx := context.Background()

	// Start with initial config
	initialConfig := types.ServiceConfig{
		Name: "http-unified",
		Config: map[string]any{
			"http": map[string]any{
				"listen": []string{":0"},
				"routes": []types.HTTPRoute{
					{
						Path:    "/initial",
						Handler: "static_response",
						Config: map[string]any{
							"body": "initial",
						},
					},
				},
				"security": map[string]any{
					"enabled": false,
				},
			},
		},
	}

	err := service.Start(ctx, initialConfig)
	require.NoError(t, err)
	defer service.Stop(ctx)

	// Test update config when running
	updatedConfig := types.ServiceConfig{
		Name: "http-unified",
		Config: map[string]any{
			"http": map[string]any{
				"listen": []string{":0"},
				"routes": []types.HTTPRoute{
					{
						Path:    "/updated",
						Handler: "static_response",
						Config: map[string]any{
							"body": "updated",
						},
					},
				},
				"security": map[string]any{
					"enabled": false,
				},
			},
		},
	}

	err = service.UpdateConfig(updatedConfig)
	assert.NoError(t, err)

	// Test update config when not running
	err = service.Stop(ctx)
	require.NoError(t, err)

	err = service.UpdateConfig(updatedConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service not running")
}
