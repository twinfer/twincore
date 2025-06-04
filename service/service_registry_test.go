package service

import (
	"context"
	"io"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twinfer/twincore/pkg/types"
)

// MockService for testing
type MockService struct {
	name            string
	requiredLicense []string
	dependencies    []string
	startCalled     bool
	stopCalled      bool
	updateCalled    bool
	startError      error
	stopError       error
	updateError     error
}

func NewMockService(name string) *MockService {
	return &MockService{
		name:            name,
		requiredLicense: []string{"core"},
		dependencies:    []string{},
	}
}

func (m *MockService) Name() string              { return m.name }
func (m *MockService) RequiredLicense() []string { return m.requiredLicense }
func (m *MockService) Dependencies() []string    { return m.dependencies }
func (m *MockService) Start(ctx context.Context, config types.ServiceConfig) error {
	m.startCalled = true
	return m.startError
}
func (m *MockService) Stop(ctx context.Context) error {
	m.stopCalled = true
	return m.stopError
}
func (m *MockService) UpdateConfig(config types.ServiceConfig) error {
	m.updateCalled = true
	return m.updateError
}
func (m *MockService) HealthCheck() error { return nil }

// MockLicense for testing
type MockLicense struct {
	enabledFeatures map[string]bool
}

func NewMockLicense(features ...string) *MockLicense {
	enabled := make(map[string]bool)
	for _, feature := range features {
		enabled[feature] = true
	}
	return &MockLicense{enabledFeatures: enabled}
}

func (m *MockLicense) IsFeatureEnabled(feature string) bool {
	return m.enabledFeatures[feature]
}

func TestServiceRegistry_BasicOperations(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	registry := NewServiceRegistryWithLogger(logger)

	// Test service registration
	mockService := NewMockService("test-service")
	registry.RegisterService("test", mockService)

	// Test service status
	status := registry.GetServiceStatus()
	assert.Contains(t, status, "test")
	assert.Equal(t, "test-service", status["test"].ServiceType)
	assert.True(t, status["test"].Registered)
	assert.False(t, status["test"].Permitted) // Not permitted until license is loaded
	assert.False(t, status["test"].HasConfig)
}

func TestServiceRegistry_ConfigManagement(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	registry := NewServiceRegistryWithLogger(logger)

	// Test service registration with config
	mockService := NewMockService("test-service")
	config := types.ServiceConfig{
		Name: "test",
		Config: map[string]any{
			"key": "value",
		},
	}

	registry.RegisterServiceWithConfig("test", mockService, config)

	// Test service status
	status := registry.GetServiceStatus()
	assert.True(t, status["test"].HasConfig)

	// Test config update
	newConfig := types.ServiceConfig{
		Name: "test",
		Config: map[string]any{
			"key": "new_value",
		},
	}

	err := registry.SetServiceConfig("test", newConfig)
	assert.NoError(t, err)

	// Test config update for non-existent service
	err = registry.SetServiceConfig("non-existent", newConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not registered")
}

func TestServiceRegistry_LicenseManagement(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	registry := NewServiceRegistryWithLogger(logger)

	// Register services with different license requirements
	coreService := NewMockService("core-service")
	coreService.requiredLicense = []string{"core"}

	premiumService := NewMockService("premium-service")
	premiumService.requiredLicense = []string{"core", "premium"}

	registry.RegisterService("core", coreService)
	registry.RegisterService("premium", premiumService)

	// Test with license that only has "core"
	license := NewMockLicense("core")
	err := registry.LoadPermittedServices(license)
	assert.NoError(t, err)

	status := registry.GetServiceStatus()
	assert.True(t, status["core"].Permitted)
	assert.False(t, status["premium"].Permitted)

	// Test with full license
	fullLicense := NewMockLicense("core", "premium")
	err = registry.LoadPermittedServices(fullLicense)
	assert.NoError(t, err)

	status = registry.GetServiceStatus()
	assert.True(t, status["core"].Permitted)
	assert.True(t, status["premium"].Permitted)

	// Test with nil license
	err = registry.LoadPermittedServices(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "license is nil")
}

func TestServiceRegistry_ServiceLifecycle(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	registry := NewServiceRegistryWithLogger(logger)

	// Register service with config
	mockService := NewMockService("test-service")
	config := types.ServiceConfig{
		Name: "test",
		Config: map[string]any{
			"setting": "value",
		},
	}

	registry.RegisterServiceWithConfig("test", mockService, config)

	// Load license to permit service
	license := NewMockLicense("core")
	err := registry.LoadPermittedServices(license)
	require.NoError(t, err)

	// Test starting service
	ctx := context.Background()
	err = registry.StartService(ctx, "test")
	assert.NoError(t, err)
	assert.True(t, mockService.startCalled)

	// Test stopping service
	err = registry.StopService(ctx, "test")
	assert.NoError(t, err)
	assert.True(t, mockService.stopCalled)

	// Test starting non-existent service
	err = registry.StartService(ctx, "non-existent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not registered")
}

func TestServiceRegistry_StartWithCustomConfig(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	registry := NewServiceRegistryWithLogger(logger)

	// Register service
	mockService := NewMockService("test-service")
	registry.RegisterService("test", mockService)

	// Load license
	license := NewMockLicense("core")
	err := registry.LoadPermittedServices(license)
	require.NoError(t, err)

	// Test starting with custom config
	customConfig := types.ServiceConfig{
		Name: "test",
		Config: map[string]any{
			"custom": "config",
		},
	}

	ctx := context.Background()
	err = registry.StartServiceWithConfig(ctx, "test", customConfig)
	assert.NoError(t, err)
	assert.True(t, mockService.startCalled)
}

func TestServiceRegistry_PermissionChecks(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	registry := NewServiceRegistryWithLogger(logger)

	// Register service that requires premium license
	premiumService := NewMockService("premium-service")
	premiumService.requiredLicense = []string{"premium"}
	registry.RegisterService("premium", premiumService)

	// Load license without premium
	license := NewMockLicense("core")
	err := registry.LoadPermittedServices(license)
	require.NoError(t, err)

	// Try to start service without proper license
	ctx := context.Background()
	err = registry.StartService(ctx, "premium")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not permitted by license")
	assert.False(t, premiumService.startCalled)
}
