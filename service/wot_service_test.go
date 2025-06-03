package service

import (
	"context"
	"io"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
)

// MockThingRegistry for testing
type MockThingRegistry struct {
	things    []*wot.ThingDescription
	listError error
}

func NewMockThingRegistry() *MockThingRegistry {
	return &MockThingRegistry{
		things: make([]*wot.ThingDescription, 0),
	}
}

func (m *MockThingRegistry) ListThings() ([]*wot.ThingDescription, error) {
	if m.listError != nil {
		return nil, m.listError
	}
	return m.things, nil
}

func (m *MockThingRegistry) AddThing(thing *wot.ThingDescription) {
	m.things = append(m.things, thing)
}

func (m *MockThingRegistry) SetListError(err error) {
	m.listError = err
}

// MockConfigManager for testing
type MockConfigManager struct{}

func NewMockConfigManager() *MockConfigManager {
	return &MockConfigManager{}
}

func TestWoTService_Interface(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	thingRegistry := NewMockThingRegistry()
	configManager := NewMockConfigManager()

	service := NewWoTServiceWithInterfaces(thingRegistry, configManager, logger)

	// Verify it implements the Service interface
	assert.Implements(t, (*types.Service)(nil), service)

	// Test basic properties
	assert.Equal(t, "wot", service.Name())
	assert.Equal(t, []string{"core", "wot"}, service.RequiredLicense())
	assert.Equal(t, []string{"http", "stream"}, service.Dependencies())
}

func TestWoTService_BasicLifecycle(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	thingRegistry := NewMockThingRegistry()
	configManager := NewMockConfigManager()

	service := NewWoTServiceWithInterfaces(thingRegistry, configManager, logger).(*WoTService)
	ctx := context.Background()

	// Test health check when not running
	err := service.HealthCheck()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not running")

	// Test start with minimal config
	config := types.ServiceConfig{
		Name:   "wot",
		Config: make(map[string]interface{}),
	}

	err = service.Start(ctx, config)
	require.NoError(t, err)
	assert.True(t, service.running)

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
	assert.False(t, service.running)

	// Test stop when not running
	err = service.Stop(ctx)
	assert.NoError(t, err) // Should not error
}

func TestWoTService_ConfigurationHandling(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	thingRegistry := NewMockThingRegistry()
	configManager := NewMockConfigManager()

	service := NewWoTServiceWithInterfaces(thingRegistry, configManager, logger).(*WoTService)
	ctx := context.Background()

	// Test start with WoT-specific configuration
	config := types.ServiceConfig{
		Name: "wot",
		Config: map[string]interface{}{
			"wot": map[string]interface{}{
				"auto_discovery": true,
				"max_things":     100.0,
			},
		},
	}

	err := service.Start(ctx, config)
	require.NoError(t, err)

	// Test config update
	newConfig := types.ServiceConfig{
		Name: "wot",
		Config: map[string]interface{}{
			"wot": map[string]interface{}{
				"auto_discovery": false,
				"max_things":     50.0,
			},
		},
	}

	err = service.UpdateConfig(newConfig)
	assert.NoError(t, err)
	assert.Equal(t, "wot", service.currentConfig.Name)

	// Test config update when not running
	err = service.Stop(ctx)
	require.NoError(t, err)

	err = service.UpdateConfig(newConfig)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not running")
}

func TestWoTService_LoadExistingThings(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	thingRegistry := NewMockThingRegistry()
	configManager := NewMockConfigManager()

	// Add some mock things
	thing1 := &wot.ThingDescription{ID: "thing1", Title: "Test Thing 1"}
	thing2 := &wot.ThingDescription{ID: "thing2", Title: "Test Thing 2"}
	thingRegistry.AddThing(thing1)
	thingRegistry.AddThing(thing2)

	service := NewWoTServiceWithInterfaces(thingRegistry, configManager, logger).(*WoTService)
	ctx := context.Background()

	config := types.ServiceConfig{
		Name:   "wot",
		Config: make(map[string]interface{}),
	}

	err := service.Start(ctx, config)
	require.NoError(t, err)

	// Check that things were loaded
	registeredThings := service.GetRegisteredThings()
	assert.Len(t, registeredThings, 2)
	assert.Equal(t, "active", registeredThings["thing1"])
	assert.Equal(t, "active", registeredThings["thing2"])

	// Test service status
	status := service.GetServiceStatus()
	assert.Equal(t, true, status["running"])
	assert.Equal(t, 2, status["registered_things"])
	assert.Equal(t, true, status["has_config"])
	assert.Equal(t, "wot", status["config_name"])
}

func TestWoTService_HealthChecks(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	t.Run("healthy_service", func(t *testing.T) {
		thingRegistry := NewMockThingRegistry()
		configManager := NewMockConfigManager()

		service := NewWoTServiceWithInterfaces(thingRegistry, configManager, logger).(*WoTService)
		ctx := context.Background()

		config := types.ServiceConfig{
			Name:   "wot",
			Config: make(map[string]interface{}),
		}

		err := service.Start(ctx, config)
		require.NoError(t, err)

		err = service.HealthCheck()
		assert.NoError(t, err)
	})

	t.Run("nil_thing_registry", func(t *testing.T) {
		configManager := NewMockConfigManager()

		service := &WoTService{
			thingRegistry:    nil, // Nil registry
			configManager:    configManager,
			logger:           logger,
			running:          true,
			registeredThings: make(map[string]string),
		}

		err := service.HealthCheck()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ThingRegistry is nil")
	})

	t.Run("nil_config_manager", func(t *testing.T) {
		thingRegistry := NewMockThingRegistry()

		service := &WoTService{
			thingRegistry:    thingRegistry,
			configManager:    nil, // Nil config manager
			logger:           logger,
			running:          true,
			registeredThings: make(map[string]string),
		}

		err := service.HealthCheck()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ConfigManager is nil")
	})

	t.Run("registry_access_failure", func(t *testing.T) {
		thingRegistry := NewMockThingRegistry()
		thingRegistry.SetListError(assert.AnError)
		configManager := NewMockConfigManager()

		service := &WoTService{
			thingRegistry:    thingRegistry,
			configManager:    configManager,
			logger:           logger,
			running:          true,
			registeredThings: make(map[string]string),
		}

		err := service.HealthCheck()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ThingRegistry access failed")
	})
}

func TestWoTService_ConfigProcessing(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	thingRegistry := NewMockThingRegistry()
	configManager := NewMockConfigManager()

	service := NewWoTServiceWithInterfaces(thingRegistry, configManager, logger).(*WoTService)

	t.Run("valid_config", func(t *testing.T) {
		config := map[string]interface{}{
			"auto_discovery": true,
			"max_things":     100.0,
		}

		err := service.processWoTConfig(config)
		assert.NoError(t, err)
	})

	t.Run("invalid_config_type", func(t *testing.T) {
		err := service.processWoTConfig("invalid config")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be a map")
	})

	t.Run("partial_config", func(t *testing.T) {
		config := map[string]interface{}{
			"auto_discovery": false,
			// missing max_things
		}

		err := service.processWoTConfig(config)
		assert.NoError(t, err) // Should not error for missing optional fields
	})
}
