// internal/service/wot_service.go
package service

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/config"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
)

// ThingRegistryInterface defines the interface for thing registry operations
type ThingRegistryInterface interface {
	ListThings() ([]*wot.ThingDescription, error)
}

// ConfigManagerInterface defines the interface for config manager operations
type ConfigManagerInterface interface {
	// Add methods as needed for config operations
}

// WoTService manages Thing Description lifecycle and interactions.
type WoTService struct {
	thingRegistry    ThingRegistryInterface
	configManager    ConfigManagerInterface
	logger           *logrus.Logger
	running          bool
	currentConfig    *types.ServiceConfig
	registeredThings map[string]string // thingID -> registration status
}

// NewWoTService creates a new WoTService.
func NewWoTService(
	tr *config.ThingRegistry,
	cm *config.ConfigManager,
	logger *logrus.Logger,
) types.Service {
	return &WoTService{
		thingRegistry:    tr,
		configManager:    cm,
		logger:           logger,
		registeredThings: make(map[string]string),
	}
}

// NewWoTServiceWithInterfaces creates a new WoTService with interfaces for testing.
func NewWoTServiceWithInterfaces(
	tr ThingRegistryInterface,
	cm ConfigManagerInterface,
	logger *logrus.Logger,
) types.Service {
	return &WoTService{
		thingRegistry:    tr,
		configManager:    cm,
		logger:           logger,
		registeredThings: make(map[string]string),
	}
}

func (s *WoTService) Name() string {
	return "wot"
}

func (s *WoTService) RequiredLicense() []string {
	return []string{"core", "wot"} // Example license requirements
}

func (s *WoTService) Dependencies() []string {
	return []string{"http", "stream"} // Depends on HTTP and Stream services for exposure
}

func (s *WoTService) Start(ctx context.Context, serviceConfig types.ServiceConfig) error {
	if s.running {
		return fmt.Errorf("WoT service already running")
	}

	s.logger.Info("WoTService starting...")
	s.currentConfig = &serviceConfig

	// Initialize WoT-specific configuration if provided
	if wotConfig, ok := serviceConfig.Config["wot"]; ok {
		s.logger.WithField("config", wotConfig).Debug("Loading WoT configuration")
		if err := s.processWoTConfig(wotConfig); err != nil {
			return fmt.Errorf("failed to process WoT configuration: %w", err)
		}
	}

	// Load existing Things from registry
	if err := s.loadExistingThings(); err != nil {
		s.logger.WithError(err).Warn("Failed to load existing things, continuing anyway")
	}

	s.running = true
	s.logger.WithField("registered_things", len(s.registeredThings)).Info("WoTService started successfully")
	return nil
}

func (s *WoTService) Stop(ctx context.Context) error {
	if !s.running {
		return nil
	}
	s.logger.Info("WoTService stopping...")
	s.running = false
	s.logger.Info("WoTService stopped.")
	return nil
}

func (s *WoTService) UpdateConfig(serviceConfig types.ServiceConfig) error {
	s.logger.Info("WoTService UpdateConfig called")

	if !s.running {
		return fmt.Errorf("WoT service not running")
	}

	// Process WoT-specific configuration updates
	if wotConfig, ok := serviceConfig.Config["wot"]; ok {
		s.logger.WithField("config", wotConfig).Info("Updating WoT configuration")
		if err := s.processWoTConfig(wotConfig); err != nil {
			return fmt.Errorf("failed to process updated WoT configuration: %w", err)
		}
	}

	s.currentConfig = &serviceConfig
	s.logger.Info("WoTService configuration updated successfully")
	return nil
}

func (s *WoTService) HealthCheck() error {
	if !s.running {
		return fmt.Errorf("WoT service not running")
	}

	// Check ThingRegistry health
	if s.thingRegistry == nil {
		return fmt.Errorf("ThingRegistry is nil")
	}

	// Check ConfigManager health
	if s.configManager == nil {
		return fmt.Errorf("ConfigManager is nil")
	}

	// Test registry access by trying to list things
	if _, err := s.thingRegistry.ListThings(); err != nil {
		return fmt.Errorf("ThingRegistry access failed: %w", err)
	}

	s.logger.Debug("WoTService health check: OK")
	return nil
}

// processWoTConfig processes WoT-specific configuration
func (s *WoTService) processWoTConfig(config interface{}) error {
	configMap, ok := config.(map[string]interface{})
	if !ok {
		return fmt.Errorf("WoT config must be a map")
	}

	// Process any WoT-specific settings
	if enableAutoDiscovery, ok := configMap["auto_discovery"]; ok {
		if enabled, ok := enableAutoDiscovery.(bool); ok && enabled {
			s.logger.Info("Auto-discovery enabled for WoT service")
			// TODO: Implement auto-discovery logic
		}
	}

	if maxThings, ok := configMap["max_things"]; ok {
		if max, ok := maxThings.(float64); ok {
			s.logger.WithField("max_things", int(max)).Info("Setting maximum thing limit")
			// TODO: Implement thing limit enforcement
		}
	}

	return nil
}

// loadExistingThings loads existing Thing Descriptions from the registry
func (s *WoTService) loadExistingThings() error {
	things, err := s.thingRegistry.ListThings()
	if err != nil {
		return fmt.Errorf("failed to list existing things: %w", err)
	}

	for _, thing := range things {
		if thing.ID != "" {
			s.registeredThings[thing.ID] = "active"
			s.logger.WithField("thing_id", thing.ID).Debug("Loaded existing thing")
		}
	}

	s.logger.WithField("count", len(s.registeredThings)).Info("Loaded existing things from registry")
	return nil
}

// GetRegisteredThings returns a copy of registered things for monitoring
func (s *WoTService) GetRegisteredThings() map[string]string {
	result := make(map[string]string)
	for id, status := range s.registeredThings {
		result[id] = status
	}
	return result
}

// GetServiceStatus returns detailed status information
func (s *WoTService) GetServiceStatus() map[string]interface{} {
	status := map[string]interface{}{
		"running":           s.running,
		"registered_things": len(s.registeredThings),
		"has_config":        s.currentConfig != nil,
		"thing_registry_ok": s.thingRegistry != nil,
		"config_manager_ok": s.configManager != nil,
	}

	if s.currentConfig != nil {
		status["config_name"] = s.currentConfig.Name
	}

	return status
}
