// internal/service/wot_service.go
package service

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/config"
	"github.com/twinfer/twincore/pkg/types"
)

// WoTService manages Thing Description lifecycle and interactions.
type WoTService struct {
	thingRegistry *config.ThingRegistry
	configManager *config.ConfigManager
	logger        *logrus.Logger
	running       bool
}

// NewWoTService creates a new WoTService.
func NewWoTService(
	tr *config.ThingRegistry,
	cm *config.ConfigManager,
	logger *logrus.Logger,
) types.Service {
	return &WoTService{
		thingRegistry: tr,
		configManager: cm,
		logger:        logger,
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
	// WoT service might not have a long-running process itself,
	// but relies on other services (HTTP, Stream) to expose WoT interactions
	// which are configured via ThingRegistry and ConfigManager.
	// Initialization logic for WoT specific tasks could go here.
	s.running = true
	s.logger.Info("WoTService started successfully.")
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
	s.logger.Info("WoTService UpdateConfig called. No dynamic updates implemented for WoT service itself yet.")
	// WoT service configuration is primarily through Thing Descriptions.
	// Updates to TDs would trigger updates in HTTP and Stream services.
	return nil
}

func (s *WoTService) HealthCheck() error {
	if !s.running {
		return fmt.Errorf("WoT service not running")
	}
	// Add specific health checks for WoT components if necessary
	// For example, check ThingRegistry or ConfigManager health.
	s.logger.Debug("WoTService health check: OK")
	return nil
}
