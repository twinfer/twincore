package service

import (
	"context"
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/types"
)

// serviceRegistry implements the types.ServiceRegistry interface.
type serviceRegistry struct {
	services         map[string]types.Service
	permittedService map[string]bool                // Tracks which services are permitted by the license
	serviceConfigs   map[string]types.ServiceConfig // Store service configurations
	mu               sync.RWMutex
	logger           *logrus.Logger
}

// NewServiceRegistry creates a new instance of a service registry.
func NewServiceRegistry() types.ServiceRegistry {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	return &serviceRegistry{
		services:         make(map[string]types.Service),
		permittedService: make(map[string]bool),
		serviceConfigs:   make(map[string]types.ServiceConfig),
		logger:           logger,
	}
}

// NewServiceRegistryWithLogger creates a service registry with a custom logger.
func NewServiceRegistryWithLogger(logger *logrus.Logger) types.ServiceRegistry {
	return &serviceRegistry{
		services:         make(map[string]types.Service),
		permittedService: make(map[string]bool),
		serviceConfigs:   make(map[string]types.ServiceConfig),
		logger:           logger,
	}
}

func (sr *serviceRegistry) RegisterService(name string, service types.Service) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.services[name] = service
	// By default, assume a service is not permitted until LoadPermittedServices is called.
	sr.permittedService[name] = false
	sr.logger.Infof("Service registered: %s", name)
}

// RegisterServiceWithConfig registers a service with its configuration
func (sr *serviceRegistry) RegisterServiceWithConfig(name string, service types.Service, config types.ServiceConfig) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.services[name] = service
	sr.serviceConfigs[name] = config
	sr.permittedService[name] = false
	sr.logger.Infof("Service registered with config: %s", name)
}

// SetServiceConfig sets or updates the configuration for a service
func (sr *serviceRegistry) SetServiceConfig(name string, config types.ServiceConfig) error {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if _, exists := sr.services[name]; !exists {
		return fmt.Errorf("service %s not registered", name)
	}

	sr.serviceConfigs[name] = config
	sr.logger.Infof("Configuration updated for service: %s", name)
	return nil
}

func (sr *serviceRegistry) LoadPermittedServices(license types.License) error {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if license == nil {
		sr.logger.Warn("No license provided to LoadPermittedServices. All services will be disabled.")
		for name := range sr.services {
			sr.permittedService[name] = false
		}
		return fmt.Errorf("license is nil, cannot determine permitted services")
	}

	for name, service := range sr.services {
		permitted := true
		var missingFeatures []string

		for _, feature := range service.RequiredLicense() {
			if !license.IsFeatureEnabled(feature) {
				permitted = false
				missingFeatures = append(missingFeatures, feature)
			}
		}

		sr.permittedService[name] = permitted

		if permitted {
			sr.logger.Infof("Service %s is permitted by license", name)
		} else {
			sr.logger.Warnf("Service %s is NOT permitted by license (missing features: %v)", name, missingFeatures)
		}
	}
	return nil
}

func (sr *serviceRegistry) StartService(ctx context.Context, name string) error {
	sr.mu.RLock()
	service, exists := sr.services[name]
	permitted, pExists := sr.permittedService[name]
	config, hasConfig := sr.serviceConfigs[name]
	sr.mu.RUnlock()

	if !exists {
		return fmt.Errorf("service %s not registered", name)
	}
	if !pExists || !permitted {
		sr.logger.Warnf("Attempted to start service %s, but it is not permitted by the license", name)
		return fmt.Errorf("service %s is not permitted by license", name)
	}

	// Use stored configuration if available, otherwise create minimal config
	if !hasConfig {
		sr.logger.Warnf("No configuration found for service %s, using minimal config", name)
		config = types.ServiceConfig{
			Name:   name,
			Config: make(map[string]any),
		}
	}

	sr.logger.Infof("Starting service: %s", name)
	if err := service.Start(ctx, config); err != nil {
		sr.logger.Errorf("Failed to start service %s: %v", name, err)
		return fmt.Errorf("failed to start service %s: %w", name, err)
	}

	sr.logger.Infof("Service %s started successfully", name)
	return nil
}

// StartServiceWithConfig starts a service with a specific configuration
func (sr *serviceRegistry) StartServiceWithConfig(ctx context.Context, name string, config types.ServiceConfig) error {
	sr.mu.RLock()
	service, exists := sr.services[name]
	permitted, pExists := sr.permittedService[name]
	sr.mu.RUnlock()

	if !exists {
		return fmt.Errorf("service %s not registered", name)
	}
	if !pExists || !permitted {
		sr.logger.Warnf("Attempted to start service %s, but it is not permitted by the license", name)
		return fmt.Errorf("service %s is not permitted by license", name)
	}

	sr.logger.Infof("Starting service with custom config: %s", name)
	if err := service.Start(ctx, config); err != nil {
		sr.logger.Errorf("Failed to start service %s: %v", name, err)
		return fmt.Errorf("failed to start service %s: %w", name, err)
	}

	sr.logger.Infof("Service %s started successfully with custom config", name)
	return nil
}

func (sr *serviceRegistry) StopService(ctx context.Context, name string) error {
	sr.mu.RLock()
	service, exists := sr.services[name]
	sr.mu.RUnlock()

	if !exists {
		return fmt.Errorf("service %s not registered", name)
	}

	sr.logger.Infof("Stopping service: %s", name)
	if err := service.Stop(ctx); err != nil {
		sr.logger.Errorf("Failed to stop service %s: %v", name, err)
		return fmt.Errorf("failed to stop service %s: %w", name, err)
	}

	sr.logger.Infof("Service %s stopped successfully", name)
	return nil
}

// GetServiceStatus returns information about registered services
func (sr *serviceRegistry) GetServiceStatus() map[string]types.ServiceStatus {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	status := make(map[string]types.ServiceStatus)
	for name, service := range sr.services {
		permitted := sr.permittedService[name]
		_, hasConfig := sr.serviceConfigs[name]

		status[name] = types.ServiceStatus{
			Name:            name,
			Registered:      true,
			Permitted:       permitted,
			HasConfig:       hasConfig,
			ServiceType:     service.Name(),
			Dependencies:    service.Dependencies(),
			RequiredLicense: service.RequiredLicense(),
		}
	}

	return status
}
