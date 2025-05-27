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
	permittedService map[string]bool // Tracks which services are permitted by the license
	mu               sync.RWMutex
	logger           *logrus.Logger // Optional: if the registry itself needs logging
}

// NewServiceRegistry creates a new instance of a service registry.
func NewServiceRegistry() types.ServiceRegistry {
	// If the registry needs its own logger, it could be passed here or created.
	// For now, let's assume it doesn't log much itself, or services log individually.
	// logger := logrus.New()
	// logger.SetLevel(logrus.InfoLevel)

	return &serviceRegistry{
		services:         make(map[string]types.Service),
		permittedService: make(map[string]bool),
		// logger: logger,
	}
}

func (sr *serviceRegistry) RegisterService(name string, service types.Service) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.services[name] = service
	// By default, assume a service is not permitted until LoadPermittedServices is called.
	// Or, assume permitted and let LoadPermittedServices restrict.
	// For safety, let's assume not permitted by default.
	sr.permittedService[name] = false
	// sr.logger.Infof("Service registered: %s", name)
}

func (sr *serviceRegistry) LoadPermittedServices(license types.License) error {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if license == nil {
		// sr.logger.Warn("No license provided to LoadPermittedServices. All services will be disabled.")
		// Or, define a default behavior (e.g., only "core" services enabled)
		for name := range sr.services {
			sr.permittedService[name] = false // Or true for a base set
		}
		return fmt.Errorf("license is nil, cannot determine permitted services")
	}

	for name, service := range sr.services {
		permitted := true
		for _, feature := range service.RequiredLicense() {
			if !license.IsFeatureEnabled(feature) {
				permitted = false
				// sr.logger.Warnf("Service %s requires feature '%s' which is not enabled by the license.", name, feature)
				break
			}
		}
		sr.permittedService[name] = permitted
		// if permitted {
		// 	sr.logger.Infof("Service %s is permitted by license.", name)
		// } else {
		// 	sr.logger.Infof("Service %s is NOT permitted by license.", name)
		// }
	}
	return nil
}

func (sr *serviceRegistry) StartService(ctx context.Context, name string) error {
	sr.mu.RLock()
	service, exists := sr.services[name]
	permitted, pExists := sr.permittedService[name]
	sr.mu.RUnlock()

	if !exists {
		return fmt.Errorf("service %s not registered", name)
	}
	if !pExists || !permitted {
		// sr.logger.Warnf("Attempted to start service %s, but it is not permitted by the license.", name)
		return fmt.Errorf("service %s is not permitted by license", name)
	}

	// The service's Start method should take types.ServiceConfig.
	// The container.go logic should fetch the appropriate config for this service.
	// For now, this registry doesn't know about specific configs, it just calls Start.
	// The caller (container.go) is responsible for passing the correct config.
	// This is a placeholder; actual config passing needs to be handled by the caller.
	dummyConfig := types.ServiceConfig{Name: name, Config: make(map[string]interface{})}
	return service.Start(ctx, dummyConfig)
}

func (sr *serviceRegistry) StopService(ctx context.Context, name string) error {
	sr.mu.RLock()
	service, exists := sr.services[name]
	sr.mu.RUnlock()

	if !exists {
		return fmt.Errorf("service %s not registered", name)
	}
	// No license check needed for stopping
	return service.Stop(ctx)
}
