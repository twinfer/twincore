// Package service provides thin orchestration layers for TwinCore services
package service

import (
	"context"
	"fmt"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/api"
	"github.com/twinfer/twincore/internal/security"
	"github.com/twinfer/twincore/pkg/types"
)

// HTTPService is a thin orchestration layer that delegates to ConfigurationManager
type HTTPService struct {
	configManager  api.ConfigurationManager
	securityBridge *security.CaddyAuthPortalBridge
	logger         logrus.FieldLogger
	mu             sync.RWMutex
	running        bool
}

// NewHTTPService creates a new refactored HTTP service
func NewHTTPService(configManager api.ConfigurationManager, logger logrus.FieldLogger) types.Service {
	return &HTTPService{
		configManager: configManager,
		logger:        logger,
	}
}

// SetSecurityBridge sets the caddy-security integration bridge
func (h *HTTPService) SetSecurityBridge(bridge *security.CaddyAuthPortalBridge) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.securityBridge = bridge
}

// Name returns the service name
func (h *HTTPService) Name() string {
	return "http-unified"
}

// RequiredLicense returns required license features
func (h *HTTPService) RequiredLicense() []string {
	return []string{"core", "http"}
}

// Dependencies returns service dependencies
func (h *HTTPService) Dependencies() []string {
	return []string{}
}

// Start initializes and starts the HTTP service
func (h *HTTPService) Start(ctx context.Context, config types.ServiceConfig) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		return fmt.Errorf("HTTP service already running")
	}

	h.logger.Info("HTTP service starting...")

	// Extract HTTP configuration
	httpCfgRaw, ok := config.Config["http"]
	if !ok {
		return fmt.Errorf("missing HTTP configuration")
	}

	// Convert configuration to proper type
	var httpConfig types.HTTPConfig
	if hc, ok := httpCfgRaw.(types.HTTPConfig); ok {
		httpConfig = hc
	} else if httpMap, ok := httpCfgRaw.(map[string]any); ok {
		// Convert from map to HTTPConfig
		if err := h.mapToHTTPConfig(httpMap, &httpConfig); err != nil {
			return fmt.Errorf("failed to parse HTTP configuration: %w", err)
		}
	} else {
		return fmt.Errorf("invalid HTTP configuration type: %T", httpCfgRaw)
	}

	// Add routes to ConfigurationManager
	for i, route := range httpConfig.Routes {
		routeID := fmt.Sprintf("http-service-route-%d", i)

		// Security is now handled by caddy-auth-portal at the configuration level
		// The CaddyAuthPortalBridge generates the complete security configuration
		// which is applied when the Caddy configuration is loaded
		if h.securityBridge != nil {
			h.logger.WithField("path", route.Path).Debug("Route will be protected by caddy-auth-portal")
		}

		if err := h.configManager.AddRoute(ctx, routeID, route); err != nil {
			return fmt.Errorf("failed to add route %s: %w", routeID, err)
		}
	}

	// The ConfigurationManager handles all Caddy configuration and loading
	// We just need to ensure initial setup is complete
	if !h.configManager.IsSetupComplete() {
		h.logger.Info("Completing initial setup via ConfigurationManager")
		if err := h.configManager.CompleteSetup(h.logger); err != nil {
			return fmt.Errorf("failed to complete setup: %w", err)
		}
	}

	h.running = true
	h.logger.Info("HTTP service started successfully")
	return nil
}

// Stop gracefully stops the HTTP service
func (h *HTTPService) Stop(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return nil
	}

	h.logger.Info("HTTP service stopping...")

	// Stop Caddy
	if err := caddy.Stop(); err != nil {
		return fmt.Errorf("failed to stop Caddy: %w", err)
	}

	h.running = false
	h.logger.Info("HTTP service stopped successfully")
	return nil
}

// UpdateConfig updates the service configuration
func (h *HTTPService) UpdateConfig(config types.ServiceConfig) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return fmt.Errorf("service not running")
	}

	h.logger.Info("HTTP service: Updating configuration")

	// Extract HTTP configuration
	httpCfgRaw, ok := config.Config["http"]
	if !ok {
		return fmt.Errorf("missing HTTP configuration")
	}

	// Convert and update via ConfigurationManager
	if err := h.configManager.UpdateConfiguration(h.logger, "http", httpCfgRaw.(map[string]any)); err != nil {
		return fmt.Errorf("failed to update configuration: %w", err)
	}

	h.logger.Info("HTTP service configuration updated successfully")
	return nil
}

// HealthCheck verifies the service is healthy
func (h *HTTPService) HealthCheck() error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if !h.running {
		return fmt.Errorf("service not running")
	}

	// Check if configuration manager is available
	if h.configManager == nil {
		return fmt.Errorf("configuration manager not available")
	}

	// The service is considered healthy if it's running
	// Additional health checks could be added here
	return nil
}

// mapToHTTPConfig is a helper to convert map to HTTPConfig
// This is kept for backward compatibility with existing configuration formats
func (h *HTTPService) mapToHTTPConfig(m map[string]any, cfg *types.HTTPConfig) error {
	// Simple conversion logic - in production, use proper JSON marshaling
	if listen, ok := m["listen"].([]any); ok {
		cfg.Listen = make([]string, len(listen))
		for i, l := range listen {
			cfg.Listen[i] = l.(string)
		}
	}

	if routes, ok := m["routes"].([]any); ok {
		cfg.Routes = make([]types.HTTPRoute, len(routes))
		for i, r := range routes {
			if routeMap, ok := r.(map[string]any); ok {
				route := types.HTTPRoute{
					Path:    routeMap["path"].(string),
					Handler: routeMap["handler"].(string),
				}

				if methods, ok := routeMap["methods"].([]any); ok {
					route.Methods = make([]string, len(methods))
					for j, m := range methods {
						route.Methods[j] = m.(string)
					}
				}

				if config, ok := routeMap["config"].(map[string]any); ok {
					route.Config = config
				}

				if requiresAuth, ok := routeMap["requires_auth"].(bool); ok {
					route.RequiresAuth = requiresAuth
				}

				cfg.Routes[i] = route
			}
		}
	}

	return nil
}

// Interface guard
var _ types.Service = (*HTTPService)(nil)
