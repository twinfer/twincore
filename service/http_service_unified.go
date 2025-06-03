package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/josephburnett/jd/v2"
	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/security"
	"github.com/twinfer/twincore/pkg/types"
)

// HTTPServiceUnified consolidates HTTP service functionality without Admin API
type HTTPServiceUnified struct {
	currentConfig  *caddy.Config
	running        bool
	logger         logrus.FieldLogger
	mu             sync.RWMutex
	securityBridge *security.CaddySecurityBridge // Integration with caddy-security
}

// NewHTTPServiceUnified creates a new unified HTTP service
func NewHTTPServiceUnified(logger logrus.FieldLogger) types.Service {
	return &HTTPServiceUnified{
		logger: logger,
	}
}

// SetSecurityBridge sets the caddy-security integration bridge
func (h *HTTPServiceUnified) SetSecurityBridge(bridge *security.CaddySecurityBridge) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.securityBridge = bridge
}

func (h *HTTPServiceUnified) Name() string {
	return "http-unified"
}

func (h *HTTPServiceUnified) RequiredLicense() []string {
	return []string{"core", "http"}
}

func (h *HTTPServiceUnified) Dependencies() []string {
	return []string{}
}

func (h *HTTPServiceUnified) Start(ctx context.Context, config types.ServiceConfig) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.running {
		return fmt.Errorf("HTTP service already running")
	}

	// Generate initial Caddy configuration
	caddyConfig, err := h.buildCaddyConfig(config)
	if err != nil {
		return fmt.Errorf("failed to build Caddy config: %w", err)
	}

	// Don't validate before loading - Caddy will validate during Load
	// Just marshal the config directly
	configBytes, err := json.Marshal(caddyConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	h.logger.WithField("config", string(configBytes)).Debug("Loading Caddy configuration")

	// Load configuration directly (no Admin API)
	// Caddy will validate the config during loading
	if err := caddy.Load(configBytes, false); err != nil {
		h.logger.WithError(err).Error("Failed to load Caddy configuration")
		return fmt.Errorf("failed to load Caddy config: %w", err)
	}

	h.currentConfig = caddyConfig
	h.running = true
	h.logger.Info("HTTP service started successfully")
	return nil
}

func (h *HTTPServiceUnified) Stop(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return nil
	}

	if err := caddy.Stop(); err != nil {
		return fmt.Errorf("failed to stop Caddy: %w", err)
	}

	h.running = false
	h.currentConfig = nil
	h.logger.Info("HTTP service stopped successfully")
	return nil
}

func (h *HTTPServiceUnified) UpdateConfig(config types.ServiceConfig) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.running {
		return fmt.Errorf("service not running")
	}

	// Build new configuration
	newConfig, err := h.buildCaddyConfig(config)
	if err != nil {
		return fmt.Errorf("failed to build new config: %w", err)
	}

	// Calculate diff using josephburnett/jd for logging/debugging
	if h.currentConfig != nil {
		if err := h.logConfigDiff(h.currentConfig, newConfig); err != nil {
			h.logger.WithError(err).Warn("Failed to calculate config diff for logging")
		}
	}

	// Convert new config to JSON for loading
	// Don't validate before loading - Caddy will validate during Load
	newConfigJSON, err := json.Marshal(newConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal new config: %w", err)
	}

	// Apply new configuration with graceful reload
	if err := caddy.Load(newConfigJSON, false); err != nil {
		h.logger.WithError(err).Error("Failed to reload Caddy configuration")
		return fmt.Errorf("failed to reload config: %w", err)
	}

	h.currentConfig = newConfig
	h.logger.Info("HTTP service configuration updated successfully")
	return nil
}

func (h *HTTPServiceUnified) HealthCheck() error {
	h.mu.RLock()
	running := h.running
	h.mu.RUnlock()

	if !running {
		return fmt.Errorf("service not running")
	}

	// Since we don't use Admin API, we'll check if Caddy is responding
	// by making a test request to a known endpoint or checking internal status
	// For now, we'll just verify the service thinks it's running
	return nil
}

// logConfigDiff calculates and logs the difference between old and new configs
func (h *HTTPServiceUnified) logConfigDiff(oldConfig, newConfig *caddy.Config) error {
	// Convert configs to JSON for diff calculation
	oldJSON, err := json.Marshal(oldConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal old config: %w", err)
	}

	newJSON, err := json.Marshal(newConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal new config: %w", err)
	}

	// Calculate diff using josephburnett/jd
	oldJSONNode, err := jd.ReadJsonString(string(oldJSON))
	if err != nil {
		return fmt.Errorf("failed to parse old config JSON: %w", err)
	}

	newJSONNode, err := jd.ReadJsonString(string(newJSON))
	if err != nil {
		return fmt.Errorf("failed to parse new config JSON: %w", err)
	}

	diff := oldJSONNode.Diff(newJSONNode)
	if len(diff) > 0 {
		h.logger.WithField("config_changes", diff.Render()).Info("Configuration changes detected")
	} else {
		h.logger.Debug("No configuration changes detected")
	}

	return nil
}

// buildCaddyConfig creates a comprehensive Caddy configuration
func (h *HTTPServiceUnified) buildCaddyConfig(config types.ServiceConfig) (*caddy.Config, error) {
	// Try to extract HTTPConfig from the service config
	// The config might be stored as a map[string]interface{} that needs to be converted
	var httpConfig types.HTTPConfig

	if httpCfgRaw, ok := config.Config["http"]; ok {
		// Check if it's already the right type
		if hc, ok := httpCfgRaw.(types.HTTPConfig); ok {
			httpConfig = hc
		} else if httpMap, ok := httpCfgRaw.(map[string]interface{}); ok {
			// Convert from map to HTTPConfig
			if err := h.mapToHTTPConfig(httpMap, &httpConfig); err != nil {
				return nil, fmt.Errorf("failed to parse HTTP configuration: %w", err)
			}
		} else {
			return nil, fmt.Errorf("invalid HTTP configuration type: %T", httpCfgRaw)
		}
	} else {
		return nil, fmt.Errorf("missing HTTP configuration")
	}

	// Build routes
	var routes caddyhttp.RouteList

	// Add application routes
	// Note: Authentication is now handled by SystemSecurityManager middleware
	for _, route := range httpConfig.Routes {
		caddyRoute := h.buildRoute(route)
		routes = append(routes, caddyRoute)
	}

	h.logger.WithFields(logrus.Fields{
		"routes_count": len(routes),
		"listen_addrs": httpConfig.Listen,
	}).Debug("Building Caddy configuration")

	// Build server configuration
	listenAddrs := httpConfig.Listen
	if len(listenAddrs) == 0 {
		listenAddrs = []string{":8080"} // Default
	}

	// If no routes are configured, add a default route
	if len(routes) == 0 {
		// Create the path matcher
		pathMatcherJSON, err := json.Marshal([]string{"/*"})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal path matcher: %w", err)
		}

		// Create the static response handler
		staticHandler := caddyconfig.JSONModuleObject(
			caddyhttp.StaticResponse{
				Body:       `{"message": "TwinCore HTTP Service"}`,
				StatusCode: caddyhttp.WeakString("200"),
			},
			"handler", "static_response", nil,
		)

		defaultRoute := caddyhttp.Route{
			MatcherSetsRaw: []caddy.ModuleMap{
				{
					"path": json.RawMessage(pathMatcherJSON),
				},
			},
			HandlersRaw: []json.RawMessage{staticHandler},
		}
		routes = append(routes, defaultRoute)
	}

	// Create server configuration exactly like the working simple service
	server := &caddyhttp.Server{
		Listen: listenAddrs,
		Routes: routes,
	}

	// Create HTTP app configuration
	httpApp := caddyhttp.App{
		Servers: map[string]*caddyhttp.Server{
			"srv0": server,
		},
	}

	// Marshal the HTTP app directly
	httpAppJSON, err := json.Marshal(httpApp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal HTTP app: %w", err)
	}

	// Create apps configuration
	apps := caddy.ModuleMap{
		"http": json.RawMessage(httpAppJSON),
	}

	// Add caddy-security app if security bridge is configured
	if h.securityBridge != nil {
		securityAppJSON, err := h.securityBridge.GenerateSecurityApp(context.Background())
		if err != nil {
			h.logger.WithError(err).Warn("Failed to generate caddy-security app configuration")
		} else if securityAppJSON != nil {
			apps["security"] = securityAppJSON
			h.logger.Debug("Added caddy-security app to Caddy configuration")
		}
	}

	// Create Caddy config without Admin API for security
	cfg := &caddy.Config{
		Admin: &caddy.AdminConfig{
			Disabled: true, // Disable Admin API for security
		},
		AppsRaw: apps,
	}

	return cfg, nil
}

// buildRoute creates a route configuration for WoT endpoints
func (h *HTTPServiceUnified) buildRoute(route types.HTTPRoute) caddyhttp.Route {
	matcherSet := caddy.ModuleMap{}
	var handlers []json.RawMessage

	// Path matcher
	matcherSet["path"] = caddyconfig.JSON([]string{route.Path}, nil)

	// Method matcher
	if len(route.Methods) > 0 {
		matcherSet["method"] = caddyconfig.JSON(route.Methods, nil)
	}

	// Add authentication middleware if security bridge is configured and route should be protected
	if h.securityBridge != nil {
		authMiddleware, err := h.securityBridge.GenerateAuthenticationMiddleware(route)
		if err != nil {
			h.logger.WithError(err).Warn("Failed to generate authentication middleware")
		} else if authMiddleware != nil {
			handlers = append(handlers, authMiddleware)
			h.logger.WithField("path", route.Path).Debug("Added authentication middleware to route")
		}
	}

	// Build handler based on route type
	switch route.Handler {
	case "reverse_proxy":
		if upstream, ok := route.Config["upstream"].(string); ok {
			reverseProxyConfig := map[string]interface{}{
				"upstreams": []map[string]interface{}{
					{"dial": upstream},
				},
			}
			handlers = append(handlers, caddyconfig.JSONModuleObject(
				reverseProxyConfig,
				"handler", "reverse_proxy", nil,
			))
		}
	case "static", "static_response": // Support both handler names for compatibility
		body, _ := route.Config["body"].(string)
		statusCode, _ := route.Config["status_code"].(int)
		if statusCode == 0 {
			statusCode = 200
		}

		staticConfig := caddyhttp.StaticResponse{
			Body:       body,
			StatusCode: caddyhttp.WeakString(fmt.Sprintf("%d", statusCode)),
		}

		handlers = append(handlers, caddyconfig.JSONModuleObject(
			staticConfig,
			"handler", "static_response", nil,
		))
	default:
		// Default handler for unimplemented route types
		defaultConfig := caddyhttp.StaticResponse{
			Body:       fmt.Sprintf(`{"error": "handler not implemented: %s"}`, route.Handler),
			StatusCode: caddyhttp.WeakString("501"),
		}

		handlers = append(handlers, caddyconfig.JSONModuleObject(
			defaultConfig,
			"handler", "static_response", nil,
		))
	}

	return caddyhttp.Route{
		MatcherSetsRaw: []caddy.ModuleMap{matcherSet},
		HandlersRaw:    handlers,
	}
}

// mapToHTTPConfig converts a map to HTTPConfig struct
func (h *HTTPServiceUnified) mapToHTTPConfig(m map[string]interface{}, cfg *types.HTTPConfig) error {
	// Convert map to JSON then unmarshal to struct
	jsonBytes, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("failed to marshal config map: %w", err)
	}

	if err := json.Unmarshal(jsonBytes, cfg); err != nil {
		return fmt.Errorf("failed to unmarshal to HTTPConfig: %w", err)
	}

	// Set defaults if needed
	if len(cfg.Listen) == 0 {
		cfg.Listen = []string{":8080"}
	}

	return nil
}

// Interface guard
var _ types.Service = (*HTTPServiceUnified)(nil)
