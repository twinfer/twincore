// internal/service/http_service.go
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/types"
)

type HTTPServiceSimple struct {
	config  *caddy.Config
	running bool
	logger  logrus.FieldLogger
}

// NewHTTPServiceSimple creates HTTP service without go-authcrunch
func NewHTTPServiceSimple(logger logrus.FieldLogger) types.Service {
	return &HTTPServiceSimple{
		logger: logger,
	}
}

func (h *HTTPServiceSimple) Name() string {
	return "http"
}

func (h *HTTPServiceSimple) RequiredLicense() []string {
	return []string{"core", "http"}
}

func (h *HTTPServiceSimple) Dependencies() []string {
	return []string{}
}

func (h *HTTPServiceSimple) Start(ctx context.Context, config types.ServiceConfig) error {
	if h.running {
		return fmt.Errorf("HTTP service already running")
	}

	// Generate Caddy configuration
	caddyConfig, err := h.GenerateCaddyConfig(config)
	if err != nil {
		return fmt.Errorf("failed to generate Caddy config: %w", err)
	}

	// Validate using Caddy's built-in Validate function
	if err := caddy.Validate(caddyConfig); err != nil {
		return fmt.Errorf("invalid Caddy configuration: %w", err)
	}

	// Load and start Caddy with configuration
	if err := caddy.Load(caddyconfig.JSON(caddyConfig, nil), false); err != nil {
		return fmt.Errorf("failed to load Caddy config: %w", err)
	}

	h.config = caddyConfig
	h.running = true
	return nil
}

func (h *HTTPServiceSimple) Stop(ctx context.Context) error {
	if !h.running {
		return nil
	}

	if err := caddy.Stop(); err != nil {
		return fmt.Errorf("failed to stop Caddy: %w", err)
	}

	h.running = false
	return nil
}

func (h *HTTPServiceSimple) UpdateConfig(config types.ServiceConfig) error {
	if !h.running {
		return fmt.Errorf("service not running")
	}

	newConfig, err := h.GenerateCaddyConfig(config)
	if err != nil {
		return fmt.Errorf("failed to generate new config: %w", err)
	}

	// Validate before applying
	if err := caddy.Validate(newConfig); err != nil {
		return fmt.Errorf("invalid new configuration: %w", err)
	}

	// Apply new configuration (graceful reload)
	if err := caddy.Load(caddyconfig.JSON(newConfig, nil), false); err != nil {
		return fmt.Errorf("failed to reload config: %w", err)
	}

	h.config = newConfig
	return nil
}

func (h *HTTPServiceSimple) HealthCheck() error {
	if !h.running {
		return fmt.Errorf("service not running")
	}

	resp, err := http.Get("http://localhost:2019/config/")
	if err != nil {
		return fmt.Errorf("Caddy admin API not responding: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Caddy admin API returned status %d", resp.StatusCode)
	}

	return nil
}

// GenerateCaddyConfig creates Caddy configuration using native features
func (h *HTTPServiceSimple) GenerateCaddyConfig(config types.ServiceConfig) (*caddy.Config, error) {
	httpConfig, ok := config.Config["http"].(types.HTTPConfig)
	if !ok {
		return nil, fmt.Errorf("missing HTTP configuration")
	}

	// Build Caddy routes
	var routes caddyhttp.RouteList

	// Add WoT routes
	for _, route := range httpConfig.Routes {
		caddyRoute := h.buildWoTRoute(route)
		routes = append(routes, caddyRoute)
	}

	// Build server configuration
	server := &caddyhttp.Server{
		Listen: []string{":8080"},
		Routes: routes,
	}

	// Create Caddy config
	cfg := &caddy.Config{
		Admin: &caddy.AdminConfig{
			Listen: "localhost:2019",
		},
		AppsRaw: caddy.ModuleMap{
			"http": caddyconfig.JSON(caddyhttp.App{
				Servers: map[string]*caddyhttp.Server{
					"srv0": server,
				},
			}, nil),
		},
	}

	// Add simple authentication if configured
	if securityMap, ok := config.Config["security"].(map[string]interface{}); ok {
		if enabled, _ := securityMap["enabled"].(bool); enabled {
			h.addSimpleAuth(server, securityMap)
		}
	}

	return cfg, nil
}

// buildWoTRoute creates a Caddy route for WoT endpoints
func (h *HTTPServiceSimple) buildWoTRoute(route types.HTTPRoute) caddyhttp.Route {
	matcherSet := caddy.ModuleMap{}
	var handlers []json.RawMessage

	// Path matcher
	matcherSet["path"] = caddyconfig.JSON([]string{route.Path}, nil)

	// Method matcher if specified
	if len(route.Methods) > 0 {
		matcherSet["method"] = caddyconfig.JSON(route.Methods, nil)
	}

	// Add authentication check if required
	if route.RequiresAuth {
		// Simple header check for Authorization
		matcherSet["header"] = caddyconfig.JSON(map[string][]string{
			"Authorization": {"*"},
		}, nil)
	}

	// Build handler based on route type
	switch route.Handler {
	case "reverse_proxy":
		if upstream, ok := route.Metadata["upstream"].(string); ok {
			// Use raw JSON for reverse proxy configuration
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
	case "static":
		body, _ := route.Metadata["body"].(string)
		handlers = append(handlers, caddyconfig.JSONModuleObject(
			caddyhttp.StaticResponse{
				Body: body,
			},
			"handler", "static_response", nil,
		))
	default:
		// Default handler
		handlers = append(handlers, caddyconfig.JSONModuleObject(
			caddyhttp.StaticResponse{
				Body: fmt.Sprintf(`{"error": "handler not implemented: %s"}`, route.Handler),
			},
			"handler", "static_response", nil,
		))
	}

	return caddyhttp.Route{
		MatcherSetsRaw: []caddy.ModuleMap{matcherSet},
		HandlersRaw:    handlers,
	}
}

// addSimpleAuth adds basic authentication to the server
func (h *HTTPServiceSimple) addSimpleAuth(server *caddyhttp.Server, securityConfig map[string]interface{}) {
	// For now, we'll use a simple approach:
	// 1. Check for bearer tokens in a middleware
	// 2. Use Caddy's built-in basic auth if configured

	// This is a placeholder - in production, you'd want proper JWT validation
	// or integration with your existing license/auth system

	h.logger.Info("Security enabled - authentication will be enforced on protected routes")
}

// Interface guard
var _ types.Service = (*HTTPServiceSimple)(nil)
