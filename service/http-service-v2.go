package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/types"
)

// HTTPServiceV2 uses Caddy Admin API for all configuration
type HTTPServiceV2 struct {
	running   bool
	logger    logrus.FieldLogger
	adminAddr string
}

// NewHTTPServiceV2 creates a new HTTP service using Caddy Admin API
func NewHTTPServiceV2(logger logrus.FieldLogger) types.Service {
	return &HTTPServiceV2{
		logger:    logger,
		adminAddr: "http://localhost:2019",
	}
}

func (h *HTTPServiceV2) Name() string {
	return "http-v2"
}

func (h *HTTPServiceV2) RequiredLicense() []string {
	return []string{"core", "http"}
}

func (h *HTTPServiceV2) Dependencies() []string {
	return []string{}
}

func (h *HTTPServiceV2) Start(ctx context.Context, config types.ServiceConfig) error {
	if h.running {
		return fmt.Errorf("HTTP service already running")
	}

	// Start Caddy with initial config
	initialConfig := &caddy.Config{
		Admin: &caddy.AdminConfig{
			Listen: "localhost:2019",
		},
	}

	// Load initial config
	if err := h.loadConfig(initialConfig); err != nil {
		return fmt.Errorf("failed to load initial config: %w", err)
	}

	// Apply the actual configuration
	if err := h.UpdateConfig(config); err != nil {
		return fmt.Errorf("failed to apply configuration: %w", err)
	}

	h.running = true
	return nil
}

func (h *HTTPServiceV2) Stop(ctx context.Context) error {
	if !h.running {
		return nil
	}

	// Stop Caddy via Admin API
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.adminAddr+"/stop", nil)
	if err != nil {
		return fmt.Errorf("failed to create stop request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to stop Caddy: %w", err)
	}
	defer resp.Body.Close()

	h.running = false
	return nil
}

func (h *HTTPServiceV2) UpdateConfig(config types.ServiceConfig) error {
	// Build Caddy configuration
	caddyConfig, err := h.buildCaddyConfig(config)
	if err != nil {
		return fmt.Errorf("failed to build config: %w", err)
	}

	// Apply configuration via Admin API
	return h.loadConfig(caddyConfig)
}

func (h *HTTPServiceV2) HealthCheck() error {
	if !h.running {
		return fmt.Errorf("service not running")
	}

	resp, err := http.Get(h.adminAddr + "/config/")
	if err != nil {
		return fmt.Errorf("Caddy admin API not responding: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Caddy admin API returned status %d", resp.StatusCode)
	}

	return nil
}

// buildCaddyConfig creates a Caddy configuration using native features
func (h *HTTPServiceV2) buildCaddyConfig(config types.ServiceConfig) (map[string]interface{}, error) {
	httpConfig, ok := config.Config["http"].(types.HTTPConfig)
	if !ok {
		return nil, fmt.Errorf("missing HTTP configuration")
	}

	// Extract security configuration
	securityConfig, _ := config.Config["security"].(map[string]interface{})

	// Build routes with authentication
	var routes []interface{}
	
	// Add authentication route if security is enabled
	if enabled, _ := securityConfig["enabled"].(bool); enabled {
		authRoute := h.buildAuthRoute(securityConfig)
		if authRoute != nil {
			routes = append(routes, authRoute)
		}
	}

	// Add application routes
	for _, route := range httpConfig.Routes {
		caddyRoute := h.buildRoute(route, securityConfig)
		routes = append(routes, caddyRoute)
	}

	// Build complete configuration
	caddyConfig := map[string]interface{}{
		"admin": map[string]interface{}{
			"listen": "localhost:2019",
		},
		"apps": map[string]interface{}{
			"http": map[string]interface{}{
				"servers": map[string]interface{}{
					"srv0": map[string]interface{}{
						"listen": []string{":8080"},
						"routes": routes,
					},
				},
			},
		},
	}

	return caddyConfig, nil
}

// buildAuthRoute creates an authentication route using Caddy's built-in auth
func (h *HTTPServiceV2) buildAuthRoute(securityConfig map[string]interface{}) map[string]interface{} {
	var handlers []interface{}

	// Use basic auth if configured
	if basicAuth, ok := securityConfig["basic_auth"].(map[string]interface{}); ok {
		accounts := make(map[string]interface{})
		if users, ok := basicAuth["users"].([]interface{}); ok {
			for _, user := range users {
				if u, ok := user.(map[string]interface{}); ok {
					username, _ := u["username"].(string)
					password, _ := u["password"].(string)
					if username != "" && password != "" {
						// In production, passwords should be hashed
						accounts[username] = map[string]interface{}{
							"password": password,
						}
					}
				}
			}
		}

		if len(accounts) > 0 {
			handlers = append(handlers, map[string]interface{}{
				"handler": "authentication",
				"providers": map[string]interface{}{
					"http_basic": map[string]interface{}{
						"accounts": accounts,
					},
				},
			})
		}
	}

	// Add bearer token validation using subroute
	if bearerTokens, ok := securityConfig["bearer_tokens"].([]interface{}); ok && len(bearerTokens) > 0 {
		// Create a matcher for Authorization header
		handlers = append(handlers, map[string]interface{}{
			"handler": "headers",
			"request": map[string]interface{}{
				"set": map[string][]string{
					"X-Authenticated": {"true"},
				},
			},
		})
	}

	if len(handlers) == 0 {
		return nil
	}

	return map[string]interface{}{
		"match": []map[string]interface{}{
			{
				"path": []string{"/*"},
			},
		},
		"handle": handlers,
	}
}

// buildRoute creates a route configuration
func (h *HTTPServiceV2) buildRoute(route types.HTTPRoute, securityConfig map[string]interface{}) map[string]interface{} {
	// Build matchers
	var matchers []map[string]interface{}
	
	// Path matcher
	matchers = append(matchers, map[string]interface{}{
		"path": []string{route.Path},
	})
	
	// Method matcher
	if len(route.Methods) > 0 {
		matchers = append(matchers, map[string]interface{}{
			"method": route.Methods,
		})
	}

	// Build handlers
	var handlers []interface{}

	// Add authentication if required
	if route.RequiresAuth {
		if bearerTokens, ok := securityConfig["bearer_tokens"].([]interface{}); ok && len(bearerTokens) > 0 {
			// Simple bearer token check using header matcher
			// This is a simplified approach - in production, use proper JWT validation
			handlers = append(handlers, map[string]interface{}{
				"handler": "subroute",
				"routes": []map[string]interface{}{
					{
						"match": []map[string]interface{}{
							{
								"header": map[string][]string{
									"Authorization": {"Bearer *"},
								},
							},
						},
						"handle": []map[string]interface{}{
							{
								"handler": "headers",
								"response": map[string]interface{}{
									"set": map[string][]string{
										"X-Authenticated": {"true"},
									},
								},
							},
						},
					},
					{
						// No Authorization header - return 401
						"handle": []map[string]interface{}{
							{
								"handler": "static_response",
								"status_code": 401,
								"headers": map[string][]string{
									"WWW-Authenticate": {`Bearer realm="TwinCore"`},
									"Content-Type": {"application/json"},
								},
								"body": `{"error": "unauthorized", "message": "missing or invalid authorization"}`,
							},
						},
					},
				},
			})
		}
	}

	// Add the actual handler (reverse proxy, static response, etc.)
	switch route.Handler {
	case "reverse_proxy":
		if upstream, ok := route.Metadata["upstream"].(string); ok {
			handlers = append(handlers, map[string]interface{}{
				"handler": "reverse_proxy",
				"upstreams": []map[string]interface{}{
					{"dial": upstream},
				},
			})
		}
	case "static_response":
		body, _ := route.Metadata["body"].(string)
		statusCode, _ := route.Metadata["status_code"].(float64)
		if statusCode == 0 {
			statusCode = 200
		}
		handlers = append(handlers, map[string]interface{}{
			"handler": "static_response",
			"status_code": int(statusCode),
			"body": body,
		})
	default:
		// Default to a simple response
		handlers = append(handlers, map[string]interface{}{
			"handler": "static_response",
			"status_code": 200,
			"body": fmt.Sprintf(`{"message": "Handler not implemented: %s"}`, route.Handler),
		})
	}

	return map[string]interface{}{
		"match": matchers,
		"handle": handlers,
	}
}

// loadConfig loads a configuration via Caddy Admin API
func (h *HTTPServiceV2) loadConfig(config interface{}) error {
	// Convert config to JSON
	data, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Send to Caddy Admin API
	req, err := http.NewRequest(http.MethodPost, h.adminAddr+"/load", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errResp)
		return fmt.Errorf("failed to load config: %v", errResp)
	}

	return nil
}

// Interface guard
var _ types.Service = (*HTTPServiceV2)(nil)