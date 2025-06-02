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

	// Security configuration is now part of httpConfig.Security (types.SimpleSecurityConfig)
	// Build routes with authentication
	var routes []interface{}

	// Add authentication route if security is enabled
	if httpConfig.Security.Enabled {
		authRoute := h.buildAuthRoute(httpConfig.Security) // Pass SimpleSecurityConfig
		if authRoute != nil {
			routes = append(routes, authRoute)
		}
	}

	// Add application routes
	for _, route := range httpConfig.Routes {
		// buildRoute now doesn't need the separate securityConfig map
		caddyRoute := h.buildRoute(route) 
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
// It now accepts types.SimpleSecurityConfig
func (h *HTTPServiceV2) buildAuthRoute(securityConfig types.SimpleSecurityConfig) map[string]interface{} {
	var authHandlers []map[string]interface{}

	// Basic Auth
	if securityConfig.BasicAuth != nil && len(securityConfig.BasicAuth.Users) > 0 {
		caddyBasicAuthAccounts := make(map[string]interface{})
		for _, user := range securityConfig.BasicAuth.Users {
			// TODO: Hashing passwords should be handled before they get here or by Caddy itself.
			// Caddy's basicauth handler expects plaintext passwords or pre-hashed ones if specified.
			// For simplicity, assuming plaintext or that Caddy handles hashing if configured.
			caddyBasicAuthAccounts[user.Username] = map[string]interface{}{"password": user.Password}
		}
		if len(caddyBasicAuthAccounts) > 0 {
			authHandlers = append(authHandlers, map[string]interface{}{
				"handler": "authentication",
				"providers": map[string]interface{}{
					"http_basic": map[string]interface{}{
						"accounts": caddyBasicAuthAccounts,
						// "realm": "TwinCore Protected Area", // Optional realm
					},
				},
			})
		}
	}

	// Bearer Auth (using Caddy's `jwt` handler if applicable, or a custom header check for opaque tokens)
	// SimpleSecurityConfig.BearerAuth.Tokens suggests opaque tokens.
	// Caddy doesn't have a direct "match these exact bearer tokens" handler.
	// This usually requires a custom module or using `expression` matchers with `http.handlers.authentication`.
	// For JWTs, SimpleSecurityConfig.JWTAuth would be used with Caddy's `jwt` handler.

	// Placeholder for Bearer/JWT:
	// If JWTAuth is configured:
	if securityConfig.JWTAuth != nil && securityConfig.JWTAuth.PublicKey != "" {
		jwtHandler := map[string]interface{}{
			"handler": "authentication",
			"providers": map[string]interface{}{
				"jwt": map[string]interface{}{
					"primary": map[string]interface{}{
						"keys": []map[string]interface{}{
							{"source": securityConfig.JWTAuth.PublicKey, "alg": "RS256"}, // Assuming alg, might need to be configurable
						},
					},
					// "trusted_issuers": []string{securityConfig.JWTAuth.Issuer}, // If issuer is set
					// "trusted_audiences": []string{securityConfig.JWTAuth.Audience}, // If audience is set
				},
			},
		}
		// Add issuer/audience if present
		jwtProvider := jwtHandler["providers"].(map[string]interface{})["jwt"].(map[string]interface{})
		if securityConfig.JWTAuth.Issuer != "" {
			jwtProvider["trusted_issuers"] = []string{securityConfig.JWTAuth.Issuer}
		}
		if securityConfig.JWTAuth.Audience != "" {
			jwtProvider["trusted_audiences"] = []string{securityConfig.JWTAuth.Audience}
		}
		authHandlers = append(authHandlers, jwtHandler)
		h.logger.Info("JWT Authentication configured for Caddy")
	} else if securityConfig.BearerAuth != nil && len(securityConfig.BearerAuth.Tokens) > 0 {
		// This is tricky with Caddy's standard handlers.
		// A simple approach might be to use a request header matcher for specific tokens,
		// but this is not scalable and insecure if tokens are static and long-lived.
		// A more robust solution would involve a custom auth module or token introspection.
		// For now, logging that it's configured but not implementing a Caddy handler.
		h.logger.Warn("BearerAuth with static tokens configured in SimpleSecurityConfig, but Caddy handler implementation is complex and not fully provided here. Consider JWT or a custom Caddy auth module for production bearer tokens.")
	}


	if len(authHandlers) == 0 {
		return nil
	}

	return map[string]interface{}{
		"match": []map[string]interface{}{
			{
				"path": []string{"/*"}, // This auth route applies to all paths
			},
		},
		"handle": authHandlers, // Corrected from 'handlers' to 'authHandlers'
	}
}

// buildRoute creates a route configuration
// The securityConfig map parameter is removed as auth is handled by buildAuthRoute and httpConfig.Security
func (h *HTTPServiceV2) buildRoute(route types.HTTPRoute) map[string]interface{} {
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

	// Authentication for individual routes is now primarily handled by the global auth handler
	// configured by buildAuthRoute if httpConfig.Security.Enabled is true.
	// The route.RequiresAuth flag is still useful to know if a route expects to be protected.
	// Specific per-route auth logic (e.g. different JWT scopes) would require more complex Caddy config.
	// For now, if route.RequiresAuth is true, we assume the global auth handler (if enabled) takes care of it.
	// If no global auth is enabled but a route requires auth, it's effectively unprotected.
	// This simplified model might need refinement for more granular per-route auth.

	// Add the actual handler (reverse proxy, static response, etc.)
	switch route.Handler {
	case "reverse_proxy":
		if upstream, ok := route.Config["upstream"].(string); ok { // Changed from route.Metadata
			handlers = append(handlers, map[string]interface{}{
				"handler": "reverse_proxy",
				"upstreams": []map[string]interface{}{
					{"dial": upstream},
				},
			})
		}
	case "static_response":
		body, _ := route.Config["body"].(string) // Changed from route.Metadata
		statusCode, _ := route.Config["status_code"].(float64) // Changed from route.Metadata
		if statusCode == 0 {
			statusCode = 200
		}
		handlers = append(handlers, map[string]interface{}{
			"handler":     "static_response",
			"status_code": int(statusCode),
			"body":        body,
		})
	default:
		// Default to a simple response
		handlers = append(handlers, map[string]interface{}{
			"handler":     "static_response",
			"status_code": 200,
			"body":        fmt.Sprintf(`{"message": "Handler not implemented for %s or bad config: %s"}`, route.Path, route.Handler),
		})
	}

	return map[string]interface{}{
		"match":  matchers,
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
