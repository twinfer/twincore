// internal/service/http_service.go
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy-security/dist/caddysecurity"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/twinfer/twincore/pkg/types"
)

type HTTPService struct {
	instance *caddy.Caddy
	config   *caddy.Config
	running  bool
}

func NewHTTPService() types.Service {
	return &HTTPService{}
}

func (h *HTTPService) Name() string {
	return "http"
}

func (h *HTTPService) RequiredLicense() []string {
	return []string{"core", "http"}
}

func (h *HTTPService) Dependencies() []string {
	return []string{}
}

func (h *HTTPService) Start(ctx context.Context, config types.ServiceConfig) error {
	if h.running {
		return fmt.Errorf("HTTP service already running")
	}

	// Generate Caddy configuration
	caddyConfig, err := h.generateCaddyConfig(config)
	if err != nil {
		return fmt.Errorf("failed to generate Caddy config: %w", err)
	}

	// Validate using Caddy's built-in Validate function
	if err := caddy.Validate(caddyConfig); err != nil {
		return fmt.Errorf("invalid Caddy configuration: %w", err)
	}

	// Create and start Caddy instance
	h.instance = caddy.New()
	if err := h.instance.Load(caddyConfig, false); err != nil {
		return fmt.Errorf("failed to load Caddy config: %w", err)
	}

	h.config = caddyConfig
	h.running = true
	return nil
}

func (h *HTTPService) Stop(ctx context.Context) error {
	if !h.running {
		return nil
	}

	if h.instance != nil {
		if err := h.instance.Stop(); err != nil {
			return fmt.Errorf("failed to stop Caddy: %w", err)
		}
	}

	h.running = false
	return nil
}

func (h *HTTPService) UpdateConfig(config types.ServiceConfig) error {
	if !h.running {
		return fmt.Errorf("service not running")
	}

	newConfig, err := h.generateCaddyConfig(config)
	if err != nil {
		return fmt.Errorf("failed to generate new config: %w", err)
	}

	// Validate before applying
	if err := caddy.Validate(newConfig); err != nil {
		return fmt.Errorf("invalid new configuration: %w", err)
	}

	// Apply new configuration (graceful reload)
	if err := h.instance.Load(newConfig, false); err != nil {
		return fmt.Errorf("failed to reload config: %w", err)
	}

	h.config = newConfig
	return nil
}

func (h *HTTPService) HealthCheck() error {
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

// generateCaddyConfig creates Caddy configuration with security module
func (h *HTTPService) generateCaddyConfig(config types.ServiceConfig) (*caddy.Config, error) {
	httpConfig, ok := config.Config["http"].(types.HTTPConfig)
	if !ok {
		return nil, fmt.Errorf("missing HTTP configuration")
	}

	// Extract security configuration
	securityConfig, _ := config.Config["security"].(types.SecurityConfig)

	// Build Caddy routes
	var routes caddyhttp.RouteList

	// Add security middleware if configured
	if securityConfig.Enabled {
		securityRoute := h.buildSecurityRoute(securityConfig)
		routes = append(routes, securityRoute)
	}

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
			}),
			"security": h.buildSecurityApp(securityConfig),
		},
	}

	return cfg, nil
}

// buildSecurityRoute creates caddy-security middleware route
func (h *HTTPService) buildSecurityRoute(config types.SecurityConfig) caddyhttp.Route {
	return caddyhttp.Route{
		HandlersRaw: []json.RawMessage{
			caddyconfig.JSONModuleObject(
				caddysecurity.Authenticator{
					Providers: h.buildAuthProviders(config),
				},
				"handler", "authentication", nil,
			),
		},
	}
}

// buildAuthProviders creates authentication providers
func (h *HTTPService) buildAuthProviders(config types.SecurityConfig) []caddysecurity.AuthProvider {
	var providers []caddysecurity.AuthProvider

	// Local authentication
	if config.LocalAuth.Enabled {
		providers = append(providers, caddysecurity.AuthProvider{
			Name: "local",
			Credentials: caddysecurity.Credentials{
				Username: config.LocalAuth.Username,
				Password: config.LocalAuth.Password,
			},
		})
	}

	// JWT authentication
	if config.JWT.Enabled {
		providers = append(providers, caddysecurity.AuthProvider{
			Name: "jwt",
			TokenAuth: &caddysecurity.TokenAuth{
				TokenSources: []string{"header", "cookie"},
				TokenName:    "Authorization",
				Algorithm:    config.JWT.Algorithm,
				Secret:       config.JWT.Secret,
			},
		})
	}

	// SAML authentication
	if config.SAML.Enabled {
		providers = append(providers, caddysecurity.AuthProvider{
			Name: "saml",
			SAML: &caddysecurity.SAMLConfig{
				MetadataURL: config.SAML.MetadataURL,
				EntityID:    config.SAML.EntityID,
			},
		})
	}

	return providers
}

// buildSecurityApp creates the security app configuration
func (h *HTTPService) buildSecurityApp(config types.SecurityConfig) json.RawMessage {
	securityApp := caddysecurity.App{
		AuthPortal: &caddysecurity.AuthPortal{
			Name: "TwinEdge Gateway",
			UI: &caddysecurity.UserInterface{
				Title:       "TwinEdge Gateway",
				Description: "Secure access to your IoT devices",
				LogoURL:     "/assets/logo.png",
				LogoText:    "TwinEdge",
				PrivateLinks: []caddysecurity.PrivateLink{
					{
						Title:   "Portal",
						URL:     "/portal",
						IconURL: "/assets/portal-icon.png",
					},
				},
			},
		},
		Authorization: &caddysecurity.Authorization{
			Policies: h.buildPolicies(config),
		},
	}

	return caddyconfig.JSON(securityApp)
}

// buildPolicies creates authorization policies
func (h *HTTPService) buildPolicies(config types.SecurityConfig) []caddysecurity.Policy {
	var policies []caddysecurity.Policy

	// Default policy
	policies = append(policies, caddysecurity.Policy{
		Name: "default",
		Subjects: []caddysecurity.Subject{
			{User: "admin"},
		},
		Resources: []caddysecurity.Resource{
			{Path: "/*"},
		},
		Actions: []string{"GET", "POST", "PUT", "DELETE"},
	})

	// Add custom policies from config
	for _, policy := range config.Policies {
		p := caddysecurity.Policy{
			Name:      policy.Name,
			Subjects:  []caddysecurity.Subject{},
			Resources: []caddysecurity.Resource{},
			Actions:   policy.Actions,
		}

		for _, subject := range policy.Subjects {
			p.Subjects = append(p.Subjects, caddysecurity.Subject{
				User: subject,
			})
		}

		for _, resource := range policy.Resources {
			p.Resources = append(p.Resources, caddysecurity.Resource{
				Path: resource,
			})
		}

		policies = append(policies, p)
	}

	return policies
}

// buildWoTRoute creates a route for WoT interactions
func (h *HTTPService) buildWoTRoute(route types.HTTPRoute) caddyhttp.Route {
	handlers := []json.RawMessage{}

	// Add authentication if required
	if route.RequiresAuth {
		handlers = append(handlers, caddyconfig.JSONModuleObject(
			caddysecurity.Authorizer{
				Providers: []string{"jwt", "local"},
			},
			"handler", "authorization", nil,
		))
	}

	// Add WoT handler
	handlers = append(handlers, caddyconfig.JSONModuleObject(
		WoTHandler{
			Handler:  route.Handler,
			Metadata: route.Metadata,
		},
		"handler", "wot_handler", nil,
	))

	return caddyhttp.Route{
		MatcherSetsRaw: caddyhttp.RawMatcherSets{
			caddy.ModuleMap{
				"path":   caddyconfig.JSON([]string{route.Path}),
				"method": caddyconfig.JSON(route.Methods),
			},
		},
		HandlersRaw: handlers,
	}
}

// WoTHandler is a custom Caddy handler for WoT interactions
type WoTHandler struct {
	Handler  string                 `json:"handler"`
	Metadata map[string]interface{} `json:"metadata"`
}

func (WoTHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.wot_handler",
		New: func() caddy.Module { return new(WoTHandler) },
	}
}

func (h WoTHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Handle WoT interactions based on handler type
	switch h.Handler {
	case "wot_property_handler":
		return h.handleProperty(w, r)
	case "wot_action_handler":
		return h.handleAction(w, r)
	case "wot_event_handler":
		return h.handleEvent(w, r)
	default:
		return next.ServeHTTP(w, r)
	}
}

func (h WoTHandler) handleProperty(w http.ResponseWriter, r *http.Request) error {
	// Implementation for property interactions
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Property handler"))
	return nil
}

func (h WoTHandler) handleAction(w http.ResponseWriter, r *http.Request) error {
	// Implementation for action invocations
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Action handler"))
	return nil
}

func (h WoTHandler) handleEvent(w http.ResponseWriter, r *http.Request) error {
	// Implementation for event subscriptions (SSE)
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Event handler"))
	return nil
}
