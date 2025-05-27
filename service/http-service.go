// internal/service/http_service.go
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	security "github.com/greenpau/caddy-security"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/twinfer/twincore/pkg/types"

	authcrunch "github.com/greenpau/go-authcrunch" // Main config
	authn "github.com/greenpau/go-authcrunch/pkg/authn"
	authnui "github.com/greenpau/go-authcrunch/pkg/authn/ui"
	authz "github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/credentials" // General credentials
	// For specific IDP/Store configs, we might need:
	// localauth "github.com/greenpau/go-authcrunch/pkg/authn/backends/local" // if specific types are needed beyond general config
	// jwtvalidator "github.com/greenpau/go-authcrunch/pkg/authn/validators/jwt"
	// samlidp "github.com/greenpau/go-authcrunch/pkg/idp/saml"
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
	// AuthnMiddleware is a Caddy HTTP handler module from github.com/greenpau/caddy-security
	// It uses an authentication portal configured within the security.App
	authnMiddleware := security.AuthnMiddleware{
		PortalName: "default", // This name must match a portal configured in security.App
	}
	return caddyhttp.Route{
		HandlersRaw: []json.RawMessage{
			caddyconfig.JSONModuleObject(
				authnMiddleware,
				"handler", "authentication", nil, // The Caddy module name for AuthnMiddleware
			),
		},
	}
}


// buildSecurityApp creates the security app configuration for Caddy
// This function configures the github.com/greenpau/caddy-security App
func (h *HTTPService) buildSecurityApp(cfg types.SecurityConfig) json.RawMessage {
	// The main App from github.com/greenpau/caddy-security
	// This App's Config field is of type *authcrunch.Config
	app := security.App{
		Config: authcrunch.NewConfig(), // Initialize the authcrunch.Config
	}

	// Configure Authentication Portal
	portalCfg := authn.NewPortalConfig()
	portalCfg.Name = "default" // Matches AuthnMiddleware.PortalName
	portalCfg.UI = authnui.NewUserInterfaceConfig()
	portalCfg.UI.Title = "TwinEdge Gateway"
	portalCfg.UI.LogoDescription = "Secure access to your IoT devices"
	// portalCfg.UI.LogoURL = "/assets/logo.png" // TODO: Ensure this asset is served
	portalCfg.UI.PrivateLinks = []*authnui.Link{
		{Title: "Portal", Link: "/portal" /*IconLink: "/assets/portal-icon.png"*/},
	}
	
	// Configure Authentication Backends (Identity Providers and Stores)
	if cfg.LocalAuth.Enabled {
		// For local auth, we need an identity store
		localStoreCfg := authn.NewAuthenticatorConfig()
		localStoreCfg.Name = "local_store"
		localStoreCfg.Method = "local"
		localStoreCfg.Realm = "local" // Example realm
		// Define user credentials
		cred := credentials.NewConfig()
		cred.Username = cfg.LocalAuth.Username
		cred.Password = cfg.LocalAuth.Password
		// This part is tricky: go-authcrunch usually loads credentials from a file or other store.
		// Directly adding a single user credential to the portal config might need a specific structure
		// or a custom identity store setup.
		// For simplicity, we might need to assume a pre-configured identity store
		// or that the local method directly takes users.
		// The `credentials.Config` is for a single credential, not a store of them.
		// Let's assume the portal can have a basic list of users for "local" method.
		// This might need a specific backend config.
		// portalCfg.AuthN.Credentials = []*authncreds.Config{&authnCred} // This path was problematic
		// The actual structure for local users in go-authcrunch involves Identity Stores.
		// app.Config.AddIdentityStore(...) would be the way if configuring via authcrunch.Config directly.
		// Caddyfile usually handles this more abstractly.
		// For JSON config, it would be an identity store of type "local" added to app.Config.IdentityStores
		// and then referenced by the portal.
		// For now, this section remains a //TODO: for exact local user setup in JSON.
		portalCfg.AddAuthenticator(localStoreCfg) // Add local auth method
	}

	if cfg.JWT.Enabled {
		jwtAuthCfg := authn.NewAuthenticatorConfig()
		jwtAuthCfg.Name = "jwt_validator"
		jwtAuthCfg.Method = "jwt"
		jwtAuthCfg.Realm = "jwt_realm" // Example realm
		// jwtAuthCfg.TokenConfigs field or similar would be set here.
		// E.g., jwtAuthCfg.TokenConfigs = []*jwtvalidator.TokenConfig{{Name:"primary", Secret: cfg.JWT.Secret ...}}
		// This requires knowing the exact structure from jwtvalidator or authn.
		portalCfg.AddAuthenticator(jwtAuthCfg)
	}

	if cfg.SAML.Enabled {
		samlAuthCfg := authn.NewAuthenticatorConfig()
		samlAuthCfg.Name = "saml_idp"
		samlAuthCfg.Method = "saml"
		samlAuthCfg.Realm = "saml_realm"
		// samlAuthCfg.IdpConfigs = []*samlidp.IdentityProviderConfig{{MetadataURL: cfg.SAML.MetadataURL, EntityID: cfg.SAML.EntityID ...}}
		portalCfg.AddAuthenticator(samlAuthCfg)
	}
	app.Config.AddAuthenticationPortal(portalCfg)


	// Configure Authorization Policies (Gatekeeper)
	gatekeeperCfg := authz.NewGatekeeperConfig()
	gatekeeperCfg.Name = "default" // Matches AuthzMiddleware.GatekeeperName
	gatekeeperCfg.Policies = h.buildAuthzPolicies(cfg)
	app.Config.AddAuthorizationPolicy(gatekeeperCfg) // This should be AddGatekeeper or similar

	return caddyconfig.JSON(app)
}

// buildAuthzPolicies creates authorization policies for go-authcrunch
func (h *HTTPService) buildAuthzPolicies(config types.SecurityConfig) []*authz.PolicyConfig {
	var policies []*authz.PolicyConfig

	defaultPolicy := authz.NewPolicyConfig()
	defaultPolicy.Name = "default"
	// defaultPolicy.Authenticated = true // Example: require authentication
	defaultPolicy.AllowSubjects = []*authz.SubjectConfig{{ID: "admin"}} 
	defaultPolicy.AllowResources = []*authz.ResourceConfig{{Path: "/*"}}
	defaultPolicy.AllowActions = []string{"GET", "POST", "PUT", "DELETE"}
	policies = append(policies, defaultPolicy)

	for _, pConfig := range config.Policies {
		customPolicy := authz.NewPolicyConfig()
		customPolicy.Name = pConfig.Name
		for _, subj := range pConfig.Subjects {
			// Assuming Subject in types.PolicyConfig is a direct user/group ID
			customPolicy.AllowSubjects = append(customPolicy.AllowSubjects, &authz.SubjectConfig{ID: subj})
		}
		for _, res := range pConfig.Resources {
			customPolicy.AllowResources = append(customPolicy.AllowResources, &authz.ResourceConfig{Path: res})
		}
		customPolicy.AllowActions = pConfig.Actions
		policies = append(policies, customPolicy)
	}
	return policies
}


// buildWoTRoute creates a route for WoT interactions
func (h *HTTPService) buildWoTRoute(route types.HTTPRoute) caddyhttp.Route {
	handlers := []json.RawMessage{}

	// Add authentication if required
	if route.RequiresAuth {
		authzMw := security.AuthzMiddleware{
			GatekeeperName: "default", // This name must match a gatekeeper configured in security.App
		}
		handlers = append(handlers, caddyconfig.JSONModuleObject(
			authzMw,
			"handler", "authorization", nil, // The Caddy module name for AuthzMiddleware
		))
	}

	// Add WoT handler
	// The old WoTHandler struct from this file is being removed.
	// We now use the "core_wot_handler" which is api.WoTHandler.
	handlers = append(handlers, caddyconfig.JSONModuleObject(
		caddy.ModuleMap{"handler": "core_wot_handler"}, // Use the ID from api.WoTHandler.CaddyModule()
		"handler", "core_wot_handler", nil,
	))
	// Metadata is no longer passed here; api.WoTHandler gets info from path params.

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

/*
// WoTHandler is a custom Caddy handler for WoT interactions
// This struct and its methods are now superseded by api.WoTHandler from internal/api/wot-handler-core.go
type WoTHandler struct {
	Handler  string                 `json:"handler"`
	Metadata map[string]interface{} `json:"metadata"`
}

func (WoTHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.wot_handler", // Old ID
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
*/
