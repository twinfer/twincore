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
	security "github.com/greenpau/caddy-security"
	"github.com/twinfer/twincore/pkg/types"

	"database/sql" // Added for db field
	"strings"      // Added for strings.Split

	authcrunch "github.com/greenpau/go-authcrunch" // Main config
	"github.com/greenpau/go-authcrunch/pkg/authn"  // For authn.UserConfig
	"github.com/sirupsen/logrus"                   // Added for logger field
	// For specific IDP/Store configs, we might need:
	// localauth "github.com/greenpau/go-authcrunch/pkg/authn/backends/local" // if specific types are needed beyond general config
	// jwtvalidator "github.com/greenpau/go-authcrunch/pkg/authn/validators/jwt"
	// samlidp "github.com/greenpau/go-authcrunch/pkg/idp/saml"
)

type HTTPService struct {
	config  *caddy.Config
	running bool
	db      *sql.DB        // Added DB field
	logger  *logrus.Logger // Added logger field
	// configManager *config.ConfigManager // Assuming this was meant to be a field if passed in New
}

// NewHTTPService now accepts db *sql.DB and logger *logrus.Logger
// Assuming configManager is not directly used by HTTPService methods being modified,
// but if it was, it should be passed and stored too.
func NewHTTPService(logger *logrus.Logger, db *sql.DB) types.Service {
	return &HTTPService{
		logger: logger,
		db:     db,
	}
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

func (h *HTTPService) Stop(ctx context.Context) error {
	if !h.running {
		return nil
	}

	if err := caddy.Stop(); err != nil {
		return fmt.Errorf("failed to stop Caddy: %w", err)
	}

	h.running = false
	return nil
}

func (h *HTTPService) UpdateConfig(config types.ServiceConfig) error {
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

// GenerateCaddyConfig creates Caddy configuration with security module
func (h *HTTPService) GenerateCaddyConfig(config types.ServiceConfig) (*caddy.Config, error) {
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
			"http": caddyconfig.JSON(caddyhttp.App{ // Added nil for the warnings argument
				Servers: map[string]*caddyhttp.Server{
					"srv0": server,
				},
			}, nil),
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

	crunchConfig := authcrunch.NewConfig() // Create a new authcrunch.Config

	// Directly assign configurations from types.SecurityConfig to authcrunch.Config
	// The types.SecurityConfig is now designed to hold slices of *authn.PortalConfig, etc.
	if cfg.AuthenticationPortals != nil {
		crunchConfig.AuthenticationPortals = cfg.AuthenticationPortals
	}

	// Token Validators are configured at the top level of authcrunch.Config
	if cfg.TokenValidators != nil {
		crunchConfig.TokenValidators = cfg.TokenValidators // Correct field name
	}
	crunchConfig.Authorizers = cfg.AuthorizationGatekeepers // Correct field name

	// Populate IdentityStores, especially local ones from DB
	if crunchConfig.IdentityStores == nil && len(cfg.IdentityStores) > 0 {
		crunchConfig.IdentityStores = cfg.IdentityStores
	}

	for _, storeConfig := range crunchConfig.IdentityStores {
		// Identify if this storeConfig is meant to be a DB-backed local store.
		// Convention: Kind == "localdb" or a specific Name.
		// For this implementation, we'll assume Kind == "localdb" indicates DB-backed.
		// Note: go-authcrunch's built-in "local" kind typically uses UserConfigs field directly.
		// We are effectively creating a custom "localdb" store behavior here.
		if storeConfig.Kind == "localdb" { // Using "localdb" to distinguish from in-memory "local"
			h.logger.Debugf("Configuring DB-backed local identity store: %s", storeConfig.Name)
			var loadedUserConfigs []*authn.UserConfig // Changed to authn.UserConfig
			rows, err := h.db.Query("SELECT username, password_hash, roles, email, name, disabled FROM local_users WHERE disabled = FALSE")
			if err != nil {
				h.logger.Errorf("Failed to query local_users table for store %s: %v", storeConfig.Name, err)
				continue
			}
			defer rows.Close()

			for rows.Next() {
				var username, passwordHash, rolesStr, email, name sql.NullString
				var disabled sql.NullBool
				if err := rows.Scan(&username, &passwordHash, &rolesStr, &email, &name, &disabled); err != nil {
					h.logger.Errorf("Failed to scan row from local_users for store %s: %v", storeConfig.Name, err)
					continue
				}

				userCfg := &authn.UserConfig{ // Changed to authn.UserConfig
					Username: username.String,
					Password: passwordHash.String, // go-authcrunch expects the hash directly for local kind
					Name:     name.String,
					Email:    email.String,
					// Disabled status is handled by the SQL query `WHERE disabled = FALSE`
				}
				if rolesStr.Valid && rolesStr.String != "" {
					userCfg.Roles = strings.Split(rolesStr.String, ",")
					for i, r := range userCfg.Roles {
						userCfg.Roles[i] = strings.TrimSpace(r)
					}
				} else {
					userCfg.Roles = []string{}
				}
				loadedUserConfigs = append(loadedUserConfigs, userCfg)
			}
			if err := rows.Err(); err != nil {
				h.logger.Errorf("Error iterating local_users rows for store %s: %v", storeConfig.Name, err)
			}

			// Assign the loaded users to the storeConfig.
			// For go-authcrunch, a local identity store is typically configured with UserConfigs.
			// We are populating this by setting the "users" key in the Params map.
			if storeConfig.Params == nil {
				storeConfig.Params = make(map[string]interface{})
			}
			storeConfig.Params["users"] = loadedUserConfigs
			// Ensure Kind is "local" as go-authcrunch understands this for user configurations in Params.
			storeConfig.Kind = "local"
			h.logger.Infof("Loaded %d users from database for local identity store: %s", len(loadedUserConfigs), storeConfig.Name)
		}
	}

	// Example: If types.SecurityConfig had LogLevel and LogFilePath (which it currently doesn't)
	// if cfg.LogLevel != "" {
	// 	crunchConfig.LogLevel = cfg.LogLevel
	// }
	// if cfg.LogFilePath != "" {
	// 	crunchConfig.LogFilePath = cfg.LogFilePath
	// }

	// Validate the constructed authcrunch.Config
	// This step is crucial and part of go-authcrunch's typical usage.
	if err := crunchConfig.Validate(); err != nil {
		// Log this error appropriately in a real scenario.
		// For now, we'll proceed, but this indicates a misconfiguration.
		// In a production system, you might want to return an error or panic
		// if the static security configuration is invalid.
		// This service's logger (h.Logger) isn't available in this static function context.
		// A global logger or passing logger instance might be needed for production logging here.
		h.logger.Warnf("authcrunch.Config validation failed: %v. This may lead to runtime issues with Caddy security features.", err)
	}

	app := security.App{ // This is github.com/greenpau/caddy-security.App
		Config: crunchConfig,
	}

	return caddyconfig.JSON(app, nil) // No warnings expected, but passing nil for compatibility
}

// buildAuthzPolicies, buildAuthProviders / buildAuthBackends are removed as their logic
// is now encapsulated within the structure of types.SecurityConfig, which directly
// provides []*authn.PortalConfig, []*authz.GatekeeperConfig, etc.

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
	// We now use the "core_wot_handler" which is api.WoTHandler, registered globally.
	handlers = append(handlers, caddyconfig.JSON(map[string]interface{}{"handler": "core_wot_handler"}, nil)) // Added nil for the warnings argument
	// Metadata is no longer passed here; api.WoTHandler gets info from path params.

	return caddyhttp.Route{
		MatcherSetsRaw: caddyhttp.RawMatcherSets{
			caddy.ModuleMap{
				"path":   caddyconfig.JSON([]string{route.Path}, nil),                                                       // Added nil for the warnings argument
				"header": caddyconfig.JSON(map[string][]string{"Accept": {"application/ld+json", "application/json"}}, nil), // Added nil for the warnings argument
				// "query":  caddyconfig.JSON(map[string][]string{"wot": {"true"}}, nil), // Optional query matcher, if needed
				"method": caddyconfig.JSON(route.Methods, nil),
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
