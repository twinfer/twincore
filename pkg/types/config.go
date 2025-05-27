// pkg/types/config.go
package types

import (
	authn "github.com/greenpau/go-authcrunch/pkg/authn"
	authz "github.com/greenpau/go-authcrunch/pkg/authz"
	// portalui "github.com/greenpau/go-authcrunch/pkg/authn/ui" // For UI elements
	// idstore "github.com/greenpau/go-authcrunch/pkg/identity" // For identity stores
	// validator "github.com/greenpau/go-authcrunch/pkg/authn/validators" // For token validators
	// backend "github.com/greenpau/go-authcrunch/pkg/authn/backends" // For specific backends
)

// HTTPRoute represents a HTTP route configuration
type HTTPRoute struct {
	Path         string                 `json:"path"`
	Methods      []string               `json:"methods"`
	Handler      string                 `json:"handler"`
	RequiresAuth bool                   `json:"requires_auth"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// StreamTopic represents a streaming topic configuration
type StreamTopic struct {
	Name   string                 `json:"name"`
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config"`
}

// CommandStream represents a command stream configuration
type CommandStream struct {
	Name   string                 `json:"name"`
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config"`
}

// SecurityConfig directly mirrors the structure needed by go-authcrunch
// to simplify setup in http-service.go.
// This configuration would be part of the gateway's overall static configuration.
type SecurityConfig struct {
	Enabled bool `json:"enabled"`

	// Configuration for Authentication Portals
	// Typically, one portal is defined.
	AuthenticationPortals []*authn.PortalConfig `json:"authenticationPortals,omitempty"`

	// Configuration for Identity Stores (e.g., local user database, LDAP)
	// Note: authn.PortalConfig.IdentityStores and authn.PortalConfig.IdentityProviders are the typical way to link these.
	// Exposing these at top level might be redundant if PortalConfig is fully specified.
	// For now, including as per prompt, assuming they might be used to populate the main authcrunch.Config.
	IdentityStores []*authn.IdentityStoreConfig `json:"identityStores,omitempty"`

	// Configuration for Token Validators (e.g., JWT validators)
	// Similar to IdentityStores, these are often part of PortalConfig.
	TokenValidators []*authn.TokenValidatorConfig `json:"tokenValidators,omitempty"`
	
	// Configuration for Authorization (Gatekeepers and Policies)
	// Typically, one gatekeeper containing multiple policies is defined.
	AuthorizationGatekeepers []*authz.GatekeeperConfig `json:"authorizationGatekeepers,omitempty"`

	// Other global settings from authcrunch.Config if necessary
	// LogLevel string `json:"logLevel,omitempty"`
	// LogFilePath string `json:"logFilePath,omitempty"`
}

// Note: The previous structs LocalAuthConfig, JWTConfig, SAMLConfig, OIDCConfig, PolicyConfig
// have been REMOVED as their functionality is now covered by configuring
// authn.PortalConfig, authn.IdentityStoreConfig, authn.TokenValidatorConfig, and authz.GatekeeperConfig directly.
// The user of TwinEdge will need to provide configuration matching these go-authcrunch structures.


// HTTPConfig with Security field
type HTTPConfig struct {
	Routes   []HTTPRoute            `json:"routes"`
	Security map[string]interface{} `json:"security,omitempty"` // This might become redundant or change if HTTPConfig itself is part of SecurityConfig
}
