// pkg/types/config.go
package types

import (
	"context"
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
// type SecurityConfig struct {
// 	Enabled bool `json:"enabled"`

// 	// Configuration for Authentication Portals
// 	// Typically, one portal is defined.
// 	AuthenticationPortals []*authn.PortalConfig `json:"authenticationPortals,omitempty"`

// 	// Configuration for Identity Stores (e.g., local user database, LDAP)
// 	// Note: authn.PortalConfig.IdentityStores and authn.PortalConfig.IdentityProviders are the typical way to link these.
// 	// Exposing these at top level might be redundant if PortalConfig is fully specified.
// 	// For now, including as per prompt, assuming they might be used to populate the main authcrunch.Config.
// 	IdentityStores []*authn.IdentityStoreConfig `json:"identityStores,omitempty"`

// 	// Configuration for Token Validators (e.g., JWT validators)
// 	// Similar to IdentityStores, these are often part of PortalConfig.
// 	TokenValidators []*authn.TokenValidatorConfig `json:"tokenValidators,omitempty"`

// 	// Configuration for Authorization (Gatekeepers and Policies)
// 	// Typically, one gatekeeper containing multiple policies is defined.
// 	AuthorizationGatekeepers []*authz.Config `json:"authorizationGatekeepers,omitempty"`

// 	// Other global settings from authcrunch.Config if necessary
// 	// LogLevel string `json:"logLevel,omitempty"`
// 	// LogFilePath string `json:"logFilePath,omitempty"`
// }

// HTTPConfig with Security field
type HTTPConfig struct {
	Routes   []HTTPRoute            `json:"routes"`
	Security map[string]interface{} `json:"security,omitempty"` // This might become redundant or change if HTTPConfig itself is part of SecurityConfig
}

// StreamConfig holds configurations for streaming topics and commands.
// This is used for high-level configuration, not to be confused with Benthos StreamBuilder
type StreamConfig struct {
	Topics   []StreamTopic   `json:"topics"`
	Commands []CommandStream `json:"commands"`
}

// UnifiedConfig represents the overall configuration generated from a Thing Description.
type UnifiedConfig struct {
	Version string       `json:"version"`
	HTTP    HTTPConfig   `json:"http"`
	Stream  StreamConfig `json:"stream"`
}

// ServiceConfig holds the generic configuration for a service.
type ServiceConfig struct {
	Name   string                 `json:"name"`
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config"` // Generic config map
}

// Service defines the interface for a manageable service within the application.
type Service interface {
	Name() string
	RequiredLicense() []string
	Dependencies() []string
	Start(ctx context.Context, config ServiceConfig) error
	Stop(ctx context.Context) error
	UpdateConfig(config ServiceConfig) error
	HealthCheck() error
}

// License defines the interface for license information.
// Implementations of this interface will provide details about licensed features.
type License interface {
	IsFeatureEnabled(feature string) bool
	// GetFeatures() []string // Example of another method it might have
	// GetExpiry() time.Time // Example
}

// LicenseManager defines the interface for license parsing and validation.
type LicenseManager interface {
	// ParseAndValidate parses and validates a license token string.
	// It returns a License interface (which security.License implements) or an error.
	ParseAndValidate(tokenString string) (License, error)
}

// ServiceRegistry defines the interface for managing application services.
type ServiceRegistry interface {
	RegisterService(name string, service Service)
	LoadPermittedServices(license License) error
	StartService(ctx context.Context, name string) error
	StopService(ctx context.Context, name string) error
}
