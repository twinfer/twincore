// pkg/types/config.go
package types

import (
	"context"
)

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

// StreamConfig holds configurations for streaming topics and commands.
// This is used for high-level configuration, not to be confused with Benthos StreamBuilder
type StreamConfig struct {
	Topics   []StreamTopic   `json:"topics"`
	Commands []CommandStream `json:"commands"`
}

// UnifiedConfig represents a unified configuration for both HTTP and Stream services
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

// Definitions moved from pkg/types/config_v2.go:

// SimpleSecurityConfig is a lightweight security configuration
// that uses Caddy's built-in features instead of go-authcrunch
type SimpleSecurityConfig struct {
	Enabled bool `json:"enabled"`

	// Basic authentication
	BasicAuth *BasicAuthConfig `json:"basic_auth,omitempty"`

	// Bearer token authentication
	BearerAuth *BearerAuthConfig `json:"bearer_auth,omitempty"`

	// JWT validation
	JWTAuth *JWTAuthConfig `json:"jwt_auth,omitempty"`
}

// BasicAuthConfig holds basic authentication configuration
type BasicAuthConfig struct {
	Users []BasicAuthUser `json:"users"`
}

// BasicAuthUser represents a user for basic authentication
type BasicAuthUser struct {
	Username string `json:"username"`
	Password string `json:"password"` // Should be hashed in production
}

// BearerAuthConfig holds bearer token configuration
type BearerAuthConfig struct {
	Tokens []string `json:"tokens"`
}

// JWTAuthConfig holds JWT validation configuration
type JWTAuthConfig struct {
	PublicKey string `json:"public_key"` // PEM-encoded public key
	Issuer    string `json:"issuer,omitempty"`
	Audience  string `json:"audience,omitempty"`
}

// HTTPConfig is a simplified HTTP configuration
type HTTPConfig struct {
	Listen   []string             `json:"listen"`
	Routes   []HTTPRoute          `json:"routes"`
	Security SimpleSecurityConfig `json:"security"`
}

// HTTPRoute is a simplified route configuration
type HTTPRoute struct {
	Path         string                 `json:"path"`
	Methods      []string               `json:"methods,omitempty"`
	Handler      string                 `json:"handler"`
	RequiresAuth bool                   `json:"requires_auth"`
	Config       map[string]interface{} `json:"config,omitempty"`
}

// CaddyAdminClient provides methods to interact with Caddy Admin API
type CaddyAdminClient struct {
	BaseURL string
}

// NewCaddyAdminClient creates a new Caddy Admin API client
func NewCaddyAdminClient(baseURL string) *CaddyAdminClient {
	if baseURL == "" {
		baseURL = "http://localhost:2019"
	}
	return &CaddyAdminClient{BaseURL: baseURL}
}

// RouteHandler defines common route handler configurations
type RouteHandler string

const (
	HandlerReverseProxy   RouteHandler = "reverse_proxy"
	HandlerStaticResponse RouteHandler = "static_response"
	HandlerFileServer     RouteHandler = "file_server"
	HandlerSubroute       RouteHandler = "subroute"
)

// AuthType defines authentication types
type AuthType string

const (
	AuthTypeBasic  AuthType = "basic"
	AuthTypeBearer AuthType = "bearer"
	AuthTypeJWT    AuthType = "jwt"
)
