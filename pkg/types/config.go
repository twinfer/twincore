// pkg/types/config.go
package types

import (
	"context"
)

// StreamTopic represents a streaming topic configuration
type StreamTopic struct {
	Name   string         `json:"name"`
	Type   string         `json:"type"`
	Config map[string]any `json:"config"`
}

// CommandStream represents a command stream configuration
type CommandStream struct {
	Name   string         `json:"name"`
	Type   string         `json:"type"`
	Config map[string]any `json:"config"`
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
	Name   string         `json:"name"`
	Type   string         `json:"type"`
	Config map[string]any `json:"config"` // Generic config map
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
	RegisterServiceWithConfig(name string, service Service, config ServiceConfig)
	SetServiceConfig(name string, config ServiceConfig) error
	LoadPermittedServices(license License) error
	StartService(ctx context.Context, name string) error
	StartServiceWithConfig(ctx context.Context, name string, config ServiceConfig) error
	StopService(ctx context.Context, name string) error
	GetServiceStatus() map[string]ServiceStatus
}

// ServiceStatus represents the status of a service
type ServiceStatus struct {
	Name            string   `json:"name"`
	Registered      bool     `json:"registered"`
	Permitted       bool     `json:"permitted"`
	HasConfig       bool     `json:"has_config"`
	ServiceType     string   `json:"service_type"`
	Dependencies    []string `json:"dependencies"`
	RequiredLicense []string `json:"required_license"`
}

// HTTPConfig is a simplified HTTP configuration
// Security is now handled separately via SystemSecurityManager
type HTTPConfig struct {
	Listen []string    `json:"listen"`
	Routes []HTTPRoute `json:"routes"`
	// Security removed - now handled by SystemSecurityManager
}

// HTTPRoute is a simplified route configuration
type HTTPRoute struct {
	Path         string         `json:"path"`
	Methods      []string       `json:"methods,omitempty"`
	Handler      string         `json:"handler"`
	RequiresAuth bool           `json:"requires_auth"`
	Config       map[string]any `json:"config,omitempty"`
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
