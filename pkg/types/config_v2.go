package types

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

// HTTPConfigV2 is a simplified HTTP configuration
type HTTPConfigV2 struct {
	Listen   []string             `json:"listen"`
	Routes   []HTTPRouteV2        `json:"routes"`
	Security SimpleSecurityConfig `json:"security"`
}

// HTTPRouteV2 is a simplified route configuration
type HTTPRouteV2 struct {
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
