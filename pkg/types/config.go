// pkg/types/config.go
package types

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

// SecurityConfig represents security configuration
type SecurityConfig struct {
	Enabled   bool            `json:"enabled"`
	LocalAuth LocalAuthConfig `json:"local_auth"`
	JWT       JWTConfig       `json:"jwt"`
	SAML      SAMLConfig      `json:"saml"`
	OIDC      OIDCConfig      `json:"oidc"`
	Policies  []PolicyConfig  `json:"policies"`
}

// LocalAuthConfig represents local authentication configuration
type LocalAuthConfig struct {
	Enabled  bool   `json:"enabled"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// JWTConfig represents JWT authentication configuration
type JWTConfig struct {
	Enabled   bool   `json:"enabled"`
	Algorithm string `json:"algorithm"`
	Secret    string `json:"secret"`
	Issuer    string `json:"issuer"`
}

// SAMLConfig represents SAML authentication configuration
type SAMLConfig struct {
	Enabled     bool   `json:"enabled"`
	MetadataURL string `json:"metadata_url"`
	EntityID    string `json:"entity_id"`
}

// OIDCConfig represents OIDC authentication configuration
type OIDCConfig struct {
	Enabled      bool   `json:"enabled"`
	ProviderURL  string `json:"provider_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// PolicyConfig represents an authorization policy
type PolicyConfig struct {
	Name      string   `json:"name"`
	Subjects  []string `json:"subjects"`
	Resources []string `json:"resources"`
	Actions   []string `json:"actions"`
}

// HTTPConfig with Security field
type HTTPConfig struct {
	Routes   []HTTPRoute            `json:"routes"`
	Security map[string]interface{} `json:"security,omitempty"`
}
