package types

import (
	"fmt"
	"time"
)

// AuthProvider represents an authentication provider configuration
type AuthProvider struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"` // ldap, saml, oidc, oauth2
	Name      string         `json:"name"`
	Enabled   bool           `json:"enabled"`
	Priority  int            `json:"priority"`
	Config    map[string]any `json:"config"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// AuthProviderType constants
const (
	AuthProviderTypeLDAP   = "ldap"
	AuthProviderTypeSAML   = "saml"
	AuthProviderTypeOIDC   = "oidc"
	AuthProviderTypeOAuth2 = "oauth2"
)

// ValidateType checks if the provider type is valid
func (p *AuthProvider) ValidateType() error {
	switch p.Type {
	case AuthProviderTypeLDAP, AuthProviderTypeSAML, AuthProviderTypeOIDC, AuthProviderTypeOAuth2:
		return nil
	default:
		return fmt.Errorf("invalid provider type: %s", p.Type)
	}
}

// CreateAuthProviderRequest represents a request to create an auth provider
type CreateAuthProviderRequest struct {
	ID       string         `json:"id" binding:"required"`
	Type     string         `json:"type" binding:"required"`
	Name     string         `json:"name" binding:"required"`
	Enabled  bool           `json:"enabled"`
	Priority int            `json:"priority"`
	Config   map[string]any `json:"config" binding:"required"`
}

// Validate validates the create request
func (r *CreateAuthProviderRequest) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("provider ID is required")
	}
	if r.Type == "" {
		return fmt.Errorf("provider type is required")
	}
	if r.Name == "" {
		return fmt.Errorf("provider name is required")
	}
	if r.Config == nil {
		return fmt.Errorf("provider config is required")
	}

	// Validate type
	provider := &AuthProvider{Type: r.Type}
	return provider.ValidateType()
}

// UpdateAuthProviderRequest represents a request to update an auth provider
type UpdateAuthProviderRequest struct {
	Name     *string        `json:"name,omitempty"`
	Enabled  *bool          `json:"enabled,omitempty"`
	Priority *int           `json:"priority,omitempty"`
	Config   map[string]any `json:"config,omitempty"`
}

// AuthProviderResponse represents an auth provider in API responses
type AuthProviderResponse struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Name      string         `json:"name"`
	Enabled   bool           `json:"enabled"`
	Priority  int            `json:"priority"`
	Config    map[string]any `json:"config"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// NewAuthProviderResponse creates a new auth provider response
func NewAuthProviderResponse(provider *AuthProvider) *AuthProviderResponse {
	return &AuthProviderResponse{
		ID:        provider.ID,
		Type:      provider.Type,
		Name:      provider.Name,
		Enabled:   provider.Enabled,
		Priority:  provider.Priority,
		Config:    provider.Config,
		CreatedAt: provider.CreatedAt,
		UpdatedAt: provider.UpdatedAt,
	}
}

// AuthProviderListResponse represents a list of auth providers
type AuthProviderListResponse struct {
	Providers []*AuthProviderResponse `json:"providers"`
	Total     int                     `json:"total"`
}

// NewAuthProviderListResponse creates a new auth provider list response
func NewAuthProviderListResponse(providers []*AuthProvider) *AuthProviderListResponse {
	responses := make([]*AuthProviderResponse, len(providers))
	for i, provider := range providers {
		responses[i] = NewAuthProviderResponse(provider)
	}
	return &AuthProviderListResponse{
		Providers: responses,
		Total:     len(providers),
	}
}

// AuthProviderTestResult represents the result of testing an auth provider
type AuthProviderTestResult struct {
	Success bool           `json:"success"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
	Errors  []string       `json:"errors,omitempty"`
}

// ProviderUser represents a user from an external provider
type ProviderUser struct {
	ID         string         `json:"id"`
	Username   string         `json:"username"`
	Email      string         `json:"email"`
	FullName   string         `json:"full_name,omitempty"`
	Groups     []string       `json:"groups,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// ProviderUserListResponse represents a list of users from a provider
type ProviderUserListResponse struct {
	Users []*ProviderUser `json:"users"`
	Total int             `json:"total"`
}

// NewProviderUserListResponse creates a new provider user list response
func NewProviderUserListResponse(users []*ProviderUser) *ProviderUserListResponse {
	return &ProviderUserListResponse{
		Users: users,
		Total: len(users),
	}
}

// UserProviderAssociation represents the association between a user and a provider
type UserProviderAssociation struct {
	UserID     string         `json:"user_id"`
	ProviderID string         `json:"provider_id"`
	ExternalID string         `json:"external_id"`
	Attributes map[string]any `json:"attributes,omitempty"`
	LastLogin  *time.Time     `json:"last_login,omitempty"`
}

// AttributeMapping defines how external provider attributes map to TwinCore user fields
type AttributeMapping struct {
	Username string                   `json:"username"`         // External attribute for username
	Email    string                   `json:"email"`            // External attribute for email
	FullName string                   `json:"full_name"`        // External attribute for full name
	Roles    *RoleMapping             `json:"roles,omitempty"`  // Role mapping configuration
	Groups   *GroupMapping            `json:"groups,omitempty"` // Group mapping configuration
	Custom   map[string]AttributeRule `json:"custom,omitempty"` // Custom attribute mappings
}

// RoleMapping defines how external roles/groups map to TwinCore roles
type RoleMapping struct {
	Source        string            `json:"source"`         // External attribute containing roles/groups
	DefaultRoles  []string          `json:"default_roles"`  // Default roles if no mapping found
	RoleMap       map[string]string `json:"role_map"`       // Map external role to TwinCore role
	AllowMultiple bool              `json:"allow_multiple"` // Allow multiple roles
}

// GroupMapping defines how external groups map to TwinCore user groups
type GroupMapping struct {
	Source   string            `json:"source"`    // External attribute containing groups
	GroupMap map[string]string `json:"group_map"` // Map external group to TwinCore group
}

// AttributeRule defines a custom attribute mapping rule
type AttributeRule struct {
	Source       string `json:"source"`              // External attribute name
	DefaultValue any    `json:"default_value"`       // Default value if not found
	Transform    string `json:"transform,omitempty"` // Transformation rule (lowercase, uppercase, etc.)
	Required     bool   `json:"required"`            // Whether this attribute is required
}

// UserAttributeMapper provides methods for mapping external provider attributes to TwinCore users
type UserAttributeMapper interface {
	MapAttributes(providerID string, externalAttrs map[string]any, mapping *AttributeMapping) (*User, error)
	ValidateMapping(mapping *AttributeMapping) error
	GetDefaultMapping(providerType string) *AttributeMapping
}
