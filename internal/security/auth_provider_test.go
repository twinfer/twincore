package security

import (
	"context"
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/twinfer/twincore/pkg/types"
)

// EnhancedMockAuthProviderRepository for testing with state
type EnhancedMockAuthProviderRepository struct {
	providers map[string]*types.AuthProvider
}

func (m *EnhancedMockAuthProviderRepository) IsHealthy(ctx context.Context) bool {
	return true
}

func (m *EnhancedMockAuthProviderRepository) CreateProvider(ctx context.Context, provider *types.AuthProvider) error {
	m.providers[provider.ID] = provider
	return nil
}

func (m *EnhancedMockAuthProviderRepository) GetProvider(ctx context.Context, id string) (*types.AuthProvider, error) {
	if provider, exists := m.providers[id]; exists {
		return provider, nil
	}
	return nil, fmt.Errorf("provider not found: %s", id)
}

func (m *EnhancedMockAuthProviderRepository) ListProviders(ctx context.Context) ([]*types.AuthProvider, error) {
	providers := make([]*types.AuthProvider, 0, len(m.providers))
	for _, provider := range m.providers {
		providers = append(providers, provider)
	}
	return providers, nil
}

func (m *EnhancedMockAuthProviderRepository) UpdateProvider(ctx context.Context, id string, updates map[string]any) error {
	if provider, exists := m.providers[id]; exists {
		// Apply updates to the provider
		if name, ok := updates["name"].(string); ok {
			provider.Name = name
		}
		if enabled, ok := updates["enabled"].(bool); ok {
			provider.Enabled = enabled
		}
		if config, ok := updates["config"].(map[string]any); ok {
			provider.Config = config
		}
		return nil
	}
	return fmt.Errorf("provider not found: %s", id)
}

func (m *EnhancedMockAuthProviderRepository) DeleteProvider(ctx context.Context, id string) error {
	if _, exists := m.providers[id]; exists {
		delete(m.providers, id)
		return nil
	}
	return fmt.Errorf("provider not found: %s", id)
}

func (m *EnhancedMockAuthProviderRepository) AssociateUserWithProvider(ctx context.Context, userID, providerID, externalID string, attributes map[string]any) error {
	return nil
}

func (m *EnhancedMockAuthProviderRepository) GetUserProviderAssociations(ctx context.Context, userID string) ([]*types.UserProviderAssociation, error) {
	return []*types.UserProviderAssociation{}, nil
}

func (m *EnhancedMockAuthProviderRepository) UpdateProviderMetadata(ctx context.Context, providerID string, metadata map[string]any) error {
	return nil
}

func TestSystemSecurityManager_AuthProviders(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	db, securityRepo := setupTestDB(t)
	defer db.Close()

	// Create mock auth provider repository
	mockAuthProviderRepo := &EnhancedMockAuthProviderRepository{
		providers: make(map[string]*types.AuthProvider),
	}
	mockLicenseChecker := &MockUnifiedLicenseChecker{valid: true}

	manager := NewSystemSecurityManager(securityRepo, mockAuthProviderRepo, logger, mockLicenseChecker)

	t.Run("TestSAMLProvider", func(t *testing.T) {
		provider := &types.AuthProvider{
			ID:      "test-saml",
			Type:    types.AuthProviderTypeSAML,
			Name:    "Test SAML Provider",
			Enabled: true,
			Config: map[string]any{
				"entity_id":    "https://example.com/saml",
				"metadata_url": "https://example.com/saml/metadata",
				"acs_url":      "https://twincore.example.com/saml/acs",
			},
		}

		// Store provider in mock repository first
		mockAuthProviderRepo.providers = map[string]*types.AuthProvider{
			provider.ID: provider,
		}

		result, err := manager.TestAuthProvider(context.Background(), provider.ID)
		require.NoError(t, err)

		// Since we're using mock, the test should pass basic validation
		assert.NotNil(t, result)
		assert.Contains(t, result.Message, "SAML")
		assert.Contains(t, result.Details, "config_valid")
	})

	t.Run("TestOIDCProvider", func(t *testing.T) {
		provider := &types.AuthProvider{
			ID:      "test-oidc",
			Type:    types.AuthProviderTypeOIDC,
			Name:    "Test OIDC Provider",
			Enabled: true,
			Config: map[string]any{
				"issuer":        "https://auth.example.com",
				"client_id":     "twincore-client",
				"client_secret": "secret123",
				"scopes":        []any{"openid", "profile", "email"},
			},
		}

		// Store provider in mock repository first
		mockAuthProviderRepo.providers = map[string]*types.AuthProvider{
			provider.ID: provider,
		}

		result, err := manager.TestAuthProvider(context.Background(), provider.ID)
		require.NoError(t, err)

		assert.NotNil(t, result)
		assert.Contains(t, result.Message, "OIDC")
		assert.Contains(t, result.Details, "config_valid")
	})

	t.Run("TestOAuth2Provider", func(t *testing.T) {
		provider := &types.AuthProvider{
			ID:      "test-oauth2",
			Type:    types.AuthProviderTypeOAuth2,
			Name:    "Test OAuth2 Provider",
			Enabled: true,
			Config: map[string]any{
				"client_id":         "twincore-client",
				"client_secret":     "secret123",
				"authorization_url": "https://auth.example.com/oauth/authorize",
				"token_url":         "https://auth.example.com/oauth/token",
				"user_info_url":     "https://auth.example.com/oauth/userinfo",
			},
		}

		// Store provider in mock repository first
		mockAuthProviderRepo.providers = map[string]*types.AuthProvider{
			provider.ID: provider,
		}

		result, err := manager.TestAuthProvider(context.Background(), provider.ID)
		require.NoError(t, err)

		assert.NotNil(t, result)
		assert.Contains(t, result.Message, "OAuth2")
		assert.Contains(t, result.Details, "config_valid")
	})
}

func TestAttributeMapping(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	db, securityRepo := setupTestDB(t)
	defer db.Close()

	mockAuthProviderRepo := &EnhancedMockAuthProviderRepository{
		providers: make(map[string]*types.AuthProvider),
	}
	mockLicenseChecker := &MockUnifiedLicenseChecker{valid: true}

	manager := NewSystemSecurityManager(securityRepo, mockAuthProviderRepo, logger, mockLicenseChecker)

	t.Run("MapSAMLAttributes", func(t *testing.T) {
		mapping := manager.GetDefaultMapping(types.AuthProviderTypeSAML)
		require.NotNil(t, mapping)

		externalAttrs := map[string]any{
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":         "john.doe",
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "john@example.com",
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname":    "John Doe",
			"http://schemas.microsoft.com/ws/2008/06/identity/claims/role":       []any{"Administrator", "Viewer"},
		}

		user, err := manager.MapAttributes("saml-provider", externalAttrs, mapping)
		require.NoError(t, err)

		assert.Equal(t, "john.doe", user.Username)
		assert.Equal(t, "john@example.com", user.Email)
		assert.Equal(t, "John Doe", user.FullName)
		assert.Contains(t, user.Roles, "admin")
		assert.Contains(t, user.Roles, "viewer")
		assert.Equal(t, "saml-provider", user.Metadata["provider_id"])
	})

	t.Run("MapOIDCAttributes", func(t *testing.T) {
		mapping := manager.GetDefaultMapping(types.AuthProviderTypeOIDC)
		require.NotNil(t, mapping)

		externalAttrs := map[string]any{
			"preferred_username": "alice.smith",
			"email":              "alice@example.com",
			"name":               "Alice Smith",
			"roles":              []any{"operator"},
		}

		user, err := manager.MapAttributes("oidc-provider", externalAttrs, mapping)
		require.NoError(t, err)

		assert.Equal(t, "alice.smith", user.Username)
		assert.Equal(t, "alice@example.com", user.Email)
		assert.Equal(t, "Alice Smith", user.FullName)
		assert.Contains(t, user.Roles, "operator")
	})

	t.Run("MapLDAPAttributes", func(t *testing.T) {
		mapping := manager.GetDefaultMapping(types.AuthProviderTypeLDAP)
		require.NotNil(t, mapping)

		externalAttrs := map[string]any{
			"uid":      "bob.jones",
			"mail":     "bob@example.com",
			"cn":       "Bob Jones",
			"memberOf": []any{"cn=admin,ou=groups,dc=company,dc=com", "cn=viewer,ou=groups,dc=company,dc=com"},
		}

		user, err := manager.MapAttributes("ldap-provider", externalAttrs, mapping)
		require.NoError(t, err)

		assert.Equal(t, "bob.jones", user.Username)
		assert.Equal(t, "bob@example.com", user.Email)
		assert.Equal(t, "Bob Jones", user.FullName)
		assert.Contains(t, user.Roles, "admin")
		assert.Contains(t, user.Roles, "viewer")
	})

	t.Run("CustomAttributeMapping", func(t *testing.T) {
		mapping := &types.AttributeMapping{
			Username: "login",
			Email:    "email_address",
			FullName: "display_name",
			Custom: map[string]types.AttributeRule{
				"department": {
					Source:       "dept",
					DefaultValue: "Unknown",
					Transform:    "uppercase",
					Required:     false,
				},
				"employee_id": {
					Source:   "emp_id",
					Required: true,
				},
			},
		}

		externalAttrs := map[string]any{
			"login":         "test.user",
			"email_address": "test@example.com",
			"display_name":  "Test User",
			"dept":          "engineering",
			"emp_id":        "12345",
		}

		user, err := manager.MapAttributes("custom-provider", externalAttrs, mapping)
		require.NoError(t, err)

		assert.Equal(t, "test.user", user.Username)
		assert.Equal(t, "test@example.com", user.Email)
		assert.Equal(t, "Test User", user.FullName)
		assert.Equal(t, "ENGINEERING", user.Metadata["department"])
		assert.Equal(t, "12345", user.Metadata["employee_id"])
	})

	t.Run("MissingRequiredAttribute", func(t *testing.T) {
		mapping := &types.AttributeMapping{
			Username: "login",
			Custom: map[string]types.AttributeRule{
				"employee_id": {
					Source:   "emp_id",
					Required: true,
				},
			},
		}

		externalAttrs := map[string]any{
			"login": "test.user",
			// missing emp_id
		}

		_, err := manager.MapAttributes("custom-provider", externalAttrs, mapping)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "required custom attribute 'employee_id'")
	})
}

func TestCaddyAuthPortalBridge_ExternalProviders(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	db, securityRepo := setupTestDB(t)
	defer db.Close()

	mockLicenseChecker := &MockUnifiedLicenseChecker{valid: true}

	config := &types.SystemSecurityConfig{
		Enabled: true,
		AdminAuth: &types.AdminAuthConfig{
			Local: &types.LocalAuthConfig{},
		},
	}

	bridge, err := NewCaddyAuthPortalBridge(securityRepo, logger, config, mockLicenseChecker, "/tmp/test")
	require.NoError(t, err)

	t.Run("GenerateSAMLBackend", func(t *testing.T) {
		provider := &types.AuthProvider{
			ID:      "test-saml",
			Type:    types.AuthProviderTypeSAML,
			Name:    "Test SAML Provider",
			Enabled: true,
			Config: map[string]any{
				"entity_id":    "https://example.com/saml",
				"metadata_url": "https://example.com/saml/metadata",
				"acs_url":      "https://twincore.example.com/saml/acs",
			},
		}

		backend := bridge.generateSAMLBackend(provider)

		assert.Equal(t, "test-saml_backend", backend["name"])
		assert.Equal(t, "saml", backend["method"])
		assert.Equal(t, "test-saml", backend["realm"])
		assert.Equal(t, "https://example.com/saml", backend["entity_id"])
		assert.Equal(t, "https://example.com/saml/metadata", backend["idp_metadata_location"])
		assert.Equal(t, "https://twincore.example.com/saml/acs", backend["acs_url"])

		// Check default attributes are present
		attributes, ok := backend["attributes"].(map[string]any)
		assert.True(t, ok)
		assert.Contains(t, attributes, "name")
		assert.Contains(t, attributes, "email")
		assert.Contains(t, attributes, "roles")
	})

	t.Run("GenerateOIDCBackend", func(t *testing.T) {
		provider := &types.AuthProvider{
			ID:      "test-oidc",
			Type:    types.AuthProviderTypeOIDC,
			Name:    "Test OIDC Provider",
			Enabled: true,
			Config: map[string]any{
				"issuer":        "https://auth.example.com",
				"client_id":     "twincore-client",
				"client_secret": "secret123",
			},
		}

		backend := bridge.generateOIDCBackend(provider)

		assert.Equal(t, "test-oidc_backend", backend["name"])
		assert.Equal(t, "oauth2", backend["method"])
		assert.Equal(t, "oidc", backend["provider"])
		assert.Equal(t, "twincore-client", backend["client_id"])
		assert.Equal(t, "secret123", backend["client_secret"])
		assert.Equal(t, "https://auth.example.com/auth", backend["authorization_url"])
		assert.Equal(t, "https://auth.example.com/token", backend["token_url"])
		assert.Equal(t, "https://auth.example.com/.well-known/openid_configuration", backend["discovery_url"])

		// Check default scopes
		scopes, ok := backend["scopes"].([]string)
		assert.True(t, ok)
		assert.Contains(t, scopes, "openid")
		assert.Contains(t, scopes, "profile")
		assert.Contains(t, scopes, "email")
	})

	t.Run("GenerateOAuth2Backend", func(t *testing.T) {
		provider := &types.AuthProvider{
			ID:      "test-oauth2",
			Type:    types.AuthProviderTypeOAuth2,
			Name:    "Test OAuth2 Provider",
			Enabled: true,
			Config: map[string]any{
				"client_id":         "twincore-client",
				"client_secret":     "secret123",
				"authorization_url": "https://auth.example.com/oauth/authorize",
				"token_url":         "https://auth.example.com/oauth/token",
				"user_info_url":     "https://auth.example.com/oauth/userinfo",
				"provider":          "github",
			},
		}

		backend := bridge.generateOAuth2Backend(provider)

		assert.Equal(t, "test-oauth2_backend", backend["name"])
		assert.Equal(t, "oauth2", backend["method"])
		assert.Equal(t, "github", backend["provider"])
		assert.Equal(t, "twincore-client", backend["client_id"])
		assert.Equal(t, "secret123", backend["client_secret"])
		assert.Equal(t, "https://auth.example.com/oauth/authorize", backend["authorization_url"])
		assert.Equal(t, "https://auth.example.com/oauth/token", backend["token_url"])
		assert.Equal(t, "https://auth.example.com/oauth/userinfo", backend["user_info_url"])

		// Check default attributes
		attributes, ok := backend["attributes"].(map[string]any)
		assert.True(t, ok)
		assert.Contains(t, attributes, "name")
		assert.Contains(t, attributes, "email")
		assert.Contains(t, attributes, "roles")
	})

	t.Run("UpdateExternalProviders", func(t *testing.T) {
		providers := []*types.AuthProvider{
			{
				ID:      "saml-1",
				Type:    types.AuthProviderTypeSAML,
				Name:    "Corporate SAML",
				Enabled: true,
				Config: map[string]any{
					"entity_id":    "https://corp.example.com/saml",
					"metadata_url": "https://corp.example.com/saml/metadata",
				},
			},
			{
				ID:      "oidc-1",
				Type:    types.AuthProviderTypeOIDC,
				Name:    "Corporate OIDC",
				Enabled: true,
				Config: map[string]any{
					"issuer":    "https://auth.corp.example.com",
					"client_id": "twincore",
				},
			},
		}

		err := bridge.UpdateExternalProviders(context.Background(), providers)
		assert.NoError(t, err)

		// Verify providers are stored
		storedProviders := bridge.GetExternalProviders()
		assert.Len(t, storedProviders, 2)
		assert.Equal(t, "saml-1", storedProviders[0].ID)
		assert.Equal(t, "oidc-1", storedProviders[1].ID)
	})
}

func TestValidateMapping(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	db, securityRepo := setupTestDB(t)
	defer db.Close()

	mockAuthProviderRepo := &EnhancedMockAuthProviderRepository{
		providers: make(map[string]*types.AuthProvider),
	}
	mockLicenseChecker := &MockUnifiedLicenseChecker{valid: true}

	manager := NewSystemSecurityManager(securityRepo, mockAuthProviderRepo, logger, mockLicenseChecker)

	t.Run("ValidMapping", func(t *testing.T) {
		mapping := &types.AttributeMapping{
			Username: "uid",
			Email:    "mail",
			FullName: "cn",
			Roles: &types.RoleMapping{
				Source:       "memberOf",
				DefaultRoles: []string{"viewer"},
			},
		}

		err := manager.ValidateMapping(mapping)
		assert.NoError(t, err)
	})

	t.Run("MissingUsername", func(t *testing.T) {
		mapping := &types.AttributeMapping{
			Email:    "mail",
			FullName: "cn",
		}

		err := manager.ValidateMapping(mapping)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "username mapping is required")
	})

	t.Run("InvalidRoleMapping", func(t *testing.T) {
		mapping := &types.AttributeMapping{
			Username: "uid",
			Roles: &types.RoleMapping{
				// Missing Source
				DefaultRoles: []string{"viewer"},
			},
		}

		err := manager.ValidateMapping(mapping)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "role mapping source is required")
	})

	t.Run("InvalidCustomAttribute", func(t *testing.T) {
		mapping := &types.AttributeMapping{
			Username: "uid",
			Custom: map[string]types.AttributeRule{
				"department": {
					// Missing Source
					DefaultValue: "Unknown",
				},
			},
		}

		err := manager.ValidateMapping(mapping)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "custom attribute 'department' source is required")
	})
}
