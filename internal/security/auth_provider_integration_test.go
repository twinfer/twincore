package security

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/twinfer/twincore/pkg/types"
)

// Real integration tests with actual caddy-security configuration generation and testing

func TestCaddySecurityAuthProviderIntegration(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	// Create test database
	db, securityRepo := setupTestDB(t)
	defer db.Close()

	// Create real auth provider repository
	authProviderRepo := &EnhancedMockAuthProviderRepository{
		providers: make(map[string]*types.AuthProvider),
	}
	mockLicenseChecker := &MockUnifiedLicenseChecker{valid: true}

	// Create system security manager
	manager := NewSystemSecurityManager(securityRepo, authProviderRepo, logger, mockLicenseChecker)

	// Enable security
	config := &types.SystemSecurityConfig{
		Enabled: true,
		AdminAuth: &types.AdminAuthConfig{
			Local: &types.LocalAuthConfig{},
		},
	}

	// Update manager's configuration to enable security
	err := manager.UpdateConfig(context.Background(), *config)
	require.NoError(t, err)

	// Mock configuration manager for testing config updates
	mockConfigManager := &MockConfigurationManager{
		appliedConfigs: make(map[string]any),
	}
	manager.SetConfigManager(mockConfigManager)

	t.Run("SAML Provider Integration", func(t *testing.T) {
		// Create SAML metadata server
		metadataServer := createMockSAMLMetadataServer(t)
		defer metadataServer.Close()

		// Create SAML provider with real-like configuration
		provider := &types.AuthProvider{
			ID:      "corporate-saml",
			Type:    types.AuthProviderTypeSAML,
			Name:    "Corporate SAML Provider",
			Enabled: true,
			Config: map[string]any{
				"entity_id":    "https://twincore.example.com/saml",
				"metadata_url": metadataServer.URL + "/metadata",
				"acs_url":      "https://twincore.example.com/saml/acs",
				"signing_cert": generateTestX509Certificate(),
			},
		}

		// Add provider through manager
		err := manager.AddAuthProvider(context.Background(), provider)
		require.NoError(t, err)

		// Test provider connectivity
		result, err := manager.TestAuthProvider(context.Background(), provider.ID)
		require.NoError(t, err)
		assert.True(t, result.Success, "SAML provider test should pass")
		assert.Contains(t, result.Message, "SAML")
		assert.Equal(t, true, result.Details["config_valid"])

		// Refresh auth configuration to generate caddy config
		err = manager.RefreshAuthConfiguration(context.Background())
		require.NoError(t, err)

		// Verify caddy-security config was generated and applied
		securityConfig, exists := mockConfigManager.appliedConfigs["/apps/security"]
		assert.True(t, exists, "Security config should be applied")
		assert.NotNil(t, securityConfig, "Security config should not be nil")

		// Parse and verify the generated caddy-security configuration
		var configData map[string]any

		// The security config is stored as json.RawMessage ([]byte), so we need to unmarshal it
		if configBytes, ok := securityConfig.([]byte); ok {
			err = json.Unmarshal(configBytes, &configData)
		} else {
			// Fallback: if it's already a map, use it directly
			configJSON, err := json.Marshal(securityConfig)
			require.NoError(t, err)
			err = json.Unmarshal(configJSON, &configData)
		}
		require.NoError(t, err)

		// Verify authentication portals section
		portals, ok := configData["authentication_portals"].(map[string]any)
		assert.True(t, ok, "Should have authentication_portals section")

		portal, ok := portals["twincore_portal"].(map[string]any)
		assert.True(t, ok, "Should have twincore_portal configuration")

		backends, ok := portal["backends"].([]any)
		assert.True(t, ok, "Should have backends array")

		// Find our SAML backend
		var samlBackend map[string]any
		for _, backend := range backends {
			if b, ok := backend.(map[string]any); ok {
				if method, ok := b["method"].(string); ok && method == "saml" {
					samlBackend = b
					break
				}
			}
		}
		assert.NotNil(t, samlBackend, "Should find SAML backend in configuration")
		assert.Equal(t, "corporate-saml_backend", samlBackend["name"])
		assert.Equal(t, provider.Config["entity_id"], samlBackend["entity_id"])
		assert.Equal(t, provider.Config["metadata_url"], samlBackend["idp_metadata_location"])
	})

	t.Run("OIDC Provider Integration", func(t *testing.T) {
		// Create OIDC discovery server
		discoveryServer := createMockOIDCDiscoveryServer(t)
		defer discoveryServer.Close()

		provider := &types.AuthProvider{
			ID:      "corporate-oidc",
			Type:    types.AuthProviderTypeOIDC,
			Name:    "Corporate OIDC Provider",
			Enabled: true,
			Config: map[string]any{
				"issuer":        discoveryServer.URL,
				"client_id":     "twincore-oidc-client",
				"client_secret": "super-secret-key",
				"scopes":        []any{"openid", "profile", "email", "groups"},
			},
		}

		err := manager.AddAuthProvider(context.Background(), provider)
		require.NoError(t, err)

		// Test provider connectivity - this should hit our mock OIDC discovery endpoint
		result, err := manager.TestAuthProvider(context.Background(), provider.ID)
		require.NoError(t, err)
		assert.True(t, result.Success, "OIDC provider test should pass")
		assert.Contains(t, result.Message, "OIDC")

		// Refresh configuration
		err = manager.RefreshAuthConfiguration(context.Background())
		require.NoError(t, err)

		// Verify the updated config includes OIDC provider
		securityConfig := mockConfigManager.appliedConfigs["/apps/security"]
		configJSON, _ := json.Marshal(securityConfig)
		var configData map[string]any
		json.Unmarshal(configJSON, &configData)

		portals := configData["authentication_portals"].(map[string]any)
		portal := portals["twincore_portal"].(map[string]any)
		backends := portal["backends"].([]any)

		// Find OIDC backend
		var oidcBackend map[string]any
		for _, backend := range backends {
			if b, ok := backend.(map[string]any); ok {
				if provider, ok := b["provider"].(string); ok && provider == "oidc" {
					oidcBackend = b
					break
				}
			}
		}
		assert.NotNil(t, oidcBackend, "Should find OIDC backend")
		assert.Equal(t, "corporate-oidc_backend", oidcBackend["name"])
		assert.Equal(t, "oauth2", oidcBackend["method"])
		assert.Contains(t, oidcBackend["discovery_url"], "/.well-known/openid_configuration")
	})

	t.Run("OAuth2 Provider Integration", func(t *testing.T) {
		// Create OAuth2 endpoints
		authServer := createMockOAuth2Server(t)
		defer authServer.Close()

		provider := &types.AuthProvider{
			ID:      "github-oauth2",
			Type:    types.AuthProviderTypeOAuth2,
			Name:    "GitHub OAuth2",
			Enabled: true,
			Config: map[string]any{
				"provider":          "github",
				"client_id":         "github-client-id",
				"client_secret":     "github-client-secret",
				"authorization_url": authServer.URL + "/oauth/authorize",
				"token_url":         authServer.URL + "/oauth/token",
				"user_info_url":     authServer.URL + "/user",
				"scopes":            []any{"read:user", "user:email"},
			},
		}

		err := manager.AddAuthProvider(context.Background(), provider)
		require.NoError(t, err)

		// Test connectivity to OAuth2 endpoints
		result, err := manager.TestAuthProvider(context.Background(), provider.ID)
		require.NoError(t, err)
		assert.True(t, result.Success, "OAuth2 provider test should pass")

		// Test attribute mapping
		mapping := manager.GetDefaultMapping(types.AuthProviderTypeOAuth2)
		externalAttrs := map[string]any{
			"login": "octocat",
			"email": "octocat@github.com",
			"name":  "The Octocat",
		}

		user, err := manager.MapAttributes(provider.ID, externalAttrs, mapping)
		require.NoError(t, err)
		assert.Equal(t, "octocat", user.Username)
		assert.Equal(t, "octocat@github.com", user.Email)
		assert.Equal(t, "The Octocat", user.FullName)
		assert.Equal(t, provider.ID, user.Metadata["provider_id"])
	})

	t.Run("Multi-Provider Configuration", func(t *testing.T) {
		// Test that all providers are included in final configuration
		err := manager.RefreshAuthConfiguration(context.Background())
		require.NoError(t, err)

		securityConfig := mockConfigManager.appliedConfigs["/apps/security"]
		configJSON, _ := json.Marshal(securityConfig)
		var configData map[string]any
		json.Unmarshal(configJSON, &configData)

		portals := configData["authentication_portals"].(map[string]any)
		portal := portals["twincore_portal"].(map[string]any)
		backends := portal["backends"].([]any)

		// Should have local + 3 external providers = 4 backends
		assert.GreaterOrEqual(t, len(backends), 4, "Should have local backend plus external providers")

		// Verify each provider type is present
		var foundSAML, foundOIDC, foundOAuth2, foundLocal bool
		for _, backend := range backends {
			if b, ok := backend.(map[string]any); ok {
				method, _ := b["method"].(string)
				name, _ := b["name"].(string)

				switch {
				case method == "saml":
					foundSAML = true
				case method == "oauth2" && name == "corporate-oidc_backend":
					foundOIDC = true
				case method == "oauth2" && name == "github-oauth2_backend":
					foundOAuth2 = true
				case method == "form":
					foundLocal = true
				}
			}
		}

		assert.True(t, foundSAML, "Should find SAML backend")
		assert.True(t, foundOIDC, "Should find OIDC backend")
		assert.True(t, foundOAuth2, "Should find OAuth2 backend")
		assert.True(t, foundLocal, "Should find local backend")

		// Verify authorization policies are generated
		policies, ok := configData["authorization_policies"].(map[string]any)
		assert.True(t, ok, "Should have authorization policies")

		policy, ok := policies["twincore_policy"].(map[string]any)
		assert.True(t, ok, "Should have twincore policy")

		rules, ok := policy["rules"].([]any)
		assert.True(t, ok, "Should have policy rules")
		assert.Greater(t, len(rules), 0, "Should have at least one policy rule")
	})

	t.Run("Real Attribute Mapping Integration", func(t *testing.T) {
		// Test complex SAML attribute mapping scenario
		mapping := &types.AttributeMapping{
			Username: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
			Email:    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
			FullName: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
			Roles: &types.RoleMapping{
				Source:       "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
				DefaultRoles: []string{"viewer"},
				RoleMap: map[string]string{
					"TwinCore-Administrators": "admin",
					"TwinCore-Operators":      "operator",
					"TwinCore-Viewers":        "viewer",
				},
				AllowMultiple: true,
			},
			Custom: map[string]types.AttributeRule{
				"department": {
					Source:       "http://schemas.xmlsoap.org/claims/department",
					DefaultValue: "Unknown",
					Transform:    "uppercase",
					Required:     false,
				},
				"employee_id": {
					Source:   "http://schemas.xmlsoap.org/claims/employeeid",
					Required: true,
				},
			},
		}

		// Simulate SAML assertion attributes
		samlAttrs := map[string]any{
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name":         "john.doe",
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "john.doe@company.com",
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname":    "John Doe",
			"http://schemas.microsoft.com/ws/2008/06/identity/claims/role":       []any{"TwinCore-Operators", "TwinCore-Viewers"},
			"http://schemas.xmlsoap.org/claims/department":                       "engineering",
			"http://schemas.xmlsoap.org/claims/employeeid":                       "EMP-12345",
		}

		user, err := manager.MapAttributes("corporate-saml", samlAttrs, mapping)
		require.NoError(t, err)

		assert.Equal(t, "john.doe", user.Username)
		assert.Equal(t, "john.doe@company.com", user.Email)
		assert.Equal(t, "John Doe", user.FullName)
		assert.Contains(t, user.Roles, "operator")
		assert.Contains(t, user.Roles, "viewer")
		assert.Equal(t, "ENGINEERING", user.Metadata["department"]) // Should be uppercase
		assert.Equal(t, "EMP-12345", user.Metadata["employee_id"])
		assert.Equal(t, "corporate-saml", user.Metadata["provider_id"])
	})
}

// Mock HTTP servers for testing real integration

func createMockSAMLMetadataServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metadata" {
			w.Header().Set("Content-Type", "application/samlmetadata+xml")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://example.com/saml">
	<md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
		<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://example.com/saml/sso"/>
	</md:IDPSSODescriptor>
</md:EntityDescriptor>`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func createMockOIDCDiscoveryServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid_configuration" {
			w.Header().Set("Content-Type", "application/json")
			discovery := map[string]any{
				"issuer":                   r.URL.Scheme + "://" + r.Host,
				"authorization_endpoint":   r.URL.Scheme + "://" + r.Host + "/auth",
				"token_endpoint":           r.URL.Scheme + "://" + r.Host + "/token",
				"userinfo_endpoint":        r.URL.Scheme + "://" + r.Host + "/userinfo",
				"jwks_uri":                 r.URL.Scheme + "://" + r.Host + "/certs",
				"scopes_supported":         []string{"openid", "profile", "email"},
				"response_types_supported": []string{"code", "id_token", "token id_token"},
			}
			json.NewEncoder(w).Encode(discovery)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "ok"}`))
		}
	}))
}

func createMockOAuth2Server(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/authorize":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"authorization_endpoint": "available"}`))
		case "/oauth/token":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token_endpoint": "available"}`))
		case "/user":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"user_info_endpoint": "available"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func generateTestX509Certificate() string {
	return `-----BEGIN CERTIFICATE-----
MIICXTCCAcYCCQDL3eeXgKGCFjANBgkqhkiG9w0BAQsFADByMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCQ0ExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xEzARBgNVBAoM
ClRlc3QgQ29tcDEPMA0GA1UECwwGVGVzdGluZzEYMBYGA1UEAwwPdGVzdC5leGFt
cGxlLmNvbTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMHIxCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJDQTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzETMBEG
A1UECgwKVGVzdCBDb21wMQ8wDQYDVQQLDAZUZXN0aW5nMRgwFgYDVQQDDA90ZXN0
LmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8Q7HgLCbZ
L+0qw1A3hK5Z8m6r8vXn5rQ8J1qpOhKuQ5Q7w5wN1OQ0KqQqQ7w5wN1OQ0KqQqQ7
w5wN1OQ0KqQqQ7w5wN1OQ0KqQqQ7w5wN1OQ0KqQqQ7w5wN1OQ0KqQqQ7w5wN1OQ0
KqQqQ7w5wN1OQ0KqQqQ7w5wN1OQ0KqQqQIDAQABMA0GCSqGSIb3DQEBCwUAA4GB
AIDAQABo4GsMIGpMB0GA1UdDgQWBBQ7w5wN1OQ0KqQqQ7w5wN1OQ0KqQqwwHwYD
VR0jBBgwFoAU+8OcDdTkNCqkKkO8OcDdTkNCqkKsMD8GA1UdHwQ4MDYwNKAyoDCG
Lmh0dHA6Ly93d3cuZXhhbXBsZS5jb20vY3JsL3Rlc3QtY3JsLTEuY3JsMA4GA1Ud
DwEB/wQEAwIBBjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4GBAIDAQ=
-----END CERTIFICATE-----`
}

// MockConfigurationManager for testing configuration updates
type MockConfigurationManager struct {
	appliedConfigs map[string]any
}

func (m *MockConfigurationManager) UpdateCaddyConfig(logger logrus.FieldLogger, path string, config any) error {
	m.appliedConfigs[path] = config
	logger.WithFields(logrus.Fields{
		"path":   path,
		"config": "updated",
	}).Info("Mock: Applied caddy configuration")
	return nil
}

// Additional integration test for license-based feature gating
func TestAuthProviderLicenseIntegration(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	db, securityRepo := setupTestDB(t)
	defer db.Close()

	authProviderRepo := &EnhancedMockAuthProviderRepository{
		providers: make(map[string]*types.AuthProvider),
	}

	t.Run("SAML Provider Blocked by License", func(t *testing.T) {
		// Create license checker that blocks SAML
		restrictedLicenseChecker := &MockUnifiedLicenseChecker{
			valid: true,
			features: map[string]bool{
				"saml_auth": false, // SAML blocked
				"oidc_auth": true,  // OIDC allowed
			},
		}

		manager := NewSystemSecurityManager(securityRepo, authProviderRepo, logger, restrictedLicenseChecker)

		samlProvider := &types.AuthProvider{
			ID:      "blocked-saml",
			Type:    types.AuthProviderTypeSAML,
			Name:    "Blocked SAML Provider",
			Enabled: true,
			Config: map[string]any{
				"entity_id":    "https://blocked.example.com/saml",
				"metadata_url": "https://blocked.example.com/saml/metadata",
			},
		}

		// Should fail to add SAML provider due to license
		err := manager.AddAuthProvider(context.Background(), samlProvider)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "SAML authentication not licensed")
	})

	t.Run("OIDC Provider Allowed by License", func(t *testing.T) {
		restrictedLicenseChecker := &MockUnifiedLicenseChecker{
			valid: true,
			features: map[string]bool{
				"saml_auth": false,
				"oidc_auth": true,
			},
		}

		manager := NewSystemSecurityManager(securityRepo, authProviderRepo, logger, restrictedLicenseChecker)

		oidcProvider := &types.AuthProvider{
			ID:      "allowed-oidc",
			Type:    types.AuthProviderTypeOIDC,
			Name:    "Allowed OIDC Provider",
			Enabled: true,
			Config: map[string]any{
				"issuer":        "https://allowed.example.com",
				"client_id":     "allowed-client",
				"client_secret": "allowed-secret",
			},
		}

		// Should succeed to add OIDC provider
		err := manager.AddAuthProvider(context.Background(), oidcProvider)
		assert.NoError(t, err, "OIDC provider should be allowed by license")
	})
}
