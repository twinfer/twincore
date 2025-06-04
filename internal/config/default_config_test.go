package config

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/twinfer/twincore/pkg/license"
)

func TestDefaultConfigProvider_SeparatedLicenseFeatures(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce log noise

	// Test public key for validation
	publicKey := []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890abcdef...
-----END PUBLIC KEY-----`)

	t.Run("BasicTier_SystemSecurityConfig", func(t *testing.T) {
		// Create license checker with basic tier (default)
		licenseChecker := license.NewDefaultUnifiedLicenseChecker(logger, publicKey)

		// Create config provider with license checker
		provider := NewDefaultConfigProviderWithLicense(licenseChecker)

		// Get default system security config
		secConfig := provider.GetDefaultSystemSecurityConfig()

		// Basic tier should have local auth enabled but not advanced features
		require.NotNil(t, secConfig.AdminAuth)
		assert.Equal(t, "local", secConfig.AdminAuth.Method)
		assert.Contains(t, secConfig.AdminAuth.Providers, "local")
		assert.NotContains(t, secConfig.AdminAuth.Providers, "ldap", "Basic tier should not include LDAP")
		assert.False(t, secConfig.AdminAuth.MFA, "Basic tier should not have MFA")

		// API auth should be basic
		require.NotNil(t, secConfig.APIAuth)
		assert.Contains(t, secConfig.APIAuth.Methods, "jwt")

		// Should have basic policies but not advanced RBAC
		assert.Len(t, secConfig.APIAuth.Policies, 2, "Basic tier should have default admin and user policies")

		// Check for default admin and user policies (no RBAC operator policy)
		policyNames := make([]string, len(secConfig.APIAuth.Policies))
		for i, policy := range secConfig.APIAuth.Policies {
			policyNames[i] = policy.ID
		}
		assert.Contains(t, policyNames, "default_admin")
		assert.Contains(t, policyNames, "default_user")
		assert.NotContains(t, policyNames, "rbac_operator", "Basic tier should not have RBAC operator policy")
	})

	t.Run("BasicTier_WoTSecurityConfig", func(t *testing.T) {
		// Create license checker with basic tier (default)
		licenseChecker := license.NewDefaultUnifiedLicenseChecker(logger, publicKey)

		// Create config provider with license checker
		provider := NewDefaultConfigProviderWithLicense(licenseChecker)

		// Get default WoT security config
		wotConfig := provider.GetDefaultWoTSecurityConfig()

		// Basic tier should have no credential stores (feature not enabled)
		assert.Len(t, wotConfig.CredentialStores, 0, "Basic tier should have no credential stores")

		// Basic tier should have no security templates (feature not enabled)
		assert.Len(t, wotConfig.SecurityTemplates, 0, "Basic tier should have no security templates")

		// Basic tier should not have global policies
		assert.Nil(t, wotConfig.GlobalPolicies, "Basic tier should not have global policies")
	})

	t.Run("LegacyLicenseFeatures_Fallback", func(t *testing.T) {
		// Test fallback to legacy license feature map when no unified checker is provided
		provider := NewDefaultConfigProvider()

		// Set legacy license features
		legacyFeatures := map[string]bool{
			"ldap_auth": true,
			"mfa":       true,
			"rbac":      false,
		}
		provider.SetLicenseFeatures(legacyFeatures)

		// Get default system security config
		secConfig := provider.GetDefaultSystemSecurityConfig()

		// Should use legacy features
		require.NotNil(t, secConfig.AdminAuth)
		assert.Contains(t, secConfig.AdminAuth.Providers, "ldap", "Should use legacy LDAP feature")
		assert.True(t, secConfig.AdminAuth.MFA, "Should use legacy MFA feature")

		// RBAC should be disabled
		assert.Len(t, secConfig.APIAuth.Policies, 2, "Should not have RBAC policy when disabled")
	})

	t.Run("NoLicenseChecker_BasicDefaults", func(t *testing.T) {
		// Test behavior when no license checker is provided
		provider := NewDefaultConfigProvider()

		// Get configs without license checker
		secConfig := provider.GetDefaultSystemSecurityConfig()
		wotConfig := provider.GetDefaultWoTSecurityConfig()
		streamConfig := provider.GetDefaultStreamConfig()

		// Should get basic configurations
		assert.NotNil(t, secConfig)
		assert.NotNil(t, wotConfig)
		assert.NotNil(t, streamConfig)

		// Security should be disabled by default
		assert.False(t, secConfig.Enabled, "Security should be disabled without license")

		// WoT config should have minimal features (no credential stores without license)
		assert.Len(t, wotConfig.CredentialStores, 0, "Should have no credential stores without license")
	})
}

func TestDefaultConfigProvider_HelperMethods(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	publicKey := []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890abcdef...
-----END PUBLIC KEY-----`)

	t.Run("FeatureChecking_WithUnifiedChecker", func(t *testing.T) {
		licenseChecker := license.NewDefaultUnifiedLicenseChecker(logger, publicKey)
		provider := NewDefaultConfigProviderWithLicense(licenseChecker)

		// Test system feature checking with basic tier (default)
		assert.True(t, provider.isSystemFeatureEnabled("local_auth"), "Basic tier should have local auth")
		assert.False(t, provider.isSystemFeatureEnabled("ldap_auth"), "Basic tier should not have LDAP auth")
		assert.False(t, provider.isSystemFeatureEnabled("saml_auth"), "Basic tier should not have SAML auth")

		// Test WoT feature checking with basic tier
		assert.True(t, provider.isWoTFeatureEnabled("basic_auth"), "Basic tier should have basic auth")
		assert.False(t, provider.isWoTFeatureEnabled("oauth2_auth"), "Basic tier should not have OAuth2 auth")
		assert.False(t, provider.isWoTFeatureEnabled("vault_integration"), "Basic tier should not have Vault")

		// Test general feature checking with basic tier
		assert.True(t, provider.isFeatureEnabled("tls_required"), "Basic tier should have TLS requirement")
	})

	t.Run("FeatureChecking_WithLegacyFeatures", func(t *testing.T) {
		provider := NewDefaultConfigProvider()

		// Set legacy features
		legacyFeatures := map[string]bool{
			"ldap_auth":         true,
			"mfa":               true,
			"oauth2_auth":       false,
			"vault_integration": false,
		}
		provider.SetLicenseFeatures(legacyFeatures)

		// Test feature checking falls back to legacy map
		assert.True(t, provider.isSystemFeatureEnabled("ldap_auth"), "Should use legacy LDAP feature")
		assert.True(t, provider.isSystemFeatureEnabled("mfa"), "Should use legacy MFA feature")
		assert.False(t, provider.isWoTFeatureEnabled("oauth2_auth"), "Should use legacy OAuth2 feature")
		assert.False(t, provider.isWoTFeatureEnabled("vault_integration"), "Should use legacy Vault feature")
	})

	t.Run("LicenseChecker_SetterAndGetter", func(t *testing.T) {
		provider := NewDefaultConfigProvider()

		// Initially no license checker
		assert.Nil(t, provider.licenseChecker)

		// Set license checker
		licenseChecker := license.NewDefaultUnifiedLicenseChecker(logger, publicKey)
		provider.SetLicenseChecker(licenseChecker)

		// Verify license checker is set
		assert.NotNil(t, provider.licenseChecker)
		assert.Equal(t, licenseChecker, provider.licenseChecker)
	})
}
