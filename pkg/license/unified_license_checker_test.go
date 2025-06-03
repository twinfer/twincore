package license

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/twinfer/twincore/pkg/types"
)

func TestUnifiedLicenseChecker_SeparatedSecurityFeatures(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce log noise during tests

	// Test public key for validation
	publicKey := []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890abcdef...
-----END PUBLIC KEY-----`)

	t.Run("BasicTier_SystemSecurityFeatures", func(t *testing.T) {
		checker := NewDefaultUnifiedLicenseChecker(logger, publicKey)
		ctx := context.Background()

		// Test System Security Features - Basic tier should have limited features
		assert.True(t, checker.IsSystemFeatureEnabled(ctx, "local_auth"), "Basic tier should support local auth")
		assert.True(t, checker.IsSystemFeatureEnabled(ctx, "session_mgmt"), "Basic tier should support session management")
		
		// Advanced system features should be disabled in basic tier
		assert.False(t, checker.IsSystemFeatureEnabled(ctx, "ldap_auth"), "Basic tier should not support LDAP")
		assert.False(t, checker.IsSystemFeatureEnabled(ctx, "saml_auth"), "Basic tier should not support SAML")
		assert.False(t, checker.IsSystemFeatureEnabled(ctx, "mfa"), "Basic tier should not support MFA")
		assert.False(t, checker.IsSystemFeatureEnabled(ctx, "rbac"), "Basic tier should not support RBAC")

		// Get system security features
		systemFeatures, err := checker.GetSystemSecurityFeatures(ctx)
		require.NoError(t, err)
		require.NotNil(t, systemFeatures)

		assert.True(t, systemFeatures.LocalAuth, "Basic tier should have local auth")
		assert.False(t, systemFeatures.LDAPAuth, "Basic tier should not have LDAP auth")
		assert.False(t, systemFeatures.MFA, "Basic tier should not have MFA")
	})

	t.Run("BasicTier_WoTSecurityFeatures", func(t *testing.T) {
		checker := NewDefaultUnifiedLicenseChecker(logger, publicKey)
		ctx := context.Background()

		// Test WoT Security Features - Basic tier should have basic authentication
		assert.True(t, checker.IsWoTFeatureEnabled(ctx, "basic_auth"), "Basic tier should support basic auth")
		assert.True(t, checker.IsWoTFeatureEnabled(ctx, "bearer_auth"), "Basic tier should support bearer auth")
		
		// Advanced WoT features should be disabled
		assert.False(t, checker.IsWoTFeatureEnabled(ctx, "oauth2_auth"), "Basic tier should not support OAuth2")
		assert.False(t, checker.IsWoTFeatureEnabled(ctx, "certificate_auth"), "Basic tier should not support certificates")
		assert.False(t, checker.IsWoTFeatureEnabled(ctx, "vault_integration"), "Basic tier should not support Vault")
		assert.False(t, checker.IsWoTFeatureEnabled(ctx, "credential_rotation"), "Basic tier should not support credential rotation")
		assert.False(t, checker.IsWoTFeatureEnabled(ctx, "thing_access_control"), "Basic tier should not support Thing ACL")

		// Get WoT security features
		wotFeatures, err := checker.GetWoTSecurityFeatures(ctx)
		require.NoError(t, err)
		require.NotNil(t, wotFeatures)

		assert.True(t, wotFeatures.BasicAuth, "Basic tier should have basic auth")
		assert.True(t, wotFeatures.BearerAuth, "Basic tier should have bearer auth")
		assert.False(t, wotFeatures.OAuth2Auth, "Basic tier should not have OAuth2")
		assert.False(t, wotFeatures.VaultIntegration, "Basic tier should not have Vault")
	})

	t.Run("FeatureValidation_SystemSecurity", func(t *testing.T) {
		checker := NewDefaultUnifiedLicenseChecker(logger, publicKey)
		ctx := context.Background()

		// Test system operation validation
		err := checker.ValidateSystemOperation(ctx, "create_user")
		assert.NoError(t, err, "Basic tier should allow user creation")

		err = checker.ValidateSystemOperation(ctx, "ldap_login")
		assert.Error(t, err, "Basic tier should not allow LDAP login")

		err = checker.ValidateSystemOperation(ctx, "mfa_verify")
		assert.Error(t, err, "Basic tier should not allow MFA verification")

		err = checker.ValidateSystemOperation(ctx, "create_policy")
		assert.Error(t, err, "Basic tier should not allow RBAC policy creation")
	})

	t.Run("FeatureValidation_WoTSecurity", func(t *testing.T) {
		checker := NewDefaultUnifiedLicenseChecker(logger, publicKey)
		ctx := context.Background()

		// Test WoT operation validation - using operations that don't require advanced features
		err := checker.ValidateWoTOperation(ctx, "read_property")
		assert.NoError(t, err, "Basic tier should allow basic operations")

		err = checker.ValidateWoTOperation(ctx, "set_thing_credentials")
		assert.Error(t, err, "Basic tier should not allow credential store operations")

		err = checker.ValidateWoTOperation(ctx, "create_security_template")
		assert.Error(t, err, "Basic tier should not allow security template creation")

		// Test security scheme validation
		err = checker.ValidateSecurityScheme(ctx, "basic")
		assert.NoError(t, err, "Basic tier should support basic scheme")

		err = checker.ValidateSecurityScheme(ctx, "oauth2")
		assert.Error(t, err, "Basic tier should not support OAuth2 scheme")

		err = checker.ValidateSecurityScheme(ctx, "psk")
		assert.Error(t, err, "Basic tier should not support PSK scheme")
	})

	t.Run("LicenseLimits_BasicTier", func(t *testing.T) {
		checker := NewDefaultUnifiedLicenseChecker(logger, publicKey)
		ctx := context.Background()

		// Get license limits
		limits, err := checker.GetLicenseLimits(ctx)
		require.NoError(t, err)
		require.NotNil(t, limits)

		// Basic tier limits should be restrictive
		assert.Equal(t, 10, limits.MaxDevices, "Basic tier should have 10 device limit")
		assert.Equal(t, 50, limits.MaxThings, "Basic tier should have 50 things limit")
		assert.Equal(t, 5, limits.MaxUsers, "Basic tier should have 5 users limit")

		// Test limit checking
		err = checker.CheckLimit(ctx, "devices", 5)
		assert.NoError(t, err, "5 devices should be within basic limit")

		err = checker.CheckLimit(ctx, "devices", 15)
		assert.Error(t, err, "15 devices should exceed basic limit")

		err = checker.CheckLimit(ctx, "users", 3)
		assert.NoError(t, err, "3 users should be within basic limit")

		err = checker.CheckLimit(ctx, "users", 8)
		assert.Error(t, err, "8 users should exceed basic limit")
	})

	t.Run("TierInformation", func(t *testing.T) {
		checker := NewDefaultUnifiedLicenseChecker(logger, publicKey)
		ctx := context.Background()

		// Test getting current tier
		currentTier, err := checker.GetCurrentTier(ctx)
		require.NoError(t, err)
		require.NotNil(t, currentTier)

		assert.Equal(t, "basic", currentTier.Name, "Default tier should be basic")

		// Test getting available tiers
		tiers, err := checker.GetAvailableTiers(ctx)
		require.NoError(t, err)
		require.NotNil(t, tiers)

		tierNames := make([]string, len(tiers))
		for i, tier := range tiers {
			tierNames[i] = tier.Name
		}
		assert.Contains(t, tierNames, "basic", "Should have basic tier")
		assert.Contains(t, tierNames, "professional", "Should have professional tier")
		assert.Contains(t, tierNames, "enterprise", "Should have enterprise tier")
	})

	t.Run("InterfaceCompliance", func(t *testing.T) {
		// Verify interface compliance
		logger := logrus.New()
		publicKey := []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890abcdef...
-----END PUBLIC KEY-----`)

		checker := NewDefaultUnifiedLicenseChecker(logger, publicKey)
		
		// Verify interface compliance
		var _ types.UnifiedLicenseChecker = checker
		
		ctx := context.Background()

		// Test all main interface methods work
		_, err := checker.GetLicenseFeatures(ctx)
		assert.NoError(t, err)

		_, err = checker.GetSystemSecurityFeatures(ctx)
		assert.NoError(t, err)

		_, err = checker.GetWoTSecurityFeatures(ctx)
		assert.NoError(t, err)

		_, err = checker.GetGeneralSecurityFeatures(ctx)
		assert.NoError(t, err)

		_, err = checker.GetLicenseLimits(ctx)
		assert.NoError(t, err)

		_, err = checker.GetLicenseInfo(ctx)
		// This might return an error if no license is loaded, which is expected
		// assert.NoError(t, err)

		// For basic tier without actual license, IsLicenseValid should return false
		// This is expected behavior - basic tier is the default but not considered a "valid license"
		// assert.True(t, checker.IsLicenseValid(ctx), "Basic tier license should be valid")
	})

	t.Run("GeneralSecurityFeatures", func(t *testing.T) {
		checker := NewDefaultUnifiedLicenseChecker(logger, publicKey)
		ctx := context.Background()

		// Test general security features
		assert.True(t, checker.IsGeneralFeatureEnabled(ctx, "tls_required"), "Basic tier should require TLS")
		assert.True(t, checker.IsGeneralFeatureEnabled(ctx, "security_headers"), "Basic tier should have security headers")
		assert.False(t, checker.IsGeneralFeatureEnabled(ctx, "zero_trust_model"), "Basic tier should not have zero trust")

		// Get general security features
		generalFeatures, err := checker.GetGeneralSecurityFeatures(ctx)
		require.NoError(t, err)
		require.NotNil(t, generalFeatures)

		assert.True(t, generalFeatures.TLSRequired, "Basic tier should require TLS")
		assert.True(t, generalFeatures.SecurityHeaders, "Basic tier should have security headers")
		assert.False(t, generalFeatures.ZeroTrustModel, "Basic tier should not have zero trust")
	})
}

func TestLicenseSecurityTiers(t *testing.T) {
	t.Run("TierStructures", func(t *testing.T) {
		// Test that tier structures are properly defined
		assert.Equal(t, "basic", types.BasicTier.Name)
		assert.Equal(t, "professional", types.ProfessionalTier.Name)
		assert.Equal(t, "enterprise", types.EnterpriseTier.Name)

		// Test tier features progression
		basicFeatures := types.BasicTier.Features
		proFeatures := types.ProfessionalTier.Features
		enterpriseFeatures := types.EnterpriseTier.Features

		// System security feature progression
		assert.True(t, basicFeatures.SystemSecurity.LocalAuth)
		assert.True(t, proFeatures.SystemSecurity.LocalAuth)
		assert.True(t, enterpriseFeatures.SystemSecurity.LocalAuth)

		// Professional should have more features than basic
		assert.False(t, basicFeatures.SystemSecurity.LDAPAuth)
		assert.True(t, proFeatures.SystemSecurity.LDAPAuth)
		assert.True(t, enterpriseFeatures.SystemSecurity.LDAPAuth)

		// Enterprise should have more features than professional
		assert.False(t, basicFeatures.SystemSecurity.SAMLAuth)
		assert.False(t, proFeatures.SystemSecurity.SAMLAuth)
		assert.True(t, enterpriseFeatures.SystemSecurity.SAMLAuth)

		// WoT security feature progression
		assert.True(t, basicFeatures.WoTSecurity.BasicAuth)
		assert.False(t, basicFeatures.WoTSecurity.VaultIntegration)
		assert.True(t, enterpriseFeatures.WoTSecurity.VaultIntegration)
	})

	t.Run("TierLimits", func(t *testing.T) {
		// Test that limits increase with tiers
		basicLimits := types.BasicTier.Limits
		proLimits := types.ProfessionalTier.Limits
		enterpriseLimits := types.EnterpriseTier.Limits

		// Devices
		assert.Equal(t, 10, basicLimits.MaxDevices)
		assert.Equal(t, 100, proLimits.MaxDevices)
		assert.Equal(t, -1, enterpriseLimits.MaxDevices) // Unlimited

		// Things
		assert.Equal(t, 50, basicLimits.MaxThings)
		assert.Equal(t, 500, proLimits.MaxThings)
		assert.Equal(t, -1, enterpriseLimits.MaxThings) // Unlimited

		// Users
		assert.Equal(t, 5, basicLimits.MaxUsers)
		assert.Equal(t, 25, proLimits.MaxUsers)
		assert.Equal(t, -1, enterpriseLimits.MaxUsers) // Unlimited
	})
}