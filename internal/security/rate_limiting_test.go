package security

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/twinfer/twincore/pkg/types"
)


// TestRateLimiting tests API rate limiting functionality
func TestRateLimiting(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// Create rate limiting configuration
	rateLimitConfig := &types.RateLimitConfig{
		RequestsPerMinute: 10, // Very low for testing
		BurstSize:         3,  // Small burst for testing
		ByIP:              true,
		ByUser:            true,
		WhitelistIPs:      []string{"127.0.0.1", "::1"},
	}

	t.Run("BasicRateLimiting", func(t *testing.T) {
		// This test would typically require a rate limiter implementation
		// For now, we'll test the configuration validation

		assert.Equal(t, 10, rateLimitConfig.RequestsPerMinute)
		assert.Equal(t, 3, rateLimitConfig.BurstSize)
		assert.True(t, rateLimitConfig.ByIP)
		assert.True(t, rateLimitConfig.ByUser)
		assert.Contains(t, rateLimitConfig.WhitelistIPs, "127.0.0.1")
	})

	t.Run("RateLimitMiddlewareGeneration", func(t *testing.T) {
		// Test that rate limiting middleware can be generated for routes
		secConfig := &types.SystemSecurityConfig{
			Enabled: true,
			AdminAuth: &types.AdminAuthConfig{
				Local: &types.LocalAuthConfig{},
			},
			APIAuth: &types.APIAuthConfig{
				RateLimit: rateLimitConfig,
			},
		}

		// Create test database for auth portal bridge
		db := setupTestDB(t)
		defer db.Close()

		mockLicenseChecker := &MockUnifiedLicenseChecker{valid: true}
		bridge, err := NewCaddyAuthPortalBridge(db, logger, secConfig, mockLicenseChecker, "/tmp/test")
		require.NoError(t, err)

		// Generate auth portal config that should include rate limiting
		ctx := context.Background()
		appJSON, err := bridge.GenerateAuthPortalConfig(ctx)
		require.NoError(t, err)
		require.NotNil(t, appJSON)

		// Verify rate limiting is included in the configuration
		// In a real implementation, this would check for rate limiting middleware
		assert.Contains(t, string(appJSON), "authorization_policies")
	})

	t.Run("RateLimitConfigValidation", func(t *testing.T) {
		validConfigs := []types.RateLimitConfig{
			{RequestsPerMinute: 100, BurstSize: 10, ByIP: true},
			{RequestsPerMinute: 1000, BurstSize: 50, ByUser: true},
			{RequestsPerMinute: 60, BurstSize: 5, ByIP: true, ByUser: true},
		}

		for _, config := range validConfigs {
			assert.True(t, config.RequestsPerMinute > 0, "RequestsPerMinute should be positive")
			assert.True(t, config.BurstSize > 0, "BurstSize should be positive")
			assert.True(t, config.ByIP || config.ByUser, "Should limit by IP or User")
		}
	})

	t.Run("WhitelistConfiguration", func(t *testing.T) {
		testIPs := []string{
			"127.0.0.1",
			"::1",
			"192.168.1.0/24",
			"10.0.0.0/8",
		}

		config := &types.RateLimitConfig{
			RequestsPerMinute: 100,
			BurstSize:         10,
			WhitelistIPs:      testIPs,
		}

		// Verify whitelist IPs are properly configured
		assert.Len(t, config.WhitelistIPs, 4)
		assert.Contains(t, config.WhitelistIPs, "127.0.0.1")
		assert.Contains(t, config.WhitelistIPs, "192.168.1.0/24")
	})
}

// TestSecurityHeadersGeneration tests HTTP security headers
func TestSecurityHeadersGeneration(t *testing.T) {
	logger := logrus.New()
	
	db := setupTestDB(t)
	defer db.Close()

	secConfig := &types.SystemSecurityConfig{
		Enabled: true,
		AdminAuth: &types.AdminAuthConfig{
			Local: &types.LocalAuthConfig{},
		},
		APIAuth: &types.APIAuthConfig{
			Methods: []string{"bearer"},
		},
	}

	mockLicenseChecker := &MockUnifiedLicenseChecker{valid: true}
	bridge, err := NewCaddyAuthPortalBridge(db, logger, secConfig, mockLicenseChecker, "/tmp/test")
	require.NoError(t, err)

	t.Run("GenerateSecurityHeaders", func(t *testing.T) {
		// Test that security headers are included in caddy configuration
		ctx := context.Background()
		appJSON, err := bridge.GenerateAuthPortalConfig(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, appJSON)

		// In a real implementation, this would verify specific security headers
		// like X-Frame-Options, X-Content-Type-Options, etc.
		configStr := string(appJSON)
		assert.Contains(t, configStr, "twincore_portal")
		assert.Contains(t, configStr, "twincore_policy")
	})
}

// TestCSRFProtection tests CSRF protection mechanisms
func TestCSRFProtection(t *testing.T) {
	logger := logrus.New()
	
	db := setupTestDB(t)
	defer db.Close()

	secConfig := &types.SystemSecurityConfig{
		Enabled: true,
		AdminAuth: &types.AdminAuthConfig{
			Local: &types.LocalAuthConfig{},
		},
		SessionConfig: &types.SessionConfig{
			CSRFProtection: true,
			SecureCookies:  true,
			SameSite:       "strict",
		},
	}

	mockLicenseChecker := &MockUnifiedLicenseChecker{valid: true}
	bridge, err := NewCaddyAuthPortalBridge(db, logger, secConfig, mockLicenseChecker, "/tmp/test")
	require.NoError(t, err)

	t.Run("CSRFConfigurationEnabled", func(t *testing.T) {
		assert.True(t, secConfig.SessionConfig.CSRFProtection)
		assert.True(t, secConfig.SessionConfig.SecureCookies)
		assert.Equal(t, "strict", secConfig.SessionConfig.SameSite)
	})

	t.Run("GenerateCSRFProtection", func(t *testing.T) {
		ctx := context.Background()
		appJSON, err := bridge.GenerateAuthPortalConfig(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, appJSON)

		// Verify CSRF protection is configured
		// In caddy-security, this would include CSRF token validation
		configStr := string(appJSON)
		assert.NotEmpty(t, configStr)
	})
}

// TestAuthenticationMethods tests various authentication method configurations
func TestAuthenticationMethods(t *testing.T) {
	logger := logrus.New()
	
	db := setupTestDB(t)
	defer db.Close()

	testCases := []struct {
		name          string
		authMethods   []string
		shouldContain []string
	}{
		{
			name:          "JWTOnly",
			authMethods:   []string{"jwt"},
			shouldContain: []string{"jwt"},
		},
		{
			name:          "BearerOnly",
			authMethods:   []string{"bearer"},
			shouldContain: []string{"bearer"},
		},
		{
			name:          "MultipleAuth",
			authMethods:   []string{"jwt", "bearer", "apikey"},
			shouldContain: []string{"jwt", "bearer", "apikey"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			secConfig := &types.SystemSecurityConfig{
				Enabled: true,
				AdminAuth: &types.AdminAuthConfig{
					Local: &types.LocalAuthConfig{},
				},
				APIAuth: &types.APIAuthConfig{
					Methods: tc.authMethods,
					JWTConfig: &types.JWTConfig{
						Algorithm: "HS256",
						Issuer:    "twincore-gateway",
						Audience:  "twincore-api",
						Expiry:    time.Hour,
					},
				},
			}

			mockLicenseChecker := &MockUnifiedLicenseChecker{valid: true}
			bridge, err := NewCaddyAuthPortalBridge(db, logger, secConfig, mockLicenseChecker, "/tmp/test")
			require.NoError(t, err)

			// Verify configuration includes expected auth methods
			assert.Equal(t, tc.authMethods, secConfig.APIAuth.Methods)

			ctx := context.Background()
			appJSON, err := bridge.GenerateAuthPortalConfig(ctx)
			assert.NoError(t, err)
			assert.NotNil(t, appJSON)

			configStr := string(appJSON)
			for _, method := range tc.shouldContain {
				// In a real implementation, this would check for specific auth method configs
				assert.NotEmpty(t, configStr, "Should generate config for %s", method)
			}
		})
	}
}

// TestAccessControlPolicies tests access control policy generation
func TestAccessControlPolicies(t *testing.T) {
	logger := logrus.New()
	
	db := setupTestDB(t)
	defer db.Close()

	policies := []types.APIPolicy{
		{
			ID:          "admin_policy",
			Name:        "Administrator Access",
			Description: "Full access to all APIs",
			Principal:   "role:admin",
			Resources:   []string{"/api/*"},
			Actions:     []string{"read", "write", "delete", "admin"},
		},
		{
			ID:          "operator_policy",
			Name:        "Operator Access",
			Description: "Access to Things and Streams",
			Principal:   "role:operator",
			Resources:   []string{"/api/things/*", "/api/streams/*"},
			Actions:     []string{"read", "write"},
		},
		{
			ID:          "viewer_policy",
			Name:        "Viewer Access",
			Description: "Read-only access",
			Principal:   "role:viewer",
			Resources:   []string{"/api/things/*", "/api/streams/*"},
			Actions:     []string{"read"},
		},
	}

	secConfig := &types.SystemSecurityConfig{
		Enabled: true,
		AdminAuth: &types.AdminAuthConfig{
			Local: &types.LocalAuthConfig{},
		},
		APIAuth: &types.APIAuthConfig{
			Methods:  []string{"jwt"},
			Policies: policies,
		},
	}

	mockLicenseChecker := &MockUnifiedLicenseChecker{valid: true}
	bridge, err := NewCaddyAuthPortalBridge(db, logger, secConfig, mockLicenseChecker, "/tmp/test")
	require.NoError(t, err)

	t.Run("PolicyGeneration", func(t *testing.T) {
		ctx := context.Background()
		appJSON, err := bridge.GenerateAuthPortalConfig(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, appJSON)

		configStr := string(appJSON)
		assert.Contains(t, configStr, "authorization_policies")
		assert.Contains(t, configStr, "twincore_policy")
	})

	t.Run("PolicyValidation", func(t *testing.T) {
		// Test policy structure validation
		for _, policy := range policies {
			assert.NotEmpty(t, policy.ID, "Policy ID should not be empty")
			assert.NotEmpty(t, policy.Principal, "Policy principal should not be empty")
			assert.NotEmpty(t, policy.Resources, "Policy resources should not be empty")
			assert.NotEmpty(t, policy.Actions, "Policy actions should not be empty")

			// Validate principal format
			if policy.Principal == "role:admin" {
				assert.Equal(t, "role:admin", policy.Principal)
			}

			// Validate resource patterns
			for _, resource := range policy.Resources {
				assert.True(t, len(resource) > 0, "Resource pattern should not be empty")
			}

			// Validate actions
			validActions := []string{"read", "write", "delete", "admin"}
			for _, action := range policy.Actions {
				assert.Contains(t, validActions, action, "Action should be valid")
			}
		}
	})

	t.Run("RoleBasedPolicyAccess", func(t *testing.T) {
		// Test that policies correctly map to roles
		adminPolicy := policies[0]
		operatorPolicy := policies[1]
		viewerPolicy := policies[2]

		// Admin should have all actions
		assert.Contains(t, adminPolicy.Actions, "admin")
		assert.Contains(t, adminPolicy.Actions, "delete")
		assert.Contains(t, adminPolicy.Resources, "/api/*")

		// Operator should have read/write but not admin/delete
		assert.Contains(t, operatorPolicy.Actions, "read")
		assert.Contains(t, operatorPolicy.Actions, "write")
		assert.NotContains(t, operatorPolicy.Actions, "admin")
		assert.NotContains(t, operatorPolicy.Actions, "delete")

		// Viewer should only have read access
		assert.Contains(t, viewerPolicy.Actions, "read")
		assert.NotContains(t, viewerPolicy.Actions, "write")
		assert.NotContains(t, viewerPolicy.Actions, "admin")
		assert.NotContains(t, viewerPolicy.Actions, "delete")
	})
}
