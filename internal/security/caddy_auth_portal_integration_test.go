package security

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/twinfer/twincore/pkg/types"
	_ "github.com/marcboeker/go-duckdb"
)

// MockUnifiedLicenseChecker for testing
type MockUnifiedLicenseChecker struct {
	features map[string]bool
	valid    bool
}

func (m *MockUnifiedLicenseChecker) IsSystemFeatureEnabled(ctx context.Context, feature string) bool {
	if m.features == nil {
		return true // Default to enabled for tests
	}
	return m.features[feature]
}

func (m *MockUnifiedLicenseChecker) IsWoTFeatureEnabled(ctx context.Context, feature string) bool {
	return m.IsSystemFeatureEnabled(ctx, feature)
}

func (m *MockUnifiedLicenseChecker) IsGeneralFeatureEnabled(ctx context.Context, feature string) bool {
	return m.IsSystemFeatureEnabled(ctx, feature)
}

func (m *MockUnifiedLicenseChecker) IsLicenseValid(ctx context.Context) bool {
	return m.valid
}

func (m *MockUnifiedLicenseChecker) ValidateLicense(ctx context.Context, licenseData string) (*types.LicenseSecurityFeatures, error) {
	return &types.LicenseSecurityFeatures{}, nil
}

func (m *MockUnifiedLicenseChecker) GetLicenseFeatures(ctx context.Context) (*types.LicenseSecurityFeatures, error) {
	return &types.LicenseSecurityFeatures{}, nil
}

func (m *MockUnifiedLicenseChecker) GetLicenseExpiry(ctx context.Context) (time.Time, error) {
	return time.Now().Add(time.Hour), nil
}

func (m *MockUnifiedLicenseChecker) GetSystemSecurityFeatures(ctx context.Context) (*types.SystemSecurityFeatures, error) {
	return &types.SystemSecurityFeatures{}, nil
}

func (m *MockUnifiedLicenseChecker) ValidateSystemOperation(ctx context.Context, operation string) error {
	return nil
}

func (m *MockUnifiedLicenseChecker) GetWoTSecurityFeatures(ctx context.Context) (*types.WoTSecurityFeatures, error) {
	return &types.WoTSecurityFeatures{}, nil
}

func (m *MockUnifiedLicenseChecker) ValidateWoTOperation(ctx context.Context, operation string) error {
	return nil
}

func (m *MockUnifiedLicenseChecker) ValidateSecurityScheme(ctx context.Context, scheme string) error {
	return nil
}

func (m *MockUnifiedLicenseChecker) GetGeneralSecurityFeatures(ctx context.Context) (*types.GeneralSecurityFeatures, error) {
	return &types.GeneralSecurityFeatures{}, nil
}

func (m *MockUnifiedLicenseChecker) GetLicenseLimits(ctx context.Context) (*types.LicenseLimits, error) {
	return &types.LicenseLimits{}, nil
}

func (m *MockUnifiedLicenseChecker) CheckLimit(ctx context.Context, limitType string, currentUsage int) error {
	return nil
}

func (m *MockUnifiedLicenseChecker) GetUsageStats(ctx context.Context) (map[string]int, error) {
	return map[string]int{}, nil
}

func (m *MockUnifiedLicenseChecker) ReloadLicense(ctx context.Context) error {
	return nil
}

func (m *MockUnifiedLicenseChecker) GetLicenseInfo(ctx context.Context) (*types.LicenseInfo, error) {
	return &types.LicenseInfo{}, nil
}

func (m *MockUnifiedLicenseChecker) ValidateLicenseForUpgrade(ctx context.Context, newLicenseData string) error {
	return nil
}

func (m *MockUnifiedLicenseChecker) GetAvailableTiers(ctx context.Context) ([]types.LicenseTier, error) {
	return []types.LicenseTier{}, nil
}

func (m *MockUnifiedLicenseChecker) GetCurrentTier(ctx context.Context) (*types.LicenseTier, error) {
	return &types.LicenseTier{}, nil
}

func (m *MockUnifiedLicenseChecker) CompareTiers(ctx context.Context, currentTier, targetTier string) (*types.TierComparison, error) {
	return &types.TierComparison{}, nil
}

// MockConfigManager for testing
type MockConfigManager struct {
	appliedConfigs map[string]json.RawMessage
}

func (m *MockConfigManager) UpdateCaddyConfig(logger logrus.FieldLogger, path string, config any) error {
	if m.appliedConfigs == nil {
		m.appliedConfigs = make(map[string]json.RawMessage)
	}
	
	configBytes, err := json.Marshal(config)
	if err != nil {
		return err
	}
	
	m.appliedConfigs[path] = json.RawMessage(configBytes)
	return nil
}

func (m *MockConfigManager) GetAppliedConfig(path string) json.RawMessage {
	return m.appliedConfigs[path]
}

// Test setup helpers

func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("duckdb", ":memory:")
	require.NoError(t, err)

	// Create test schema
	schema := `
	CREATE TABLE IF NOT EXISTS local_users (
		username TEXT PRIMARY KEY,
		password_hash TEXT NOT NULL,
		roles TEXT,
		email TEXT,
		name TEXT,
		disabled BOOLEAN DEFAULT FALSE,
		last_login TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	_, err = db.Exec(schema)
	require.NoError(t, err)

	return db
}

func createTestUser(t *testing.T, db *sql.DB, username, email, name string, roles []string) {
	rolesJSON, _ := json.Marshal(roles)
	_, err := db.Exec(`
		INSERT INTO local_users (username, password_hash, email, name, roles, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, username, "$2a$10$testhashedpassword", email, name, string(rolesJSON), time.Now(), time.Now())
	require.NoError(t, err)
}

// TestLocalIdentityStore tests the local identity store functionality
func TestLocalIdentityStore(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Reduce test noise

	store := NewLocalIdentityStore(db, logger, "test_store")

	t.Run("GetName", func(t *testing.T) {
		assert.Equal(t, "test_store", store.GetName())
	})

	t.Run("GetType", func(t *testing.T) {
		assert.Equal(t, "local", store.GetType())
	})

	t.Run("Validate", func(t *testing.T) {
		err := store.Validate()
		assert.NoError(t, err)
	})

	t.Run("CreateUser", func(t *testing.T) {
		user := &AuthUser{
			Username: "testuser",
			Email:    "test@example.com",
			FullName: "Test User",
			Roles:    []string{"viewer"},
		}

		err := store.CreateUser(context.Background(), user, "testpassword")
		assert.NoError(t, err)
	})

	t.Run("GetUser", func(t *testing.T) {
		user, err := store.GetUser(context.Background(), "testuser")
		require.NoError(t, err)
		assert.Equal(t, "testuser", user.Username)
		assert.Equal(t, "test@example.com", user.Email)
		assert.Equal(t, "Test User", user.FullName)
		assert.Equal(t, []string{"viewer"}, user.Roles)
		assert.False(t, user.Disabled)
	})

	t.Run("ValidateUser", func(t *testing.T) {
		user, err := store.ValidateUser(context.Background(), "testuser", "testpassword")
		require.NoError(t, err)
		assert.Equal(t, "testuser", user.Username)
	})

	t.Run("UpdateUser", func(t *testing.T) {
		updates := map[string]any{
			"email": "updated@example.com",
			"roles": []string{"operator"},
		}

		err := store.UpdateUser(context.Background(), "testuser", updates)
		assert.NoError(t, err)

		// Verify update
		user, err := store.GetUser(context.Background(), "testuser")
		require.NoError(t, err)
		assert.Equal(t, "updated@example.com", user.Email)
		assert.Equal(t, []string{"operator"}, user.Roles)
	})

	t.Run("ListUsers", func(t *testing.T) {
		users, err := store.ListUsers(context.Background())
		require.NoError(t, err)
		assert.Len(t, users, 1)
		assert.Equal(t, "testuser", users[0].Username)
	})

	t.Run("DeleteUser", func(t *testing.T) {
		err := store.DeleteUser(context.Background(), "testuser")
		assert.NoError(t, err)

		// Verify deletion
		_, err = store.GetUser(context.Background(), "testuser")
		assert.Error(t, err)
	})
}

// TestCaddyAuthPortalBridge tests the auth portal bridge functionality
func TestCaddyAuthPortalBridge(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Reduce test noise

	// Create test data
	createTestUser(t, db, "admin", "admin@example.com", "Admin User", []string{"admin"})
	createTestUser(t, db, "operator", "operator@example.com", "Operator User", []string{"operator"})

	licenseChecker := &MockUnifiedLicenseChecker{
		features: map[string]bool{
			"local_auth": true,
			"ldap_auth":  false,
		},
		valid: true,
	}

	config := &types.SystemSecurityConfig{
		Enabled: true,
		AdminAuth: &types.AdminAuthConfig{
			Local: &types.LocalAuthConfig{
				PasswordPolicy: &types.PasswordPolicy{
					MinLength:        8,
					RequireUppercase: true,
					RequireLowercase: true,
					RequireNumbers:   true,
					RequireSymbols:   false,
				},
			},
		},
		APIAuth: &types.APIAuthConfig{
			JWTConfig: &types.JWTConfig{
				Algorithm: "HS256",
				Issuer:    "twincore-gateway",
				Audience:  "twincore-api",
				Expiry:    time.Hour,
			},
		},
		SessionConfig: &types.SessionConfig{
			Timeout: 3600,
		},
	}

	bridge, err := NewCaddyAuthPortalBridge(db, logger, config, licenseChecker, "/tmp/test")
	require.NoError(t, err)

	t.Run("ValidateConfiguration", func(t *testing.T) {
		err := bridge.ValidateConfiguration()
		assert.NoError(t, err)
	})

	t.Run("GenerateAuthPortalConfig", func(t *testing.T) {
		configJSON, err := bridge.GenerateAuthPortalConfig(context.Background())
		require.NoError(t, err)
		assert.NotNil(t, configJSON)

		// Parse and validate structure
		var config map[string]any
		err = json.Unmarshal(configJSON, &config)
		require.NoError(t, err)

		// Check for required sections
		assert.Contains(t, config, "authentication_portals")
		assert.Contains(t, config, "authorization_policies")
		assert.Contains(t, config, "identity_stores")
		assert.Contains(t, config, "crypto_key")

		// Validate portal config
		portals := config["authentication_portals"].(map[string]any)
		assert.Contains(t, portals, "twincore_portal")

		// Validate identity store config
		stores := config["identity_stores"].(map[string]any)
		assert.Contains(t, stores, "twincore_local")
	})

	t.Run("ApplyAuthConfiguration", func(t *testing.T) {
		mockConfigMgr := &MockConfigManager{}
		bridge.SetConfigManager(mockConfigMgr)

		err := bridge.ApplyAuthConfiguration(context.Background())
		assert.NoError(t, err)

		// Verify config was applied
		appliedConfig := mockConfigMgr.GetAppliedConfig("/apps/security")
		assert.NotNil(t, appliedConfig)
	})

	t.Run("GetIdentityStore", func(t *testing.T) {
		store := bridge.GetIdentityStore()
		assert.NotNil(t, store)
		assert.Equal(t, "twincore_local", store.GetName())
	})
}

// TestSimplifiedSystemSecurityManager tests the simplified security manager
func TestSimplifiedSystemSecurityManager(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Reduce test noise

	licenseChecker := &MockUnifiedLicenseChecker{
		features: map[string]bool{
			"local_auth": true,
		},
		valid: true,
	}

	manager := NewSimplifiedSystemSecurityManager(db, logger, licenseChecker)

	// Configure security
	config := types.SystemSecurityConfig{
		Enabled: true,
		AdminAuth: &types.AdminAuthConfig{
			Local: &types.LocalAuthConfig{
				PasswordPolicy: &types.PasswordPolicy{
					MinLength:        8,
					RequireUppercase: true,
					RequireLowercase: true,
					RequireNumbers:   true,
					RequireSymbols:   false,
				},
			},
		},
	}
	err := manager.UpdateConfig(context.Background(), config)
	require.NoError(t, err)

	t.Run("CreateUser", func(t *testing.T) {
		user := &types.User{
			ID:       "testuser",
			Username: "testuser",
			Email:    "test@example.com",
			FullName: "Test User",
			Roles:    []string{"viewer"},
		}

		err := manager.CreateUser(context.Background(), user, "TestPass123")
		assert.NoError(t, err)
	})

	t.Run("GetUser", func(t *testing.T) {
		user, err := manager.GetUser(context.Background(), "testuser")
		require.NoError(t, err)
		assert.Equal(t, "testuser", user.Username)
		assert.Equal(t, "test@example.com", user.Email)
		assert.Equal(t, []string{"viewer"}, user.Roles)
	})

	t.Run("ListUsers", func(t *testing.T) {
		users, err := manager.ListUsers(context.Background())
		require.NoError(t, err)
		assert.Len(t, users, 1)
		assert.Equal(t, "testuser", users[0].Username)
	})

	t.Run("UpdateUser", func(t *testing.T) {
		updates := map[string]any{
			"email": "updated@example.com",
			"roles": []string{"operator"},
		}

		err := manager.UpdateUser(context.Background(), "testuser", updates)
		assert.NoError(t, err)

		// Verify update
		user, err := manager.GetUser(context.Background(), "testuser")
		require.NoError(t, err)
		assert.Equal(t, "updated@example.com", user.Email)
		assert.Equal(t, []string{"operator"}, user.Roles)
	})

	t.Run("AuthorizeAPIAccess", func(t *testing.T) {
		user := &types.User{
			Username: "testuser",
			Roles:    []string{"admin"},
		}

		// Admin should have access to everything
		err := manager.AuthorizeAPIAccess(context.Background(), user, "/api/admin/users", "write")
		assert.NoError(t, err)

		// Operator should not have access to admin endpoints
		user.Roles = []string{"operator"}
		err = manager.AuthorizeAPIAccess(context.Background(), user, "/api/admin/users", "write")
		assert.Error(t, err)

		// Viewer should only have read access to non-admin endpoints
		user.Roles = []string{"viewer"}
		err = manager.AuthorizeAPIAccess(context.Background(), user, "/api/things", "read")
		assert.NoError(t, err)

		err = manager.AuthorizeAPIAccess(context.Background(), user, "/api/things", "write")
		assert.Error(t, err)
	})

	t.Run("HealthCheck", func(t *testing.T) {
		err := manager.HealthCheck(context.Background())
		assert.NoError(t, err)
	})

	t.Run("GetSecurityMetrics", func(t *testing.T) {
		metrics, err := manager.GetSecurityMetrics(context.Background())
		require.NoError(t, err)

		assert.Contains(t, metrics, "total_users")
		assert.Contains(t, metrics, "security_enabled")
		assert.Contains(t, metrics, "license_valid")
		assert.Contains(t, metrics, "auth_provider")
		assert.Equal(t, "caddy-auth-portal", metrics["auth_provider"])
		assert.Equal(t, true, metrics["security_enabled"])
		assert.Equal(t, true, metrics["license_valid"])
	})

	t.Run("DeleteUser", func(t *testing.T) {
		err := manager.DeleteUser(context.Background(), "testuser")
		assert.NoError(t, err)

		// Verify deletion
		_, err = manager.GetUser(context.Background(), "testuser")
		assert.Error(t, err)
	})
}

// TestIntegrationFlow tests the complete integration flow
func TestIntegrationFlow(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Reduce test noise

	licenseChecker := &MockUnifiedLicenseChecker{
		features: map[string]bool{
			"local_auth": true,
			"ldap_auth":  false,
		},
		valid: true,
	}

	// Create system security manager
	securityManager := NewSimplifiedSystemSecurityManager(db, logger, licenseChecker)

	// Configure security
	config := types.SystemSecurityConfig{
		Enabled: true,
		AdminAuth: &types.AdminAuthConfig{
			Local: &types.LocalAuthConfig{
				PasswordPolicy: &types.PasswordPolicy{
					MinLength:        8,
					RequireUppercase: true,
					RequireLowercase: true,
					RequireNumbers:   true,
					RequireSymbols:   false,
				},
			},
		},
		APIAuth: &types.APIAuthConfig{
			JWTConfig: &types.JWTConfig{
				Algorithm: "HS256",
				Issuer:    "twincore-gateway",
				Audience:  "twincore-api",
				Expiry:    time.Hour,
			},
		},
	}
	err := securityManager.UpdateConfig(context.Background(), config)
	require.NoError(t, err)

	// Create auth portal bridge
	authBridge, err := NewCaddyAuthPortalBridge(db, logger, &config, licenseChecker, "/tmp/test")
	require.NoError(t, err)

	mockConfigMgr := &MockConfigManager{}
	authBridge.SetConfigManager(mockConfigMgr)

	t.Run("CompleteIntegrationFlow", func(t *testing.T) {
		// 1. Create a user through security manager
		user := &types.User{
			ID:       "integrationuser",
			Username: "integrationuser",
			Email:    "integration@example.com",
			FullName: "Integration Test User",
			Roles:    []string{"admin"},
		}

		err := securityManager.CreateUser(context.Background(), user, "IntegrationPass123")
		assert.NoError(t, err)

		// 2. Verify user exists in identity store
		identityStore := authBridge.GetIdentityStore()
		authUser, err := identityStore.GetUser(context.Background(), "integrationuser")
		require.NoError(t, err)
		assert.Equal(t, "integrationuser", authUser.Username)
		assert.Equal(t, []string{"admin"}, authUser.Roles)

		// 3. Validate user credentials through identity store
		validatedUser, err := identityStore.ValidateUser(context.Background(), "integrationuser", "IntegrationPass123")
		require.NoError(t, err)
		assert.Equal(t, "integrationuser", validatedUser.Username)

		// 4. Generate and apply caddy-auth-portal configuration
		err = authBridge.ApplyAuthConfiguration(context.Background())
		assert.NoError(t, err)

		// 5. Verify configuration was applied
		appliedConfig := mockConfigMgr.GetAppliedConfig("/apps/security")
		assert.NotNil(t, appliedConfig)

		// 6. Parse and validate the applied configuration
		var authConfig map[string]any
		err = json.Unmarshal(appliedConfig, &authConfig)
		require.NoError(t, err)

		// Verify structure
		assert.Contains(t, authConfig, "authentication_portals")
		assert.Contains(t, authConfig, "authorization_policies")
		assert.Contains(t, authConfig, "identity_stores")

		// 7. Test authorization through security manager
		err = securityManager.AuthorizeAPIAccess(context.Background(), user, "/api/admin/config", "write")
		assert.NoError(t, err, "Admin should have access to admin endpoints")

		// 8. Clean up
		err = securityManager.DeleteUser(context.Background(), "integrationuser")
		assert.NoError(t, err)
	})
}

// TestErrorHandling tests error handling scenarios
func TestErrorHandling(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Reduce test noise

	t.Run("InvalidDatabase", func(t *testing.T) {
		// This test verifies error handling with invalid database
		db, _ := sql.Open("duckdb", ":memory:")
		db.Close() // Close immediately to simulate error
		
		store := NewLocalIdentityStore(db, logger, "test")
		_, err := store.GetUser(context.Background(), "nonexistent")
		assert.Error(t, err)
	})

	t.Run("DisabledSecurity", func(t *testing.T) {
		db := setupTestDB(t)
		defer db.Close()

		licenseChecker := &MockUnifiedLicenseChecker{valid: true}
		config := &types.SystemSecurityConfig{
			Enabled: false, // Disabled
		}

		bridge, err := NewCaddyAuthPortalBridge(db, logger, config, licenseChecker, "/tmp/test")
		require.NoError(t, err)

		configJSON, err := bridge.GenerateAuthPortalConfig(context.Background())
		assert.NoError(t, err)
		assert.Nil(t, configJSON, "Should return nil config when security is disabled")
	})

	t.Run("UnlicensedFeatures", func(t *testing.T) {
		db := setupTestDB(t)
		defer db.Close()

		licenseChecker := &MockUnifiedLicenseChecker{
			features: map[string]bool{
				"local_auth": false, // Not licensed
			},
			valid: true,
		}

		manager := NewSimplifiedSystemSecurityManager(db, logger, licenseChecker)

		user := &types.User{
			Username: "testuser",
			Email:    "test@example.com",
			Roles:    []string{"viewer"},
		}

		err := manager.CreateUser(context.Background(), user, "password")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not licensed")
	})
}