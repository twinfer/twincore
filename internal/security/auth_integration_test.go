package security

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	_ "github.com/marcboeker/go-duckdb"
	"github.com/twinfer/twincore/pkg/types"
)

// AuthTestSuite contains comprehensive authentication tests
type AuthTestSuite struct {
	db        *sql.DB
	logger    *logrus.Logger
	sysSecMgr *DefaultSystemSecurityManager
	bridge    *CaddySecurityBridge
	config    *types.SystemSecurityConfig
}

func setupAuthTestSuite(t *testing.T) *AuthTestSuite {
	// Create in-memory database
	db, err := sql.Open("duckdb", ":memory:")
	require.NoError(t, err)

	// Run migrations
	err = runTestMigrations(db)
	require.NoError(t, err)

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// Create mock license checker that enables all features
	licenseChecker := &MockUnifiedLicenseChecker{}
	licenseChecker.EnableAllFeatures()

	// Create system security manager
	sysSecMgr := NewDefaultSystemSecurityManager(db, logger, licenseChecker)

	// Create comprehensive security config
	config := &types.SystemSecurityConfig{
		Enabled: true,
		AdminAuth: &types.AdminAuthConfig{
			Method:    "local",
			Providers: []string{"local"},
			MFA:       false,
			Local: &types.LocalAuthConfig{
				Users: []types.LocalUser{
					{
						Username:     "admin",
						PasswordHash: mustHashPassword("AdminPass123!"),
						Email:        "admin@twincore.local",
						FullName:     "System Administrator",
						Roles:        []string{"admin"},
						Disabled:     false,
					},
					{
						Username:     "operator",
						PasswordHash: mustHashPassword("OpPass456!"),
						Email:        "operator@twincore.local",
						FullName:     "System Operator",
						Roles:        []string{"operator"},
						Disabled:     false,
					},
					{
						Username:     "viewer",
						PasswordHash: mustHashPassword("ViewPass789!"),
						Email:        "viewer@twincore.local",
						FullName:     "Read Only User",
						Roles:        []string{"viewer"},
						Disabled:     false,
					},
					{
						Username:     "disabled_user",
						PasswordHash: mustHashPassword("DisabledPass123!"),
						Email:        "disabled@twincore.local",
						FullName:     "Disabled User",
						Roles:        []string{"viewer"},
						Disabled:     true,
					},
				},
				PasswordPolicy: &types.PasswordPolicy{
					MinLength:        8,
					RequireUppercase: true,
					RequireLowercase: true,
					RequireNumbers:   true,
					RequireSymbols:   true,
				},
				AccountLockout: &types.AccountLockoutPolicy{
					Enabled:         true,
					MaxAttempts:     3,
					LockoutDuration: 5 * time.Minute,
					ResetAfter:      15 * time.Minute,
				},
			},
		},
		APIAuth: &types.APIAuthConfig{
			Methods: []string{"bearer", "jwt"},
			JWTConfig: &types.JWTConfig{
				Algorithm:    "HS256",
				Issuer:       "twincore-gateway",
				Audience:     "twincore-api",
				Expiry:       time.Hour,
				RefreshToken: true,
			},
			Policies: []types.APIPolicy{
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
					Resources:   []string{"/api/things/*", "/api/streams/*", "/api/status"},
					Actions:     []string{"read"},
				},
			},
			RateLimit: &types.RateLimitConfig{
				RequestsPerMinute: 1000,
				BurstSize:         100,
				ByIP:              true,
				ByUser:            true,
			},
		},
		SessionConfig: &types.SessionConfig{
			Timeout:        time.Hour,
			MaxSessions:    5,
			SecureCookies:  true,
			SameSite:       "lax",
			CSRFProtection: true,
		},
	}

	// Update system security manager config
	err = sysSecMgr.UpdateConfig(context.Background(), *config)
	require.NoError(t, err)

	// Initialize test users in database
	err = initializeTestUsers(db, config.AdminAuth.Local.Users)
	require.NoError(t, err)

	// Create caddy-security bridge
	bridge := NewCaddySecurityBridge(sysSecMgr, config, logger)

	return &AuthTestSuite{
		db:        db,
		logger:    logger,
		sysSecMgr: sysSecMgr,
		bridge:    bridge,
		config:    config,
	}
}

func (suite *AuthTestSuite) cleanup() {
	if suite.db != nil {
		suite.db.Close()
	}
}

// TestLocalAuthentication tests local user authentication scenarios
func TestLocalAuthentication(t *testing.T) {
	suite := setupAuthTestSuite(t)
	defer suite.cleanup()

	ctx := context.Background()

	t.Run("ValidUserAuthentication", func(t *testing.T) {
		credentials := types.UserCredentials{
			Username: "admin",
			Password: "AdminPass123!",
		}

		session, err := suite.sysSecMgr.AuthenticateUser(ctx, credentials)
		require.NoError(t, err)
		require.NotNil(t, session)
		assert.Equal(t, "admin", session.Username)
		assert.NotEmpty(t, session.Token)
		assert.True(t, session.ExpiresAt.After(time.Now()))
	})

	t.Run("InvalidPassword", func(t *testing.T) {
		credentials := types.UserCredentials{
			Username: "admin",
			Password: "WrongPassword",
		}

		session, err := suite.sysSecMgr.AuthenticateUser(ctx, credentials)
		assert.Error(t, err)
		assert.Nil(t, session)
		assert.Contains(t, err.Error(), "authentication failed")
	})

	t.Run("NonExistentUser", func(t *testing.T) {
		credentials := types.UserCredentials{
			Username: "nonexistent",
			Password: "AnyPassword123!",
		}

		session, err := suite.sysSecMgr.AuthenticateUser(ctx, credentials)
		assert.Error(t, err)
		assert.Nil(t, session)
		assert.Contains(t, err.Error(), "authentication failed")
	})

	t.Run("DisabledUser", func(t *testing.T) {
		credentials := types.UserCredentials{
			Username: "disabled_user",
			Password: "DisabledPass123!",
		}

		session, err := suite.sysSecMgr.AuthenticateUser(ctx, credentials)
		assert.Error(t, err)
		assert.Nil(t, session)
		assert.Contains(t, err.Error(), "user account disabled")
	})
}

// TestJWTTokenGeneration tests JWT token creation and validation
func TestJWTTokenGeneration(t *testing.T) {
	suite := setupAuthTestSuite(t)
	defer suite.cleanup()

	ctx := context.Background()

	t.Run("CreateAndValidateJWTToken", func(t *testing.T) {
		// First authenticate to get a session
		credentials := types.UserCredentials{
			Username: "admin",
			Password: "AdminPass123!",
		}

		session, err := suite.sysSecMgr.AuthenticateUser(ctx, credentials)
		require.NoError(t, err)
		require.NotNil(t, session)

		// Validate the JWT token
		validatedSession, err := suite.sysSecMgr.ValidateSession(ctx, session.Token)
		assert.NoError(t, err)
		assert.NotNil(t, validatedSession)
		assert.Equal(t, session.ID, validatedSession.ID)
		assert.Equal(t, session.Username, validatedSession.Username)
	})

	t.Run("InvalidJWTToken", func(t *testing.T) {
		invalidToken := "invalid.jwt.token"

		session, err := suite.sysSecMgr.ValidateSession(ctx, invalidToken)
		assert.Error(t, err)
		assert.Nil(t, session)
	})

	t.Run("ExpiredJWTToken", func(t *testing.T) {
		// Create a token with immediate expiry
		user := &types.User{
			ID:       "test",
			Username: "admin",
			Roles:    []string{"admin"},
		}

		// Create JWT token that expires immediately
		claims := jwt.MapClaims{
			"sub":      user.ID,
			"username": user.Username,
			"roles":    user.Roles,
			"iss":      suite.config.APIAuth.JWTConfig.Issuer,
			"aud":      suite.config.APIAuth.JWTConfig.Audience,
			"exp":      time.Now().Add(-time.Hour).Unix(), // Expired
			"iat":      time.Now().Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signedToken, err := token.SignedString(suite.sysSecMgr.jwtSecret)
		require.NoError(t, err)

		// Try to validate expired token
		session, err := suite.sysSecMgr.ValidateSession(ctx, signedToken)
		assert.Error(t, err)
		assert.Nil(t, session)
		assert.Contains(t, err.Error(), "token is expired")
	})
}

// TestRBACAuthorization tests role-based access control
func TestRBACAuthorization(t *testing.T) {
	suite := setupAuthTestSuite(t)
	defer suite.cleanup()

	ctx := context.Background()

	testCases := []struct {
		name        string
		username    string
		resource    string
		action      string
		shouldAllow bool
	}{
		// Admin access
		{"AdminFullAccess", "admin", "/api/things/sensor1", "delete", true},
		{"AdminConfigAccess", "admin", "/api/config/system", "write", true},
		{"AdminUserMgmt", "admin", "/api/users/create", "admin", true},

		// Operator access
		{"OperatorThingsRead", "operator", "/api/things/sensor1", "read", true},
		{"OperatorThingsWrite", "operator", "/api/things/sensor1", "write", true},
		{"OperatorStreamsAccess", "operator", "/api/streams/config", "write", true},
		{"OperatorNoConfigAccess", "operator", "/api/config/system", "write", false},
		{"OperatorNoUserMgmt", "operator", "/api/users/create", "admin", false},

		// Viewer access
		{"ViewerThingsRead", "viewer", "/api/things/sensor1", "read", true},
		{"ViewerStatusRead", "viewer", "/api/status", "read", true},
		{"ViewerNoThingsWrite", "viewer", "/api/things/sensor1", "write", false},
		{"ViewerNoStreamsWrite", "viewer", "/api/streams/config", "write", false},
		{"ViewerNoConfigAccess", "viewer", "/api/config/system", "read", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Get user
			user, err := suite.sysSecMgr.getUserByUsername(ctx, tc.username)
			require.NoError(t, err)

			// Convert to types.User
			typesUser := &types.User{
				ID:       user.Username,
				Username: user.Username,
				Email:    user.Email,
				FullName: user.FullName,
				Roles:    user.Roles,
			}

			// Test authorization
			err = suite.sysSecMgr.AuthorizeAPIAccess(ctx, typesUser, tc.resource, tc.action)

			if tc.shouldAllow {
				assert.NoError(t, err, "User %s should have %s access to %s", tc.username, tc.action, tc.resource)
			} else {
				assert.Error(t, err, "User %s should NOT have %s access to %s", tc.username, tc.action, tc.resource)
			}
		})
	}
}

// TestSessionManagement tests session creation, validation, and revocation
func TestSessionManagement(t *testing.T) {
	suite := setupAuthTestSuite(t)
	defer suite.cleanup()

	ctx := context.Background()

	t.Run("CreateAndManageSessions", func(t *testing.T) {
		// Authenticate user
		credentials := types.UserCredentials{
			Username: "admin",
			Password: "AdminPass123!",
		}

		session1, err := suite.sysSecMgr.AuthenticateUser(ctx, credentials)
		require.NoError(t, err)

		// Create another session for the same user
		session2, err := suite.sysSecMgr.AuthenticateUser(ctx, credentials)
		require.NoError(t, err)

		// Both sessions should be valid
		assert.NotEqual(t, session1.ID, session2.ID)
		assert.NotEqual(t, session1.Token, session2.Token)

		// List user sessions
		sessions, err := suite.sysSecMgr.ListUserSessions(ctx, "admin")
		assert.NoError(t, err)
		assert.Len(t, sessions, 2)

		// Revoke one session
		err = suite.sysSecMgr.RevokeSession(ctx, session1.Token)
		assert.NoError(t, err)

		// First session should be invalid, second should still be valid
		_, err = suite.sysSecMgr.ValidateSession(ctx, session1.Token)
		assert.Error(t, err)

		validSession, err := suite.sysSecMgr.ValidateSession(ctx, session2.Token)
		assert.NoError(t, err)
		assert.Equal(t, session2.ID, validSession.ID)

		// Revoke all user sessions
		err = suite.sysSecMgr.RevokeAllUserSessions(ctx, "admin")
		assert.NoError(t, err)

		// Second session should now be invalid
		_, err = suite.sysSecMgr.ValidateSession(ctx, session2.Token)
		assert.Error(t, err)
	})

	t.Run("SessionTimeout", func(t *testing.T) {
		// Test would require mocking time or waiting - simplified for unit test
		// In real implementation, sessions should expire based on SessionConfig.Timeout
		t.Skip("Session timeout test requires time mocking")
	})

	t.Run("MaxSessionsLimit", func(t *testing.T) {
		// Create sessions up to the limit
		credentials := types.UserCredentials{
			Username: "operator",
			Password: "OpPass456!",
		}

		var sessions []*types.UserSession
		for range 5 { // MaxSessions is 5
			session, err := suite.sysSecMgr.AuthenticateUser(ctx, credentials)
			require.NoError(t, err)
			sessions = append(sessions, session)
		}

		// Creating one more should either fail or revoke oldest session
		session6, err := suite.sysSecMgr.AuthenticateUser(ctx, credentials)
		if err == nil {
			// If successful, oldest session should be invalidated
			_, err = suite.sysSecMgr.ValidateSession(ctx, sessions[0].Token)
			assert.Error(t, err, "Oldest session should be invalidated")

			// Newest session should be valid
			_, err = suite.sysSecMgr.ValidateSession(ctx, session6.Token)
			assert.NoError(t, err)
		} else {
			// If failed, should contain message about session limit
			assert.Contains(t, err.Error(), "session limit")
		}
	})
}

// TestCaddySecurityIntegration tests caddy-security bridge functionality
func TestCaddySecurityIntegration(t *testing.T) {
	suite := setupAuthTestSuite(t)
	defer suite.cleanup()

	ctx := context.Background()

	t.Run("GenerateSecurityAppConfig", func(t *testing.T) {
		appJSON, err := suite.bridge.GenerateSecurityApp(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, appJSON)

		// Parse the JSON to verify structure
		var appConfig map[string]any
		err = json.Unmarshal(appJSON, &appConfig)
		assert.NoError(t, err)

		// Verify expected keys exist
		config := appConfig["config"].(map[string]any)
		assert.Contains(t, config, "authentication_portals")
		assert.Contains(t, config, "authorization_policies")
		assert.Contains(t, config, "user_registries")

		// Verify portal configuration
		portals := config["authentication_portals"].(map[string]any)
		assert.Contains(t, portals, "twincore_portal")

		// Verify authorization configuration
		policies := config["authorization_policies"].(map[string]any)
		assert.Contains(t, policies, "twincore_policy")
	})

	t.Run("GenerateAuthenticationMiddleware", func(t *testing.T) {
		protectedRoute := types.HTTPRoute{
			Path:         "/api/things",
			Methods:      []string{"GET", "POST"},
			Handler:      "reverse_proxy",
			RequiresAuth: true,
		}

		middleware, err := suite.bridge.GenerateAuthenticationMiddleware(protectedRoute)
		assert.NoError(t, err)
		assert.NotNil(t, middleware)

		// Verify middleware contains authentication configuration
		middlewareStr := string(middleware)
		assert.Contains(t, middlewareStr, "authentication")
		assert.Contains(t, middlewareStr, "twincore_portal")
	})

	t.Run("RouteProtectionRules", func(t *testing.T) {
		testRoutes := []struct {
			path          string
			requiresAuth  bool
			shouldProtect bool
		}{
			{"/api/things", true, true},
			{"/api/streams", true, true},
			{"/portal/index.html", false, false},
			{"/auth/login", false, false},
			{"/health", false, false},
			{"/setup/init", true, true},
		}

		for _, tr := range testRoutes {
			route := types.HTTPRoute{
				Path:         tr.path,
				RequiresAuth: tr.requiresAuth,
				Handler:      "reverse_proxy",
			}

			middleware, err := suite.bridge.GenerateAuthenticationMiddleware(route)
			assert.NoError(t, err)

			if tr.shouldProtect {
				assert.NotNil(t, middleware, "Route %s should be protected", tr.path)
			} else {
				assert.Nil(t, middleware, "Route %s should not be protected", tr.path)
			}
		}
	})

	t.Run("UserStoreSynchronization", func(t *testing.T) {
		err := suite.bridge.SyncUsersToUserStore(ctx)
		assert.NoError(t, err)

		// Verify that user store synchronization doesn't error
		// In a real implementation, this would sync users to caddy-security's user store
	})
}

// TestPasswordPolicyValidation tests password policy enforcement
func TestPasswordPolicyValidation(t *testing.T) {
	suite := setupAuthTestSuite(t)
	defer suite.cleanup()

	ctx := context.Background()

	testCases := []struct {
		name        string
		password    string
		shouldPass  bool
		description string
	}{
		{"ValidPassword", "StrongPass123!", true, "meets all requirements"},
		{"TooShort", "Short1!", false, "less than 8 characters"},
		{"NoUppercase", "lowercase123!", false, "no uppercase letters"},
		{"NoLowercase", "UPPERCASE123!", false, "no lowercase letters"},
		{"NoNumbers", "NoNumbers!", false, "no numbers"},
		{"NoSymbols", "NoSymbols123", false, "no special characters"},
		{"AllRequirements", "Perfect123!", true, "meets all policy requirements"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testUser := &types.User{
				ID:       "testuser",
				Username: "testuser",
				Email:    "test@twincore.local",
				FullName: "Test User",
				Roles:    []string{"viewer"},
			}

			err := suite.sysSecMgr.CreateUser(ctx, testUser, tc.password)

			if tc.shouldPass {
				assert.NoError(t, err, "Password should pass validation: %s", tc.description)
				// Clean up - delete the test user
				suite.sysSecMgr.DeleteUser(ctx, testUser.ID)
			} else {
				assert.Error(t, err, "Password should fail validation: %s", tc.description)
			}
		})
	}
}

// Helper functions

func mustHashPassword(password string) string {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic(fmt.Sprintf("Failed to hash password: %v", err))
	}
	return string(hash)
}

func runTestMigrations(db *sql.DB) error {
	schema := `
		CREATE TABLE IF NOT EXISTS local_users (
			username TEXT PRIMARY KEY,
			password_hash TEXT NOT NULL,
			roles TEXT,
			email TEXT,
			name TEXT,
			disabled BOOLEAN DEFAULT FALSE,
			last_login TIMESTAMP,
			created_at TIMESTAMP DEFAULT now(),
			updated_at TIMESTAMP DEFAULT now()
		);

		CREATE TABLE IF NOT EXISTS user_sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			username TEXT NOT NULL,
			token TEXT NOT NULL,
			refresh_token TEXT,
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP DEFAULT now(),
			last_activity TIMESTAMP DEFAULT now(),
			ip_address TEXT,
			user_agent TEXT
		);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(token);

		CREATE TABLE IF NOT EXISTS security_audit_events (
			id TEXT PRIMARY KEY,
			event_type TEXT NOT NULL,
			timestamp TIMESTAMP NOT NULL,
			user_id TEXT,
			thing_id TEXT,
			operation TEXT NOT NULL,
			resource TEXT,
			success BOOLEAN NOT NULL,
			error TEXT,
			ip_address TEXT,
			user_agent TEXT,
			details TEXT
		);
	`
	_, err := db.Exec(schema)
	return err
}

func initializeTestUsers(db *sql.DB, users []types.LocalUser) error {
	for _, user := range users {
		rolesJSON, _ := json.Marshal(user.Roles)
		_, err := db.Exec(`
			INSERT INTO local_users 
			(username, password_hash, roles, email, name, disabled, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, now(), now())
			ON CONFLICT(username) DO UPDATE SET
				password_hash = excluded.password_hash,
				roles = excluded.roles,
				email = excluded.email,
				name = excluded.name,
				disabled = excluded.disabled,
				updated_at = now()
		`, user.Username, user.PasswordHash, string(rolesJSON), user.Email, user.FullName, user.Disabled)
		if err != nil {
			return err
		}
	}
	return nil
}

// MockUnifiedLicenseChecker for testing
type MockUnifiedLicenseChecker struct {
	systemFeatures  map[string]bool
	wotFeatures     map[string]bool
	generalFeatures map[string]bool
}

func (m *MockUnifiedLicenseChecker) EnableAllFeatures() {
	m.systemFeatures = map[string]bool{
		"local_auth": true,
		"ldap_auth":  true,
		"mfa":        true,
		"rbac":       true,
	}
	m.wotFeatures = map[string]bool{
		"credential_stores":     true,
		"security_templates":    true,
		"global_policies":       true,
		"credential_encryption": true,
		"vault_integration":     true,
		"wot_rate_limit":        true,
	}
	m.generalFeatures = map[string]bool{
		"enterprise_streaming": true,
	}
}

func (m *MockUnifiedLicenseChecker) ValidateLicense(ctx context.Context, licenseToken string) (*types.LicenseSecurityFeatures, error) {
	return &types.LicenseSecurityFeatures{}, nil
}

func (m *MockUnifiedLicenseChecker) GetLicenseFeatures(ctx context.Context) (*types.LicenseSecurityFeatures, error) {
	return &types.LicenseSecurityFeatures{}, nil
}

func (m *MockUnifiedLicenseChecker) IsLicenseValid(ctx context.Context) bool {
	return true
}

func (m *MockUnifiedLicenseChecker) GetLicenseExpiry(ctx context.Context) (time.Time, error) {
	return time.Now().Add(365 * 24 * time.Hour), nil
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

func (m *MockUnifiedLicenseChecker) IsSystemFeatureEnabled(ctx context.Context, feature string) bool {
	return m.systemFeatures[feature]
}

func (m *MockUnifiedLicenseChecker) IsWoTFeatureEnabled(ctx context.Context, feature string) bool {
	return m.wotFeatures[feature]
}

func (m *MockUnifiedLicenseChecker) IsGeneralFeatureEnabled(ctx context.Context, feature string) bool {
	return m.generalFeatures[feature]
}

func (m *MockUnifiedLicenseChecker) GetSystemFeatures(ctx context.Context) []string {
	var features []string
	for feature, enabled := range m.systemFeatures {
		if enabled {
			features = append(features, feature)
		}
	}
	return features
}

func (m *MockUnifiedLicenseChecker) GetWoTFeatures(ctx context.Context) []string {
	var features []string
	for feature, enabled := range m.wotFeatures {
		if enabled {
			features = append(features, feature)
		}
	}
	return features
}

func (m *MockUnifiedLicenseChecker) GetGeneralFeatures(ctx context.Context) []string {
	var features []string
	for feature, enabled := range m.generalFeatures {
		if enabled {
			features = append(features, feature)
		}
	}
	return features
}
