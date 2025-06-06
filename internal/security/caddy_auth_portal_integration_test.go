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

	_ "github.com/marcboeker/go-duckdb"
	"github.com/twinfer/twincore/internal/database"
	"github.com/twinfer/twincore/internal/database/repositories"
	"github.com/twinfer/twincore/pkg/types"
)

// MockUnifiedLicenseChecker for testing
type MockUnifiedLicenseChecker struct {
	features map[string]bool
	valid    bool
}

func (m *MockUnifiedLicenseChecker) ValidateLicense(ctx context.Context, licenseData string) (*types.LicenseSecurityFeatures, error) {
	return &types.LicenseSecurityFeatures{}, nil
}

func (m *MockUnifiedLicenseChecker) GetLicenseFeatures(ctx context.Context) (*types.LicenseSecurityFeatures, error) {
	return &types.LicenseSecurityFeatures{}, nil
}

func (m *MockUnifiedLicenseChecker) IsLicenseValid(ctx context.Context) bool {
	return m.valid
}

func (m *MockUnifiedLicenseChecker) GetLicenseExpiry(ctx context.Context) (time.Time, error) {
	return time.Now().Add(365 * 24 * time.Hour), nil
}

func (m *MockUnifiedLicenseChecker) IsSystemFeatureEnabled(ctx context.Context, feature string) bool {
	if m.features == nil {
		return true // Default to enabled for tests
	}
	return m.features[feature]
}

func (m *MockUnifiedLicenseChecker) GetSystemSecurityFeatures(ctx context.Context) (*types.SystemSecurityFeatures, error) {
	return &types.SystemSecurityFeatures{
		LocalAuth:            true,
		LDAPAuth:             false,
		SAMLAuth:             false,
		OIDCAuth:             false,
		MFA:                  false,
		SSO:                  false,
		JWTAuth:              true,
		APIKeys:              true,
		SessionMgmt:          true,
		SessionTimeout:       true,
		ConcurrentSessions:   true,
		RBAC:                 true,
		PolicyEngine:         true,
		FineGrainedACL:       true,
		AuditLogging:         true,
		BruteForceProtection: true,
		PasswordPolicy:       true,
		CSRFProtection:       true,
		RateLimit:            true,
	}, nil
}

func (m *MockUnifiedLicenseChecker) IsWoTFeatureEnabled(ctx context.Context, feature string) bool {
	return true
}

func (m *MockUnifiedLicenseChecker) IsGeneralFeatureEnabled(ctx context.Context, feature string) bool {
	return true
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

// MockAuthProviderRepository for testing
type MockAuthProviderRepository struct{}

func (m *MockAuthProviderRepository) IsHealthy(ctx context.Context) bool {
	return true
}

func (m *MockAuthProviderRepository) CreateProvider(ctx context.Context, provider *types.AuthProvider) error {
	return nil
}

func (m *MockAuthProviderRepository) GetProvider(ctx context.Context, id string) (*types.AuthProvider, error) {
	return &types.AuthProvider{
		ID:      id,
		Type:    "ldap",
		Name:    "Test Provider",
		Enabled: true,
		Config:  map[string]any{},
	}, nil
}

func (m *MockAuthProviderRepository) ListProviders(ctx context.Context) ([]*types.AuthProvider, error) {
	return []*types.AuthProvider{}, nil
}

func (m *MockAuthProviderRepository) UpdateProvider(ctx context.Context, id string, updates map[string]any) error {
	return nil
}

func (m *MockAuthProviderRepository) DeleteProvider(ctx context.Context, id string) error {
	return nil
}

func (m *MockAuthProviderRepository) AssociateUserWithProvider(ctx context.Context, userID, providerID, externalID string, attributes map[string]any) error {
	return nil
}

func (m *MockAuthProviderRepository) GetUserProviderAssociations(ctx context.Context, userID string) ([]*types.UserProviderAssociation, error) {
	return []*types.UserProviderAssociation{}, nil
}

func (m *MockAuthProviderRepository) UpdateProviderMetadata(ctx context.Context, providerID string, metadata map[string]any) error {
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

func setupTestDB(t *testing.T) (*sql.DB, database.SecurityRepositoryInterface) {
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
		created_at TIMESTAMP DEFAULT now(),
		updated_at TIMESTAMP DEFAULT now()
	);
	
	CREATE TABLE IF NOT EXISTS user_sessions (
		session_id TEXT PRIMARY KEY,
		username TEXT NOT NULL,
		token TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT now(),
		last_activity TIMESTAMP DEFAULT now(),
		expires_at TIMESTAMP,
		ip_address TEXT,
		user_agent TEXT
	);
	
	CREATE TABLE IF NOT EXISTS api_policies (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		policy_data TEXT NOT NULL,
		enabled BOOLEAN DEFAULT TRUE,
		created_at TIMESTAMP DEFAULT now(),
		updated_at TIMESTAMP DEFAULT now()
	);
	
	CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY,
		user_id TEXT,
		action TEXT NOT NULL,
		resource TEXT,
		details TEXT,
		ip_address TEXT,
		user_agent TEXT,
		timestamp TIMESTAMP DEFAULT now()
	);
	
	CREATE TABLE IF NOT EXISTS thing_security_policies (
		thing_id TEXT PRIMARY KEY,
		policy_data TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT now(),
		updated_at TIMESTAMP DEFAULT now()
	);`

	_, err = db.Exec(schema)
	require.NoError(t, err)

	// Create a mock database manager
	mockDBManager := &MockDatabaseManager{db: db}

	// Create security repository
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)
	securityRepo := repositories.NewSecurityRepository(mockDBManager, logger)

	return db, securityRepo
}

// MockDatabaseManager for testing
type MockDatabaseManager struct {
	db *sql.DB
}

func (m *MockDatabaseManager) Execute(ctx context.Context, queryName string, args ...any) (sql.Result, error) {
	// Simple mock - just execute queries directly
	// Note: SecurityRepository now marshals roles to JSON before calling this method
	switch queryName {
	case "CreateUser":
		return m.db.Exec(`INSERT INTO local_users (username, password_hash, roles, email, name, disabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, now(), now())`, args...)
	case "UpdateUser":
		return m.db.Exec(`UPDATE local_users SET password_hash = ?, roles = ?, email = ?, name = ?, disabled = ?, updated_at = now() WHERE username = ?`, args...)
	case "DeleteUser":
		return m.db.Exec(`DELETE FROM local_users WHERE username = ?`, args...)
	case "UpdateLastLogin":
		return m.db.Exec(`UPDATE local_users SET last_login = now() WHERE username = ?`, args...)
	default:
		return nil, nil
	}
}

func (m *MockDatabaseManager) Query(ctx context.Context, queryName string, args ...any) (*sql.Rows, error) {
	switch queryName {
	case "ListUsers":
		return m.db.Query(`SELECT username, password_hash, roles, email, name, disabled, last_login, created_at, updated_at FROM local_users ORDER BY username`)
	default:
		return nil, nil
	}
}

func (m *MockDatabaseManager) QueryRow(ctx context.Context, queryName string, args ...any) *sql.Row {
	switch queryName {
	case "GetUser":
		return m.db.QueryRow(`SELECT username, password_hash, roles, email, name, disabled, last_login, created_at, updated_at FROM local_users WHERE username = ?`, args...)
	case "GetUserForAuth":
		return m.db.QueryRow(`SELECT username, password_hash, roles, disabled FROM local_users WHERE username = ?`, args...)
	case "UserExists":
		return m.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM local_users WHERE username = ?)`, args...)
	default:
		return nil
	}
}

func (m *MockDatabaseManager) Transaction(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := fn(tx); err != nil {
		return err
	}

	return tx.Commit()
}

func (m *MockDatabaseManager) GetQuery(name string) (string, error) {
	return "", nil
}

func (m *MockDatabaseManager) ListQueries() []string {
	return []string{}
}

func (m *MockDatabaseManager) IsHealthy() bool {
	return true
}

func (m *MockDatabaseManager) GetQueryStats() map[string]*database.QueryStats {
	return map[string]*database.QueryStats{}
}

func (m *MockDatabaseManager) Close() error {
	return m.db.Close()
}

func (m *MockDatabaseManager) GetConnection() *sql.DB {
	return m.db
}

func createTestUser(t *testing.T, securityRepo database.SecurityRepositoryInterface, username, email, name string, roles []string) {
	user := &types.LocalUser{
		Username:     username,
		PasswordHash: "$2a$10$testhashedpassword",
		Email:        email,
		FullName:     name,
		Roles:        roles,
		Disabled:     false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	err := securityRepo.CreateUser(context.Background(), user)
	require.NoError(t, err)
}

// TestLocalIdentityStore tests the local identity store functionality
func TestLocalIdentityStore(t *testing.T) {
	db, securityRepo := setupTestDB(t)
	defer db.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel) // Reduce test noise

	store := NewLocalIdentityStore(securityRepo, logger, "test_store")

	t.Run("GetName", func(t *testing.T) {
		assert.Equal(t, "test_store", store.GetName())
	})

	t.Run("CreateUser", func(t *testing.T) {
		user := &AuthUser{
			Username: "testuser",
			Email:    "test@example.com",
			FullName: "Test User",
			Roles:    []string{"viewer"},
			Password: "testpassword",
		}

		err := store.CreateUser(context.Background(), user)
		assert.NoError(t, err)

		// Verify user was created
		retrievedUser, err := store.GetUser(context.Background(), "testuser")
		assert.NoError(t, err)
		assert.Equal(t, "testuser", retrievedUser.Username)
		assert.Equal(t, "test@example.com", retrievedUser.Email)
		assert.Equal(t, "Test User", retrievedUser.FullName)
		assert.Equal(t, []string{"viewer"}, retrievedUser.Roles)
	})

	t.Run("AuthenticateUser", func(t *testing.T) {
		// First create a user
		user := &AuthUser{
			Username: "authuser",
			Email:    "auth@example.com",
			FullName: "Auth User",
			Roles:    []string{"admin"},
			Password: "authpassword",
		}
		err := store.CreateUser(context.Background(), user)
		require.NoError(t, err)

		// Now authenticate
		authenticatedUser, err := store.AuthenticateUser(context.Background(), "authuser", "authpassword")
		assert.NoError(t, err)
		assert.Equal(t, "authuser", authenticatedUser.Username)
		assert.Equal(t, []string{"admin"}, authenticatedUser.Roles)

		// Test wrong password
		_, err = store.AuthenticateUser(context.Background(), "authuser", "wrongpassword")
		assert.Error(t, err)
	})

	t.Run("UpdateUser", func(t *testing.T) {
		// Create initial user
		user := &AuthUser{
			Username: "updateuser",
			Email:    "update@example.com",
			FullName: "Update User",
			Roles:    []string{"viewer"},
			Password: "password",
		}
		err := store.CreateUser(context.Background(), user)
		require.NoError(t, err)

		// Update user
		updatedUser := &AuthUser{
			Username: "updateuser",
			Email:    "newemail@example.com",
			FullName: "Updated User",
			Roles:    []string{"admin", "viewer"},
		}
		err = store.UpdateUser(context.Background(), updatedUser)
		assert.NoError(t, err)

		// Verify update
		retrievedUser, err := store.GetUser(context.Background(), "updateuser")
		assert.NoError(t, err)
		assert.Equal(t, "newemail@example.com", retrievedUser.Email)
		assert.Equal(t, "Updated User", retrievedUser.FullName)
		assert.Equal(t, []string{"admin", "viewer"}, retrievedUser.Roles)
	})
}

// TestCaddyAuthPortalBridge tests the integration bridge
func TestCaddyAuthPortalBridge(t *testing.T) {
	db, securityRepo := setupTestDB(t)
	defer db.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	// Create mock license checker
	mockLicenseChecker := &MockUnifiedLicenseChecker{
		features: map[string]bool{
			"admin_auth": true,
		},
		valid: true,
	}

	// Create system security config
	config := &types.SystemSecurityConfig{
		Enabled: true,
		AdminAuth: &types.AdminAuthConfig{
			Local: &types.LocalAuthConfig{
				PasswordPolicy: &types.PasswordPolicy{
					MinLength: 8,
				},
			},
		},
	}

	bridge, err := NewCaddyAuthPortalBridge(
		securityRepo,
		logger,
		config,
		mockLicenseChecker,
		"/tmp",
	)
	require.NoError(t, err)

	t.Run("GenerateAuthPortalConfig", func(t *testing.T) {
		configJSON, err := bridge.GenerateAuthPortalConfig(context.Background())
		assert.NoError(t, err)
		assert.NotNil(t, configJSON)

		// Parse and validate config
		var authConfig map[string]any
		err = json.Unmarshal(configJSON, &authConfig)
		assert.NoError(t, err)
		assert.Contains(t, authConfig, "authentication_portals")
	})

	t.Run("GetIdentityStore", func(t *testing.T) {
		store := bridge.GetIdentityStore()
		assert.NotNil(t, store)
		assert.Equal(t, "twincore_local", store.GetName())
	})
}

// TestSystemSecurityManager tests the system security manager
func TestSystemSecurityManager(t *testing.T) {
	db, securityRepo := setupTestDB(t)
	defer db.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	mockLicenseChecker := &MockUnifiedLicenseChecker{
		features: map[string]bool{
			"user_management": true,
			"local_auth":      true,
		},
		valid: true,
	}

	// Create mock auth provider repository
	mockAuthProviderRepo := &MockAuthProviderRepository{}

	manager := NewSystemSecurityManager(securityRepo, mockAuthProviderRepo, logger, mockLicenseChecker)

	t.Run("CreateUser", func(t *testing.T) {
		user := &types.User{
			Username: "testuser",
			Email:    "test@example.com",
			FullName: "Test User",
			Roles:    []string{"viewer"},
		}

		err := manager.CreateUser(context.Background(), user, "testpassword")
		assert.NoError(t, err)

		// Verify user was created by trying to get it
		retrievedUser, err := manager.GetUser(context.Background(), "testuser")
		assert.NoError(t, err)
		assert.Equal(t, "testuser", retrievedUser.Username)
	})

	t.Run("GetUser", func(t *testing.T) {
		// Create user first
		user := &types.User{
			Username: "authuser",
			Email:    "auth@example.com",
			FullName: "Auth User",
			Roles:    []string{"admin"},
		}
		err := manager.CreateUser(context.Background(), user, "password")
		require.NoError(t, err)

		// Test retrieving the user
		retrieved, err := manager.GetUser(context.Background(), "authuser")
		assert.NoError(t, err)
		assert.Equal(t, "authuser", retrieved.Username)
		assert.Equal(t, "auth@example.com", retrieved.Email)
		assert.Equal(t, []string{"admin"}, retrieved.Roles)
	})
}

// TestIntegrationWorkflow tests the complete authentication workflow
func TestIntegrationWorkflow(t *testing.T) {
	db, securityRepo := setupTestDB(t)
	defer db.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	// Setup components
	mockLicenseChecker := &MockUnifiedLicenseChecker{valid: true}

	config := &types.SystemSecurityConfig{
		Enabled: true,
		AdminAuth: &types.AdminAuthConfig{
			Local: &types.LocalAuthConfig{},
		},
	}

	// Create identity store
	identityStore := NewLocalIdentityStore(securityRepo, logger, "twincore_local")

	// Create auth portal bridge
	bridge, err := NewCaddyAuthPortalBridge(
		securityRepo,
		logger,
		config,
		mockLicenseChecker,
		"/tmp",
	)
	require.NoError(t, err)

	// Create system security manager
	// Create mock auth provider repository
	mockAuthProviderRepo2 := &MockAuthProviderRepository{}

	securityManager := NewSystemSecurityManager(securityRepo, mockAuthProviderRepo2, logger, mockLicenseChecker)

	t.Run("CompleteUserWorkflow", func(t *testing.T) {
		// 1. Create user via security manager
		user := &types.User{
			Username: "workflowuser",
			Email:    "workflow@example.com",
			FullName: "Workflow User",
			Roles:    []string{"admin"},
		}
		err := securityManager.CreateUser(context.Background(), user, "workflowpassword")
		assert.NoError(t, err)

		// 2. Retrieve user via identity store
		authUser, err := identityStore.GetUser(context.Background(), "workflowuser")
		assert.NoError(t, err)
		assert.Equal(t, "workflowuser", authUser.Username)
		assert.Equal(t, []string{"admin"}, authUser.Roles)

		// 3. Generate auth config that includes this user
		authConfig, err := bridge.GenerateAuthPortalConfig(context.Background())
		assert.NoError(t, err)
		assert.NotNil(t, authConfig)

		// 4. Verify config contains expected authentication settings
		var config map[string]any
		err = json.Unmarshal(authConfig, &config)
		assert.NoError(t, err)
		assert.Contains(t, config, "authentication_portals")
	})
}
