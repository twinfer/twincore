package security

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/twinfer/twincore/pkg/types"
)

// MockSystemSecurityManager for testing
type MockSystemSecurityManager struct {
	mock.Mock
}

func (m *MockSystemSecurityManager) AuthenticateUser(ctx context.Context, credentials types.UserCredentials) (*types.UserSession, error) {
	args := m.Called(ctx, credentials)
	return args.Get(0).(*types.UserSession), args.Error(1)
}

func (m *MockSystemSecurityManager) AuthorizeAPIAccess(ctx context.Context, user *types.User, resource string, action string) error {
	args := m.Called(ctx, user, resource, action)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) GetUser(ctx context.Context, userID string) (*types.User, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(*types.User), args.Error(1)
}

func (m *MockSystemSecurityManager) ListUsers(ctx context.Context) ([]*types.User, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*types.User), args.Error(1)
}

func (m *MockSystemSecurityManager) CreateUser(ctx context.Context, user *types.User, password string) error {
	args := m.Called(ctx, user, password)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) UpdateUser(ctx context.Context, userID string, updates map[string]any) error {
	args := m.Called(ctx, userID, updates)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) DeleteUser(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) ChangePassword(ctx context.Context, userID string, oldPassword, newPassword string) error {
	args := m.Called(ctx, userID, oldPassword, newPassword)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) CreateSession(ctx context.Context, user *types.User) (*types.UserSession, error) {
	args := m.Called(ctx, user)
	return args.Get(0).(*types.UserSession), args.Error(1)
}

func (m *MockSystemSecurityManager) ValidateSession(ctx context.Context, sessionToken string) (*types.UserSession, error) {
	args := m.Called(ctx, sessionToken)
	return args.Get(0).(*types.UserSession), args.Error(1)
}

func (m *MockSystemSecurityManager) RefreshSession(ctx context.Context, refreshToken string) (*types.UserSession, error) {
	args := m.Called(ctx, refreshToken)
	return args.Get(0).(*types.UserSession), args.Error(1)
}

func (m *MockSystemSecurityManager) RevokeSession(ctx context.Context, sessionToken string) error {
	args := m.Called(ctx, sessionToken)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) ListUserSessions(ctx context.Context, userID string) ([]*types.UserSession, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]*types.UserSession), args.Error(1)
}

func (m *MockSystemSecurityManager) RevokeAllUserSessions(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// Policy Management
func (m *MockSystemSecurityManager) AddPolicy(ctx context.Context, policy types.APIPolicy) error {
	args := m.Called(ctx, policy)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) RemovePolicy(ctx context.Context, policyID string) error {
	args := m.Called(ctx, policyID)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) UpdatePolicy(ctx context.Context, policyID string, policy types.APIPolicy) error {
	args := m.Called(ctx, policyID, policy)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) GetPolicy(ctx context.Context, policyID string) (*types.APIPolicy, error) {
	args := m.Called(ctx, policyID)
	return args.Get(0).(*types.APIPolicy), args.Error(1)
}

func (m *MockSystemSecurityManager) ListPolicies(ctx context.Context) ([]types.APIPolicy, error) {
	args := m.Called(ctx)
	return args.Get(0).([]types.APIPolicy), args.Error(1)
}

func (m *MockSystemSecurityManager) EvaluatePolicy(ctx context.Context, accessCtx *types.AccessContext) error {
	args := m.Called(ctx, accessCtx)
	return args.Error(0)
}

// Configuration Management
func (m *MockSystemSecurityManager) UpdateConfig(ctx context.Context, config types.SystemSecurityConfig) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) GetConfig(ctx context.Context) (*types.SystemSecurityConfig, error) {
	args := m.Called(ctx)
	return args.Get(0).(*types.SystemSecurityConfig), args.Error(1)
}

func (m *MockSystemSecurityManager) ValidateConfig(ctx context.Context, config types.SystemSecurityConfig) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

// Health and Monitoring
func (m *MockSystemSecurityManager) HealthCheck(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) GetSecurityMetrics(ctx context.Context) (map[string]any, error) {
	args := m.Called(ctx)
	return args.Get(0).(map[string]any), args.Error(1)
}

func (m *MockSystemSecurityManager) GetAuditLog(ctx context.Context, filters map[string]any) ([]types.AuditEvent, error) {
	args := m.Called(ctx, filters)
	return args.Get(0).([]types.AuditEvent), args.Error(1)
}

// TestCaddySecurityBridge tests the caddy-security bridge functionality
func TestCaddySecurityBridge(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// Create mock system security manager
	mockSSM := &MockSystemSecurityManager{}

	// Create test security configuration
	secConfig := &types.SystemSecurityConfig{
		Enabled: true,
		AdminAuth: &types.AdminAuthConfig{
			Method:    "local",
			Providers: []string{"local"},
			Local: &types.LocalAuthConfig{
				Users: []types.LocalUser{
					{
						Username:     "admin",
						PasswordHash: "$2a$10$defaulthash",
						Email:        "admin@twincore.local",
						FullName:     "Test Admin",
						Roles:        []string{"admin"},
					},
				},
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
			Methods: []string{"jwt"},
			Policies: []types.APIPolicy{
				{
					ID:        "admin_policy",
					Name:      "Admin Policy",
					Principal: "role:admin",
					Resources: []string{"/api/*"},
					Actions:   []string{"read", "write", "delete", "admin"},
				},
			},
		},
	}

	// Create caddy-security bridge
	bridge := NewCaddySecurityBridge(mockSSM, secConfig, logger)

	t.Run("GenerateSecurityApp", func(t *testing.T) {
		ctx := context.Background()

		appJSON, err := bridge.GenerateSecurityApp(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, appJSON)

		// Verify the JSON contains expected structure
		assert.Contains(t, string(appJSON), "authentication_portals")
		assert.Contains(t, string(appJSON), "authorization_policies")
		assert.Contains(t, string(appJSON), "twincore_portal")
		assert.Contains(t, string(appJSON), "twincore_policy")
	})

	t.Run("GenerateAuthenticationMiddleware_ProtectedRoute", func(t *testing.T) {
		// Test with a protected API route
		route := types.HTTPRoute{
			Path:    "/api/things",
			Methods: []string{"GET", "POST"},
			Handler: "reverse_proxy",
		}

		middleware, err := bridge.GenerateAuthenticationMiddleware(route)
		assert.NoError(t, err)
		assert.NotNil(t, middleware)

		// Verify middleware configuration
		assert.Contains(t, string(middleware), "authentication")
		assert.Contains(t, string(middleware), "twincore_portal")
		assert.Contains(t, string(middleware), "twincore_policy")
	})

	t.Run("GenerateAuthenticationMiddleware_PublicRoute", func(t *testing.T) {
		// Test with a public portal route
		route := types.HTTPRoute{
			Path:    "/portal/index.html",
			Methods: []string{"GET"},
			Handler: "file_server",
		}

		middleware, err := bridge.GenerateAuthenticationMiddleware(route)
		assert.NoError(t, err)
		assert.Nil(t, middleware) // Should not protect public routes
	})

	t.Run("SyncUsersToUserStore", func(t *testing.T) {
		ctx := context.Background()

		// Mock the ListUsers call
		testUsers := []*types.User{
			{
				ID:       "admin",
				Username: "admin",
				Email:    "admin@twincore.local",
				FullName: "Test Admin",
				Roles:    []string{"admin"},
			},
			{
				ID:       "user1",
				Username: "user1",
				Email:    "user1@twincore.local",
				FullName: "Test User",
				Roles:    []string{"user"},
			},
		}

		mockSSM.On("ListUsers", ctx).Return(testUsers, nil)

		err := bridge.SyncUsersToUserStore(ctx)
		assert.NoError(t, err)

		mockSSM.AssertExpectations(t)
	})

	t.Run("DisabledSecurity", func(t *testing.T) {
		// Test with disabled security
		disabledConfig := &types.SystemSecurityConfig{
			Enabled: false,
		}

		disabledBridge := NewCaddySecurityBridge(mockSSM, disabledConfig, logger)

		// Should return nil for security app
		appJSON, err := disabledBridge.GenerateSecurityApp(context.Background())
		assert.NoError(t, err)
		assert.Nil(t, appJSON)

		// Should return nil for authentication middleware
		route := types.HTTPRoute{Path: "/api/test"}
		middleware, err := disabledBridge.GenerateAuthenticationMiddleware(route)
		assert.NoError(t, err)
		assert.Nil(t, middleware)
	})
}

func TestCaddySecurityBridge_RouteProtection(t *testing.T) {
	logger := logrus.New()
	mockSSM := &MockSystemSecurityManager{}
	secConfig := &types.SystemSecurityConfig{Enabled: true}
	bridge := NewCaddySecurityBridge(mockSSM, secConfig, logger)

	testCases := []struct {
		name          string
		path          string
		shouldProtect bool
	}{
		{"API route", "/api/things", true},
		{"Admin route", "/admin/config", true},
		{"Setup route", "/setup/initialize", true},
		{"Portal route", "/portal/index.html", false},
		{"WoT route", "/things/sensor1/properties/temperature", false},
		{"Login route", "/login", false},
		{"Logout route", "/logout", false},
		{"Assets route", "/assets/logo.png", false},
		{"Unknown route", "/unknown/path", true}, // Default to protected
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			route := types.HTTPRoute{
				Path:    tc.path,
				Methods: []string{"GET"},
				Handler: "reverse_proxy",
			}

			middleware, err := bridge.GenerateAuthenticationMiddleware(route)
			assert.NoError(t, err)

			if tc.shouldProtect {
				assert.NotNil(t, middleware, "Route %s should be protected", tc.path)
				assert.Contains(t, string(middleware), "authentication")
			} else {
				assert.Nil(t, middleware, "Route %s should not be protected", tc.path)
			}
		})
	}
}
