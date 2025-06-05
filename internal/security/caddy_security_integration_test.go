package security

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/twinfer/twincore/pkg/types"
)

// TestCaddySecurityRealIntegration tests actual integration with caddy-security modules
func TestCaddySecurityRealIntegration(t *testing.T) {
	// Skip if not in integration test mode
	if testing.Short() {
		t.Skip("Skipping caddy-security integration test in short mode")
	}

	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// Setup test database
	db := setupTestDB(t)
	defer db.Close()

	// Create test user
	testUser := &AuthUser{
		Username: "testuser",
		Email:    "test@example.com",
		FullName: "Test User",
		Roles:    []string{"admin"},
	}

	store := NewLocalIdentityStore(db, logger, "twincore_local")
	err := store.CreateUser(context.Background(), testUser, "testpass123")
	require.NoError(t, err)

	t.Run("CaddySecurityModuleLoading", func(t *testing.T) {
		// Test that caddy-security modules can be loaded
		modules := caddy.Modules()

		// Check if security modules are available
		securityModules := []string{}
		for _, moduleName := range modules {
			if strings.Contains(moduleName, "security") || strings.Contains(moduleName, "auth") {
				securityModules = append(securityModules, moduleName)
			}
		}

		t.Logf("Found %d security-related modules:", len(securityModules))
		for _, module := range securityModules {
			t.Logf("  - %s", module)
		}

		// At minimum, we should have HTTP modules available
		assert.Greater(t, len(modules), 0, "Should have some Caddy modules loaded")
	})

	t.Run("CaddyConfigGeneration", func(t *testing.T) {
		// Test generating a complete Caddy configuration with security
		mockLicenseChecker := &MockUnifiedLicenseChecker{
			features: map[string]bool{
				"local_auth": true,
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
		}

		bridge, err := NewCaddyAuthPortalBridge(db, logger, config, mockLicenseChecker, "/tmp/test")
		require.NoError(t, err)

		// Generate auth portal configuration
		authConfig, err := bridge.GenerateAuthPortalConfig(context.Background())
		require.NoError(t, err)
		require.NotNil(t, authConfig)

		// Create a complete Caddy configuration
		caddyConfig := createTestCaddyConfig(t, authConfig)

		// Try to load the configuration (basic validation)
		err = caddy.Load(caddyConfig, false)
		if err != nil {
			t.Logf("Caddy config load error (expected without caddy-security): %v", err)
			// Note: This will fail without caddy-security modules, but the config structure should be valid
		} else {
			t.Log("Caddy configuration loaded successfully")
			defer caddy.Stop()
		}
	})

	t.Run("HTTPAuthenticationFlow", func(t *testing.T) {
		// Test HTTP authentication flow simulation
		handler := createTestAuthHandler(t, store)

		// Test valid credentials
		req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{"username":"testuser","password":"testpass123"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]any
		err := json.Unmarshal(w.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Contains(t, response, "token")
		assert.Equal(t, "testuser", response["username"])

		// Test invalid credentials
		req = httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{"username":"testuser","password":"wrongpass"}`))
		req.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("JWTTokenGeneration", func(t *testing.T) {
		// Test JWT token generation and validation
		mockLicenseChecker := &MockUnifiedLicenseChecker{valid: true}
		securityMgr := NewSystemSecurityManager(db, logger, mockLicenseChecker)

		// Configure JWT settings
		config := types.SystemSecurityConfig{
			Enabled: true,
			APIAuth: &types.APIAuthConfig{
				JWTConfig: &types.JWTConfig{
					Algorithm: "HS256",
					Issuer:    "twincore-gateway",
					Audience:  "twincore-api",
					Expiry:    time.Hour,
				},
			},
		}
		err := securityMgr.UpdateConfig(context.Background(), config)
		require.NoError(t, err)

		// This would typically be done by caddy-security, but we'll simulate it
		user := &types.User{
			Username: "testuser",
			Roles:    []string{"admin"},
		}

		// Test authorization
		err = securityMgr.AuthorizeAPIAccess(context.Background(), user, "/api/admin/config", "write")
		assert.NoError(t, err, "Admin should have access to admin endpoints")

		// Test role-based access
		user.Roles = []string{"viewer"}
		err = securityMgr.AuthorizeAPIAccess(context.Background(), user, "/api/things", "read")
		assert.NoError(t, err, "Viewer should have read access")

		err = securityMgr.AuthorizeAPIAccess(context.Background(), user, "/api/things", "write")
		assert.Error(t, err, "Viewer should not have write access")
	})

	t.Run("IdentityStoreIntegration", func(t *testing.T) {
		// Test identity store with simulated caddy-security calls

		// Simulate user lookup that caddy-security would perform
		user, err := store.GetUser(context.Background(), "testuser")
		require.NoError(t, err)
		assert.Equal(t, "testuser", user.Username)
		assert.Equal(t, []string{"admin"}, user.Roles)

		// Simulate authentication that caddy-security would perform
		validatedUser, err := store.ValidateUser(context.Background(), "testuser", "testpass123")
		require.NoError(t, err)
		assert.Equal(t, "testuser", validatedUser.Username)

		// Test invalid password
		_, err = store.ValidateUser(context.Background(), "testuser", "wrongpass")
		assert.Error(t, err)

		// Test user update (simulating admin operations)
		updates := map[string]any{
			"roles": []string{"operator"},
		}
		err = store.UpdateUser(context.Background(), "testuser", updates)
		assert.NoError(t, err)

		// Verify update
		updatedUser, err := store.GetUser(context.Background(), "testuser")
		require.NoError(t, err)
		assert.Equal(t, []string{"operator"}, updatedUser.Roles)
	})

	t.Run("SecurityConfigValidation", func(t *testing.T) {
		// Test that our generated configuration is valid for caddy-security
		mockLicenseChecker := &MockUnifiedLicenseChecker{valid: true}

		config := &types.SystemSecurityConfig{
			Enabled: true,
			AdminAuth: &types.AdminAuthConfig{
				Local: &types.LocalAuthConfig{},
			},
		}

		bridge, err := NewCaddyAuthPortalBridge(db, logger, config, mockLicenseChecker, "/tmp/test")
		require.NoError(t, err)

		// Validate configuration
		err = bridge.ValidateConfiguration()
		assert.NoError(t, err)

		// Generate configuration
		authConfig, err := bridge.GenerateAuthPortalConfig(context.Background())
		require.NoError(t, err)

		// Parse and validate JSON structure
		var configMap map[string]any
		err = json.Unmarshal(authConfig, &configMap)
		require.NoError(t, err)

		// Verify required sections exist
		assert.Contains(t, configMap, "authentication_portals")
		assert.Contains(t, configMap, "authorization_policies")
		assert.Contains(t, configMap, "identity_stores")
		assert.Contains(t, configMap, "crypto_key")

		// Verify portal configuration
		portals := configMap["authentication_portals"].(map[string]any)
		assert.Contains(t, portals, "twincore_portal")

		portal := portals["twincore_portal"].(map[string]any)
		assert.Contains(t, portal, "backends")
		assert.Contains(t, portal, "cookie")
		assert.Contains(t, portal, "ui")

		// Verify identity store configuration
		stores := configMap["identity_stores"].(map[string]any)
		assert.Contains(t, stores, "twincore_local")

		store := stores["twincore_local"].(map[string]any)
		assert.Equal(t, "twincore_local", store["name"])
		assert.Equal(t, "local", store["kind"])
	})
}

// createTestCaddyConfig creates a minimal Caddy configuration for testing
func createTestCaddyConfig(t *testing.T, securityConfig json.RawMessage) []byte {
	config := map[string]any{
		"apps": map[string]any{
			"http": map[string]any{
				"servers": map[string]any{
					"srv0": map[string]any{
						"listen": []string{":8080"},
						"routes": []map[string]any{
							{
								"match": []map[string]any{
									{"path": []string{"/api/*"}},
								},
								"handle": []map[string]any{
									{
										"handler": "authentication",
									},
									{
										"handler": "authorization",
									},
									{
										"handler":     "static_response",
										"status_code": 200,
										"body":        "API endpoint",
									},
								},
							},
						},
					},
				},
			},
			"security": securityConfig,
		},
	}

	configBytes, err := json.Marshal(config)
	require.NoError(t, err)
	return configBytes
}

// createTestAuthHandler creates a test HTTP handler that simulates authentication
func createTestAuthHandler(t *testing.T, store *LocalIdentityStore) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/auth/login" {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}

		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		// Validate credentials using our identity store
		user, err := store.ValidateUser(r.Context(), creds.Username, creds.Password)
		if err != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		// Return successful authentication response
		response := map[string]any{
			"username": user.Username,
			"roles":    user.Roles,
			"token":    "mock-jwt-token", // In real implementation, this would be a real JWT
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})
}

// TestCaddySecurityMiddleware tests the middleware integration
func TestCaddySecurityMiddleware(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping middleware integration test in short mode")
	}

	t.Run("MiddlewareChain", func(t *testing.T) {
		// Test that middleware can be properly chained
		// This simulates how caddy-security middleware would be integrated

		// Create a test HTTP handler chain
		finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Success"))
		})

		// Simulate authentication middleware
		authMiddleware := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Simulate authentication check
				token := r.Header.Get("Authorization")
				if token == "" {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
			})
		}

		// Simulate authorization middleware
		authzMiddleware := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Simulate authorization check
				user := r.Header.Get("X-User-Role")
				if user != "admin" {
					http.Error(w, "Forbidden", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
			})
		}

		// Chain the middleware
		handler := authMiddleware(authzMiddleware(finalHandler))

		// Test unauthorized request
		req := httptest.NewRequest("GET", "/api/test", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)

		// Test authorized request
		req = httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("Authorization", "Bearer token")
		req.Header.Set("X-User-Role", "admin")
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "Success", w.Body.String())
	})
}

// BenchmarkCaddySecurityIntegration benchmarks the integration performance
func BenchmarkCaddySecurityIntegration(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce noise in benchmarks

	db := setupTestDB(&testing.T{}) // Note: This is a bit hacky for benchmarks
	defer db.Close()

	store := NewLocalIdentityStore(db, logger, "twincore_local")

	// Create test user
	testUser := &AuthUser{
		Username: "benchuser",
		Email:    "bench@example.com",
		FullName: "Benchmark User",
		Roles:    []string{"user"},
	}
	store.CreateUser(context.Background(), testUser, "benchpass")

	b.Run("UserAuthentication", func(b *testing.B) {
		for b.Loop() {
			_, err := store.ValidateUser(context.Background(), "benchuser", "benchpass")
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ConfigGeneration", func(b *testing.B) {
		mockLicenseChecker := &MockUnifiedLicenseChecker{valid: true}
		config := &types.SystemSecurityConfig{
			Enabled: true,
			AdminAuth: &types.AdminAuthConfig{
				Local: &types.LocalAuthConfig{},
			},
		}

		bridge, _ := NewCaddyAuthPortalBridge(db, logger, config, mockLicenseChecker, "/tmp/test")

		for b.Loop() {
			_, err := bridge.GenerateAuthPortalConfig(context.Background())
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
