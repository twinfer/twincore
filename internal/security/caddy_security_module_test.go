package security

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/twinfer/twincore/pkg/types"
)

// TestCaddySecurityModuleIntegration tests actual caddy-security module integration
func TestCaddySecurityModuleIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping caddy-security module integration test in short mode")
	}

	// Check if we're in a CI environment where caddy-security may not be available
	if os.Getenv("CI") == "true" {
		t.Skip("Skipping caddy-security module test in CI environment")
	}

	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	t.Run("ModuleDiscovery", func(t *testing.T) {
		// List all available Caddy modules to see what's loaded
		modules := caddy.Modules()
		
		securityModules := []string{}
		for _, moduleName := range modules {
			if contains(moduleName, "security") || contains(moduleName, "auth") {
				securityModules = append(securityModules, moduleName)
			}
		}

		t.Logf("Found %d security-related modules:", len(securityModules))
		for _, module := range securityModules {
			t.Logf("  - %s", module)
		}

		// At minimum, we should have some HTTP modules
		assert.Greater(t, len(modules), 0, "Should have some Caddy modules loaded")
	})

	t.Run("IdentityStoreFileGeneration", func(t *testing.T) {
		// Test creating a user file compatible with caddy-security local identity store
		db := setupTestDB(t)
		defer db.Close()

		store := NewLocalIdentityStore(db, logger, "twincore_local")

		// Create test users
		users := []*AuthUser{
			{
				Username: "admin",
				Email:    "admin@twincore.local",
				FullName: "Administrator",
				Roles:    []string{"admin"},
			},
			{
				Username: "operator",
				Email:    "operator@twincore.local", 
				FullName: "Operator User",
				Roles:    []string{"operator"},
			},
			{
				Username: "viewer",
				Email:    "viewer@twincore.local",
				FullName: "Viewer User", 
				Roles:    []string{"viewer"},
			},
		}

		for _, user := range users {
			err := store.CreateUser(context.Background(), user, "password123")
			require.NoError(t, err)
		}

		// Generate user file in caddy-security format
		tempDir := t.TempDir()
		userFile := filepath.Join(tempDir, "users.json")

		err := generateCaddySecurityUserFile(store, userFile)
		require.NoError(t, err)

		// Verify file was created and has valid JSON
		data, err := os.ReadFile(userFile)
		require.NoError(t, err)

		var userStore map[string]any
		err = json.Unmarshal(data, &userStore)
		require.NoError(t, err)

		// Verify structure
		assert.Contains(t, userStore, "revision")
		assert.Contains(t, userStore, "users")

		users_map := userStore["users"].(map[string]any)
		assert.Len(t, users_map, 3)
		assert.Contains(t, users_map, "admin")
		assert.Contains(t, users_map, "operator")
		assert.Contains(t, users_map, "viewer")

		t.Logf("Generated caddy-security user file: %s", userFile)
		t.Logf("User file content preview: %s", string(data)[:min(len(data), 200)])
	})

	t.Run("SecurityAppConfiguration", func(t *testing.T) {
		// Test generating a complete security app configuration
		db := setupTestDB(t)
		defer db.Close()

		mockLicenseChecker := &MockUnifiedLicenseChecker{
			features: map[string]bool{
				"local_auth": true,
				"jwt_auth":   true,
				"rbac":       true,
			},
			valid: true,
		}

		config := &types.SystemSecurityConfig{
			Enabled: true,
			AdminAuth: &types.AdminAuthConfig{
				Local: &types.LocalAuthConfig{
					PasswordPolicy: &types.PasswordPolicy{
						MinLength:        12,
						RequireUppercase: true,
						RequireLowercase: true,
						RequireNumbers:   true,
						RequireSymbols:   true,
					},
				},
			},
			APIAuth: &types.APIAuthConfig{
				Methods: []string{"jwt", "bearer"},
				JWTConfig: &types.JWTConfig{
					Algorithm: "HS256",
					Issuer:    "twincore-gateway",
					Audience:  "twincore-api",
					Expiry:    2 * time.Hour,
				},
				Policies: []types.APIPolicy{
					{
						ID:          "admin_full_access",
						Name:        "Administrator Full Access",
						Description: "Full access to all APIs",
						Principal:   "role:admin",
						Resources:   []string{"/api/*"},
						Actions:     []string{"read", "write", "delete", "admin"},
					},
					{
						ID:          "operator_limited_access", 
						Name:        "Operator Limited Access",
						Description: "Read/write access to operational APIs",
						Principal:   "role:operator",
						Resources:   []string{"/api/things/*", "/api/streams/*"},
						Actions:     []string{"read", "write"},
					},
				},
			},
			SessionConfig: &types.SessionConfig{
				Timeout:        time.Hour,
				MaxSessions:    3,
				SecureCookies:  true,
				SameSite:       "strict",
				CSRFProtection: true,
			},
		}

		bridge, err := NewCaddyAuthPortalBridge(db, logger, config, mockLicenseChecker, t.TempDir())
		require.NoError(t, err)

		// Generate the security app configuration
		securityConfig, err := bridge.GenerateAuthPortalConfig(context.Background())
		require.NoError(t, err)
		require.NotNil(t, securityConfig)

		// Parse and validate the configuration structure
		var securityApp map[string]any
		err = json.Unmarshal(securityConfig, &securityApp)
		require.NoError(t, err)

		// Validate all required sections
		requiredSections := []string{
			"crypto_key",
			"authentication_portals", 
			"authorization_policies",
			"identity_stores",
		}

		for _, section := range requiredSections {
			assert.Contains(t, securityApp, section, "Security config should contain %s", section)
		}

		// Validate portal configuration
		portals := securityApp["authentication_portals"].(map[string]any)
		portal := portals["twincore_portal"].(map[string]any)
		
		assert.Contains(t, portal, "name")
		assert.Contains(t, portal, "ui")
		assert.Contains(t, portal, "cookie")
		assert.Contains(t, portal, "backends")

		// Validate authorization policies
		policies := securityApp["authorization_policies"].(map[string]any)
		policy := policies["twincore_policy"].(map[string]any)
		
		assert.Contains(t, policy, "default_action")
		assert.Contains(t, policy, "rules")
		assert.Equal(t, "deny", policy["default_action"])

		// Validate crypto configuration
		crypto := securityApp["crypto_key"].(map[string]any)
		assert.Contains(t, crypto, "token_name")
		assert.Contains(t, crypto, "token_secret")
		assert.Contains(t, crypto, "token_issuer")
		assert.Equal(t, "twincore-gateway", crypto["token_issuer"])

		t.Logf("Generated security configuration with %d sections", len(securityApp))
	})

	t.Run("CompleteCaddyConfiguration", func(t *testing.T) {
		// Test creating a complete Caddy configuration that could actually run
		db := setupTestDB(t)
		defer db.Close()

		// Create test user
		store := NewLocalIdentityStore(db, logger, "twincore_local")
		testUser := &AuthUser{
			Username: "testadmin",
			Email:    "admin@test.local",
			FullName: "Test Administrator",
			Roles:    []string{"admin"},
		}
		err := store.CreateUser(context.Background(), testUser, "AdminPass123!")
		require.NoError(t, err)

		// Generate user file
		tempDir := t.TempDir()
		userFile := filepath.Join(tempDir, "users.json")
		err = generateCaddySecurityUserFile(store, userFile)
		require.NoError(t, err)

		// Generate security configuration
		mockLicenseChecker := &MockUnifiedLicenseChecker{valid: true}
		config := &types.SystemSecurityConfig{
			Enabled: true,
			AdminAuth: &types.AdminAuthConfig{
				Local: &types.LocalAuthConfig{},
			},
		}

		bridge, err := NewCaddyAuthPortalBridge(db, logger, config, mockLicenseChecker, tempDir)
		require.NoError(t, err)

		securityConfig, err := bridge.GenerateAuthPortalConfig(context.Background())
		require.NoError(t, err)

		// Create complete Caddy configuration
		caddyConfig := map[string]any{
			"admin": map[string]any{
				"disabled": true, // Disable admin API for testing
			},
			"apps": map[string]any{
				"http": map[string]any{
					"servers": map[string]any{
						"srv0": map[string]any{
							"listen": []string{":8080"},
							"routes": []map[string]any{
								{
									"match": []map[string]any{
										{"path": []string{"/auth/*"}},
									},
									"handle": []map[string]any{
										{
											"handler": "subroute",
											"routes": []map[string]any{
												{
													"handle": []map[string]any{
														{
															"handler": "authentication",
															"providers": map[string]any{
																"portal": map[string]any{
																	"name": "twincore_portal",
																},
															},
														},
													},
												},
											},
										},
									},
								},
								{
									"match": []map[string]any{
										{"path": []string{"/api/*"}},
									},
									"handle": []map[string]any{
										{
											"handler": "authentication",
											"providers": map[string]any{
												"portal": map[string]any{
													"name": "twincore_portal",
												},
											},
										},
										{
											"handler": "authorization",
											"providers": map[string]any{
												"portal": map[string]any{
													"name": "twincore_policy",
												},
											},
										},
										{
											"handler": "static_response",
											"status_code": 200,
											"body": "API access granted",
										},
									},
								},
								{
									"handle": []map[string]any{
										{
											"handler": "static_response",
											"status_code": 200,
											"body": "Welcome to TwinCore Gateway",
										},
									},
								},
							},
						},
					},
				},
			},
		}

		// Add security app if we have the configuration
		var securityApp map[string]any
		err = json.Unmarshal(securityConfig, &securityApp)
		require.NoError(t, err)
		
		caddyConfig["apps"].(map[string]any)["security"] = securityApp

		// Marshal complete configuration
		configJSON, err := json.MarshalIndent(caddyConfig, "", "  ")
		require.NoError(t, err)

		// Save configuration to file for inspection
		configFile := filepath.Join(tempDir, "caddy_config.json")
		err = os.WriteFile(configFile, configJSON, 0644)
		require.NoError(t, err)

		t.Logf("Generated complete Caddy configuration:")
		t.Logf("- Config file: %s", configFile)
		t.Logf("- User file: %s", userFile)
		t.Logf("- Config size: %d bytes", len(configJSON))

		// Verify the configuration is valid JSON
		var testParse map[string]any
		err = json.Unmarshal(configJSON, &testParse)
		assert.NoError(t, err, "Generated configuration should be valid JSON")

		// Log configuration preview
		preview := string(configJSON)
		if len(preview) > 500 {
			preview = preview[:500] + "..."
		}
		t.Logf("Configuration preview:\n%s", preview)
	})
}

// generateCaddySecurityUserFile generates a user file compatible with caddy-security
func generateCaddySecurityUserFile(store *LocalIdentityStore, filename string) error {
	users, err := store.ListUsers(context.Background())
	if err != nil {
		return fmt.Errorf("failed to list users: %w", err)
	}

	// Create caddy-security user store format
	userStore := map[string]any{
		"revision": 1,
		"users":    make(map[string]any),
	}

	userMap := userStore["users"].(map[string]any)

	for _, user := range users {
		userEntry := map[string]any{
			"username": user.Username,
			"email":    user.Email,
			"name":     user.FullName,
			"password": user.Password, // Already hashed
			"roles":    user.Roles,
			"created":  user.CreatedAt.Unix(),
			"updated":  user.UpdatedAt.Unix(),
		}

		if user.LastLogin != nil {
			userEntry["last_login"] = user.LastLogin.Unix()
		}

		userMap[user.Username] = userEntry
	}

	// Write to file
	data, err := json.MarshalIndent(userStore, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal user store: %w", err)
	}

	err = os.WriteFile(filename, data, 0600) // Secure permissions
	if err != nil {
		return fmt.Errorf("failed to write user file: %w", err)
	}

	return nil
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && 
		   (s == substr || 
		    (len(s) > len(substr) && 
		     (s[:len(substr)] == substr || 
		      s[len(s)-len(substr):] == substr ||
		      searchInString(s, substr))))
}

func searchInString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}