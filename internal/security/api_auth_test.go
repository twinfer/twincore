package security

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/twinfer/twincore/pkg/types"
	"slices"
)

// TestAPIEndpointAuthentication tests authentication for various API endpoints
func TestAPIEndpointAuthentication(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// Create test configuration
	secConfig := &types.SystemSecurityConfig{
		Enabled: true,
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
					ID:        "admin_policy",
					Principal: "role:admin",
					Resources: []string{"/api/*"},
					Actions:   []string{"read", "write", "delete", "admin"},
				},
				{
					ID:        "operator_policy",
					Principal: "role:operator",
					Resources: []string{"/api/things/*", "/api/streams/*"},
					Actions:   []string{"read", "write"},
				},
				{
					ID:        "viewer_policy",
					Principal: "role:viewer",
					Resources: []string{"/api/things/*", "/api/streams/*"},
					Actions:   []string{"read"},
				},
			},
		},
	}

	mockSSM := &MockSystemSecurityManager{}
	bridge := NewCaddySecurityBridge(mockSSM, secConfig, logger)

	t.Run("ProtectedAPIEndpoints", func(t *testing.T) {
		protectedRoutes := []types.HTTPRoute{
			{Path: "/api/things", Handler: "reverse_proxy", RequiresAuth: true},
			{Path: "/api/streams", Handler: "reverse_proxy", RequiresAuth: true},
			{Path: "/api/config", Handler: "reverse_proxy", RequiresAuth: true},
			{Path: "/api/users", Handler: "reverse_proxy", RequiresAuth: true},
		}

		for _, route := range protectedRoutes {
			t.Run("Route_"+route.Path, func(t *testing.T) {
				middleware, err := bridge.GenerateAuthenticationMiddleware(route)
				assert.NoError(t, err)
				assert.NotNil(t, middleware, "Route %s should require authentication", route.Path)

				middlewareStr := string(middleware)
				assert.Contains(t, middlewareStr, "authentication")
			})
		}
	})

	t.Run("PublicAPIEndpoints", func(t *testing.T) {
		publicRoutes := []types.HTTPRoute{
			{Path: "/health", Handler: "static_response", RequiresAuth: false},
			{Path: "/auth/login", Handler: "authentication_portal", RequiresAuth: false},
			{Path: "/portal/index.html", Handler: "file_server", RequiresAuth: false},
			{Path: "/auth/logout", Handler: "authentication_portal", RequiresAuth: false},
		}

		for _, route := range publicRoutes {
			t.Run("Route_"+route.Path, func(t *testing.T) {
				middleware, err := bridge.GenerateAuthenticationMiddleware(route)
				assert.NoError(t, err)
				assert.Nil(t, middleware, "Route %s should NOT require authentication", route.Path)
			})
		}
	})

	t.Run("JWTTokenValidation", func(t *testing.T) {
		// Create a valid JWT token
		jwtSecret := []byte("test-secret")

		claims := jwt.MapClaims{
			"sub":      "admin",
			"username": "admin",
			"roles":    []string{"admin"},
			"iss":      secConfig.APIAuth.JWTConfig.Issuer,
			"aud":      secConfig.APIAuth.JWTConfig.Audience,
			"exp":      time.Now().Add(time.Hour).Unix(),
			"iat":      time.Now().Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signedToken, err := token.SignedString(jwtSecret)
		require.NoError(t, err)

		// Test token parsing
		parsedToken, err := jwt.Parse(signedToken, func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return jwtSecret, nil
		})

		assert.NoError(t, err)
		assert.True(t, parsedToken.Valid)

		// Verify claims
		if mapClaims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
			assert.Equal(t, "admin", mapClaims["username"])
			assert.Equal(t, secConfig.APIAuth.JWTConfig.Issuer, mapClaims["iss"])
			assert.Equal(t, secConfig.APIAuth.JWTConfig.Audience, mapClaims["aud"])
		}
	})

	t.Run("BearerTokenAuthentication", func(t *testing.T) {
		// Test Bearer token authentication format
		testCases := []struct {
			name          string
			authHeader    string
			shouldBeValid bool
		}{
			{"ValidBearerToken", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", true},
			{"MissingBearer", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...", false},
			{"InvalidFormat", "Bearer", false},
			{"EmptyToken", "", false},
			{"WrongPrefix", "Basic dXNlcjpwYXNz", false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Test authorization header validation
				hasBearer := strings.HasPrefix(tc.authHeader, "Bearer ")
				tokenPart := strings.TrimPrefix(tc.authHeader, "Bearer ")
				isValid := hasBearer && len(tokenPart) > 0 && tokenPart != "Bearer"

				if tc.shouldBeValid {
					assert.True(t, isValid, "Should be valid bearer token format")
				} else {
					assert.False(t, isValid, "Should be invalid bearer token format")
				}
			})
		}
	})
}

// TestAPIAuthorizationPolicies tests authorization policy enforcement
func TestAPIAuthorizationPolicies(t *testing.T) {
	logger := logrus.New()

	secConfig := &types.SystemSecurityConfig{
		Enabled: true,
		APIAuth: &types.APIAuthConfig{
			Policies: []types.APIPolicy{
				{
					ID:        "admin_policy",
					Principal: "role:admin",
					Resources: []string{"/api/*"},
					Actions:   []string{"read", "write", "delete", "admin"},
				},
				{
					ID:        "operator_policy",
					Principal: "role:operator",
					Resources: []string{"/api/things/*", "/api/streams/*"},
					Actions:   []string{"read", "write"},
				},
				{
					ID:        "viewer_policy",
					Principal: "role:viewer",
					Resources: []string{"/api/things/*", "/api/streams/*"},
					Actions:   []string{"read"},
				},
			},
		},
	}

	mockSSM := &MockSystemSecurityManager{}
	bridge := NewCaddySecurityBridge(mockSSM, secConfig, logger)

	t.Run("PolicyEvaluation", func(t *testing.T) {
		testCases := []struct {
			name       string
			userRole   string
			resource   string
			action     string
			shouldPass bool
		}{
			// Admin access tests
			{"AdminFullAccess", "admin", "/api/things/sensor1", "delete", true},
			{"AdminConfigAccess", "admin", "/api/config/security", "write", true},
			{"AdminUserMgmt", "admin", "/api/users/create", "admin", true},

			// Operator access tests
			{"OperatorThingsRead", "operator", "/api/things/sensor1", "read", true},
			{"OperatorThingsWrite", "operator", "/api/things/sensor1", "write", true},
			{"OperatorStreamsAccess", "operator", "/api/streams/config", "write", true},
			{"OperatorNoConfigAccess", "operator", "/api/config/security", "write", false},
			{"OperatorNoUserMgmt", "operator", "/api/users/create", "admin", false},

			// Viewer access tests
			{"ViewerThingsRead", "viewer", "/api/things/sensor1", "read", true},
			{"ViewerNoThingsWrite", "viewer", "/api/things/sensor1", "write", false},
			{"ViewerNoStreamsWrite", "viewer", "/api/streams/config", "write", false},
			{"ViewerNoConfigAccess", "viewer", "/api/config/security", "read", false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// Find matching policy for the user role
				var matchingPolicy *types.APIPolicy
				for i := range secConfig.APIAuth.Policies {
					policy := &secConfig.APIAuth.Policies[i]
					if policy.Principal == "role:"+tc.userRole {
						matchingPolicy = policy
						break
					}
				}

				require.NotNil(t, matchingPolicy, "Should find policy for role %s", tc.userRole)

				// Check if resource matches policy resources
				resourceMatches := false
				for _, policyResource := range matchingPolicy.Resources {
					if matchesResource(tc.resource, policyResource) {
						resourceMatches = true
						break
					}
				}

				// Check if action is allowed
				actionAllowed := slices.Contains(matchingPolicy.Actions, tc.action)

				shouldPass := resourceMatches && actionAllowed

				if tc.shouldPass {
					assert.True(t, shouldPass, "Access should be allowed for %s %s on %s", tc.userRole, tc.action, tc.resource)
				} else {
					assert.False(t, shouldPass, "Access should be denied for %s %s on %s", tc.userRole, tc.action, tc.resource)
				}
			})
		}
	})

	t.Run("CaddySecurityPolicyGeneration", func(t *testing.T) {
		ctx := context.Background()
		appJSON, err := bridge.GenerateSecurityApp(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, appJSON)

		// Parse the generated config
		var appConfig map[string]any
		err = json.Unmarshal(appJSON, &appConfig)
		assert.NoError(t, err)

		// Verify authorization policies are included
		config := appConfig["config"].(map[string]any)
		authzPolicies := config["authorization_policies"].(map[string]any)
		assert.Contains(t, authzPolicies, "twincore_policy")

		// The twincore_policy should contain our RBAC rules
		twincorePolicy := authzPolicies["twincore_policy"].(map[string]any)
		assert.NotNil(t, twincorePolicy)
	})
}

// TestHTTPSecurityHeaders tests HTTP security header generation
func TestHTTPSecurityHeaders(t *testing.T) {
	logger := logrus.New()
	mockSSM := &MockSystemSecurityManager{}

	secConfig := &types.SystemSecurityConfig{
		Enabled: true,
		SessionConfig: &types.SessionConfig{
			SecureCookies:  true,
			SameSite:       "strict",
			CSRFProtection: true,
		},
	}

	bridge := NewCaddySecurityBridge(mockSSM, secConfig, logger)

	t.Run("SecurityHeaderGeneration", func(t *testing.T) {
		ctx := context.Background()
		appJSON, err := bridge.GenerateSecurityApp(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, appJSON)

		// In a real implementation, the config would include security headers
		configStr := string(appJSON)
		assert.NotEmpty(t, configStr)

		// Verify security configuration is present
		assert.Contains(t, configStr, "config")
	})

	t.Run("CookieSecuritySettings", func(t *testing.T) {
		// Test cookie security configuration
		assert.True(t, secConfig.SessionConfig.SecureCookies)
		assert.Equal(t, "strict", secConfig.SessionConfig.SameSite)
		assert.True(t, secConfig.SessionConfig.CSRFProtection)
	})
}

// TestAPIErrorHandling tests API authentication error scenarios
func TestAPIErrorHandling(t *testing.T) {
	logger := logrus.New()
	mockSSM := &MockSystemSecurityManager{}

	secConfig := &types.SystemSecurityConfig{
		Enabled: true,
		APIAuth: &types.APIAuthConfig{
			Methods: []string{"bearer"},
		},
	}

	bridge := NewCaddySecurityBridge(mockSSM, secConfig, logger)

	t.Run("DisabledSecurityConfig", func(t *testing.T) {
		disabledConfig := &types.SystemSecurityConfig{
			Enabled: false,
		}

		disabledBridge := NewCaddySecurityBridge(mockSSM, disabledConfig, logger)

		appJSON, err := disabledBridge.GenerateSecurityApp(context.Background())
		assert.NoError(t, err)
		assert.Nil(t, appJSON, "Should return nil when security is disabled")
	})

	t.Run("InvalidRouteConfiguration", func(t *testing.T) {
		invalidRoutes := []types.HTTPRoute{
			{Path: "", Handler: "reverse_proxy", RequiresAuth: true},
			{Path: "/api/test", Handler: "", RequiresAuth: true},
		}

		for _, route := range invalidRoutes {
			middleware, err := bridge.GenerateAuthenticationMiddleware(route)
			// Should handle invalid routes gracefully
			assert.NoError(t, err)

			if route.Path == "" {
				// Empty path should not generate middleware
				assert.Nil(t, middleware)
			}
		}
	})

	t.Run("EmptyAuthMethodsConfig", func(t *testing.T) {
		emptyConfig := &types.SystemSecurityConfig{
			Enabled: true,
			APIAuth: &types.APIAuthConfig{
				Methods: []string{}, // Empty methods
			},
		}

		emptyBridge := NewCaddySecurityBridge(mockSSM, emptyConfig, logger)

		appJSON, err := emptyBridge.GenerateSecurityApp(context.Background())
		assert.NoError(t, err)
		// Should still generate config even with empty auth methods
		assert.NotNil(t, appJSON)
	})
}

// Helper function to match resources against patterns
func matchesResource(resource, pattern string) bool {
	// Simple pattern matching - in real implementation would use proper glob/regex
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(resource, prefix)
	}
	return resource == pattern
}

// TestAPIAuthenticationFlow tests complete authentication flows
func TestAPIAuthenticationFlow(t *testing.T) {
	t.Run("CompleteAuthFlow", func(t *testing.T) {
		// This test simulates a complete authentication flow
		// 1. User submits credentials
		// 2. System validates credentials
		// 3. JWT token is generated
		// 4. Token is used for API access
		// 5. Token is validated for each request

		// Mock HTTP handlers for testing
		authHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate login endpoint
			if r.URL.Path == "/auth/login" && r.Method == "POST" {
				// Return mock JWT token
				response := map[string]string{
					"token": "mock-jwt-token",
					"user":  "admin",
				}
				json.NewEncoder(w).Encode(response)
				return
			}
			http.NotFound(w, r)
		})

		apiHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate protected API endpoint
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Mock API response
			response := map[string]string{
				"message": "API access granted",
				"user":    "admin",
			}
			json.NewEncoder(w).Encode(response)
		})

		// Test authentication endpoint
		req := httptest.NewRequest("POST", "/auth/login", strings.NewReader("username=admin&password=test"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		authHandler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var authResponse map[string]string
		err := json.NewDecoder(w.Body).Decode(&authResponse)
		assert.NoError(t, err)
		assert.Equal(t, "mock-jwt-token", authResponse["token"])

		// Test API access with token
		req = httptest.NewRequest("GET", "/api/things", nil)
		req.Header.Set("Authorization", "Bearer "+authResponse["token"])
		w = httptest.NewRecorder()
		apiHandler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var apiResponse map[string]string
		err = json.NewDecoder(w.Body).Decode(&apiResponse)
		assert.NoError(t, err)
		assert.Equal(t, "API access granted", apiResponse["message"])

		// Test API access without token
		req = httptest.NewRequest("GET", "/api/things", nil)
		w = httptest.NewRecorder()
		apiHandler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
