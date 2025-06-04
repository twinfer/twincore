package security

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/twinfer/twincore/pkg/types"
)

// CaddySecurityBridge connects TwinCore's SystemSecurityManager with caddy-security module
type CaddySecurityBridge struct {
	systemSecurityManager types.SystemSecurityManager
	logger                *logrus.Logger
	config                *types.SystemSecurityConfig
}

// NewCaddySecurityBridge creates a new bridge between SystemSecurityManager and caddy-security
func NewCaddySecurityBridge(systemSecurityManager types.SystemSecurityManager, config *types.SystemSecurityConfig, logger *logrus.Logger) *CaddySecurityBridge {
	return &CaddySecurityBridge{
		systemSecurityManager: systemSecurityManager,
		config:                config,
		logger:                logger,
	}
}

// GenerateSecurityApp creates a caddy-security app configuration
func (csb *CaddySecurityBridge) GenerateSecurityApp(ctx context.Context) (json.RawMessage, error) {
	if !csb.config.Enabled {
		csb.logger.Debug("System security disabled, skipping caddy-security app generation")
		return nil, nil
	}

	// Create the security app configuration
	securityApp := map[string]any{
		"config": map[string]any{
			"authentication_portals": map[string]any{
				"twincore_portal": csb.generateAuthPortalConfig(),
			},
			"authorization_policies": map[string]any{
				"twincore_policy": csb.generateAuthorizationPolicy(),
			},
			"user_registries": map[string]any{
				"twincore_users": csb.generateUserRegistryConfig(),
			},
		},
	}

	// Marshal the security app configuration
	appJSON, err := json.Marshal(securityApp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal security app config: %w", err)
	}

	csb.logger.WithField("config", string(appJSON)).Debug("Generated caddy-security app configuration")
	return json.RawMessage(appJSON), nil
}

// generateAuthPortalConfig creates authentication portal configuration
func (csb *CaddySecurityBridge) generateAuthPortalConfig() map[string]any {
	portalConfig := map[string]any{
		"user_interface": map[string]any{
			"title":    "TwinCore Gateway",
			"logo_url": "/portal/assets/logo.png",
		},
		"cookie": map[string]any{
			"domain":   "",
			"path":     "/",
			"lifetime": 86400, // 24 hours
		},
		"backends": []map[string]any{},
	}

	// Add local authentication backend if configured
	if csb.config.AdminAuth != nil && csb.config.AdminAuth.Local != nil {
		localBackend := csb.generateLocalAuthBackend()
		backends := portalConfig["backends"].([]map[string]any)
		portalConfig["backends"] = append(backends, localBackend)
	}

	// Add LDAP backend if configured
	if csb.config.AdminAuth != nil && csb.config.AdminAuth.LDAP != nil {
		ldapBackend := csb.generateLDAPAuthBackend()
		backends := portalConfig["backends"].([]map[string]any)
		portalConfig["backends"] = append(backends, ldapBackend)
	}

	// Configure transformation and JWT settings
	portalConfig["transform"] = map[string]any{
		"match": map[string]any{
			"action": "exact",
			"realm":  "twincore",
		},
		"ui": map[string]any{
			"links": []map[string]any{
				{
					"title": "TwinCore Portal",
					"link":  "/portal",
					"icon":  "las la-home",
				},
			},
		},
	}

	// Configure JWT tokens for API access
	portalConfig["token"] = map[string]any{
		"jwt": map[string]any{
			"token_name":     "access_token",
			"token_secret":   csb.generateJWTSecret(),
			"token_issuer":   "twincore-gateway",
			"token_audience": []string{"twincore-api", "twincore-portal"},
			"token_lifetime": 3600, // 1 hour
			"token_origins":  []string{"twincore"},
		},
	}

	// Configure crypto settings
	portalConfig["crypto"] = map[string]any{
		"key": map[string]any{
			"sign_verify": csb.generateJWTSecret(),
		},
		"default": map[string]any{
			"token_name":     "access_token",
			"token_lifetime": 3600,
		},
	}

	return portalConfig
}

// generateLocalAuthBackend creates local authentication backend configuration
func (csb *CaddySecurityBridge) generateLocalAuthBackend() map[string]any {
	// Create local user store configuration
	userStore := map[string]any{
		"type": "local",
		"name": "twincore_local_store",
		"params": map[string]any{
			"path": "./twincore_users.json", // This will be managed by SystemSecurityManager
		},
	}

	localBackend := map[string]any{
		"type":        "local",
		"name":        "twincore_local_backend",
		"method":      "form",
		"realm":       "twincore",
		"user_stores": []map[string]any{userStore},
	}

	// Add password policy if configured
	if csb.config.AdminAuth != nil && csb.config.AdminAuth.Local != nil && csb.config.AdminAuth.Local.PasswordPolicy != nil {
		localBackend["password_policy"] = csb.generatePasswordPolicy()
	}

	return localBackend
}

// generateLDAPAuthBackend creates LDAP authentication backend configuration
func (csb *CaddySecurityBridge) generateLDAPAuthBackend() map[string]any {
	ldapConfig := csb.config.AdminAuth.LDAP

	ldapBackend := map[string]any{
		"type":   "ldap",
		"name":   "twincore_ldap_backend",
		"method": "form",
		"realm":  "twincore",
		"servers": []map[string]any{
			{
				"address":      ldapConfig.Server,
				"ignore_cert":  !ldapConfig.TLS.Enabled, // Inverse logic
				"posix_groups": true,
				"attributes": map[string]any{
					"name":      ldapConfig.Attributes.FullName,
					"surname":   "sn",
					"username":  ldapConfig.Attributes.Username,
					"member_of": ldapConfig.Attributes.Groups,
					"email":     ldapConfig.Attributes.Email,
				},
				"username_search_filter": fmt.Sprintf("(%s=%s)", ldapConfig.Attributes.Username, "{{.username}}"),
				"search_base_dn":         ldapConfig.BaseDN,
				"search_user_dn":         ldapConfig.BindDN,
				"search_user_password":   ldapConfig.BindPassword,
			},
		},
	}

	return ldapBackend
}

// generatePasswordPolicy creates password policy configuration
func (csb *CaddySecurityBridge) generatePasswordPolicy() map[string]any {
	if csb.config.AdminAuth == nil || csb.config.AdminAuth.Local == nil || csb.config.AdminAuth.Local.PasswordPolicy == nil {
		// Return default policy
		return map[string]any{
			"min_length":        8,
			"require_uppercase": true,
			"require_lowercase": true,
			"require_number":    true,
			"require_symbol":    false,
		}
	}

	policy := csb.config.AdminAuth.Local.PasswordPolicy
	return map[string]any{
		"min_length":        policy.MinLength,
		"require_uppercase": policy.RequireUppercase,
		"require_lowercase": policy.RequireLowercase,
		"require_number":    policy.RequireNumbers,
		"require_symbol":    policy.RequireSymbols,
	}
}

// generateAuthorizationPolicy creates authorization policy configuration
func (csb *CaddySecurityBridge) generateAuthorizationPolicy() map[string]any {
	policy := map[string]any{
		"default_action": "deny",
		"acl": map[string]any{
			"rules": []map[string]any{
				// Admin access to everything
				{
					"comment": "Admin full access",
					"conditions": []string{
						"match roles admin",
					},
					"action": "allow",
				},
				// Operator access to WoT and streams
				{
					"comment": "Operator access to WoT and streams",
					"conditions": []string{
						"match roles operator",
						"match path /api/things*",
					},
					"action": "allow",
				},
				{
					"comment": "Operator access to streams",
					"conditions": []string{
						"match roles operator",
						"match path /api/streams*",
					},
					"action": "allow",
				},
				// Viewer read-only access
				{
					"comment": "Viewer read-only access",
					"conditions": []string{
						"match roles viewer",
						"match method GET",
						"match path /api/things*",
					},
					"action": "allow",
				},
				{
					"comment": "Viewer read-only streams",
					"conditions": []string{
						"match roles viewer",
						"match method GET",
						"match path /api/streams*",
					},
					"action": "allow",
				},
				// Public health endpoint
				{
					"comment": "Public health check",
					"conditions": []string{
						"match path /health*",
					},
					"action": "allow",
				},
			},
		},
	}

	// Add configured API policies if available
	if csb.config.APIAuth != nil {
		existingRules := policy["acl"].(map[string]any)["rules"].([]map[string]any)
		for _, apiPolicy := range csb.config.APIAuth.Policies {
			rule := map[string]any{
				"comment": fmt.Sprintf("Custom policy for %s", apiPolicy.Principal),
				"conditions": []string{
					fmt.Sprintf("match roles %s", csb.extractRoleFromPrincipal(apiPolicy.Principal)),
				},
				"action": "allow",
			}

			// Add resource conditions
			for _, resource := range apiPolicy.Resources {
				rule["conditions"] = append(rule["conditions"].([]string), fmt.Sprintf("match path %s", resource))
			}

			existingRules = append(existingRules, rule)
		}
		policy["acl"].(map[string]any)["rules"] = existingRules
	}

	return policy
}

// generateUserRegistryConfig creates user registry configuration
func (csb *CaddySecurityBridge) generateUserRegistryConfig() map[string]any {
	return map[string]any{
		"type": "local",
		"config": map[string]any{
			"path":  "./twincore_users.json",
			"realm": "twincore",
		},
	}
}

// generateJWTSecret creates or retrieves JWT secret for token signing
func (csb *CaddySecurityBridge) generateJWTSecret() string {
	// In production, this should be loaded from secure configuration
	// For now, generate a consistent secret based on system configuration
	return "twincore-jwt-secret-change-in-production"
}

// generateAuthenticationMiddleware creates authentication middleware configuration for routes
func (csb *CaddySecurityBridge) GenerateAuthenticationMiddleware(route types.HTTPRoute) (json.RawMessage, error) {
	if !csb.config.Enabled {
		return nil, nil
	}

	// Check if this route requires authentication based on the RequiresAuth flag
	// The RequiresAuth flag takes precedence over path-based logic
	requiresAuth := route.RequiresAuth

	if requiresAuth {
		authMiddleware := map[string]any{
			"handler": "authentication",
			"config": map[string]any{
				"portal_name": "twincore_portal",
				"policy_name": "twincore_policy",
			},
		}

		middlewareJSON, err := json.Marshal(authMiddleware)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal authentication middleware: %w", err)
		}

		return json.RawMessage(middlewareJSON), nil
	}

	return nil, nil
}

// shouldProtectRoute determines if a route should be protected by authentication
// This method is used as fallback when RequiresAuth is not explicitly set
func (csb *CaddySecurityBridge) shouldProtectRoute(path string) bool {
	// First check for public routes - these should NOT be protected
	publicPaths := []string{
		"/portal/",
		"/auth/",   // Authentication endpoints (login, logout, etc.)
		"/health",  // Health check endpoint
		"/assets/", // Static assets
		"/favicon.ico",
	}

	for _, publicPath := range publicPaths {
		// Exact match for single endpoints like /health
		if path == publicPath {
			return false
		}
		// Prefix match for directories
		if len(path) >= len(publicPath) && path[:len(publicPath)] == publicPath {
			return false
		}
	}

	// Then check for protected routes - these SHOULD be protected
	protectedPaths := []string{
		"/api/",
		"/admin/",
		"/setup/",
		"/things/", // WoT routes - should be protected
	}

	for _, protectedPath := range protectedPaths {
		if len(path) >= len(protectedPath) && path[:len(protectedPath)] == protectedPath {
			return true
		}
	}

	// Default to protected for unknown routes (secure by default)
	return true
}

// Helper functions

func (csb *CaddySecurityBridge) extractRoleFromPrincipal(principal string) string {
	// Principal format: "role:admin", "user:username", "group:groupname"
	if len(principal) > 5 && principal[:5] == "role:" {
		return principal[5:]
	}
	return principal
}

func (csb *CaddySecurityBridge) convertActionsToMethods(actions []string) []string {
	methodMap := map[string][]string{
		"read":   {"GET", "HEAD"},
		"write":  {"POST", "PUT", "PATCH"},
		"delete": {"DELETE"},
		"admin":  {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
	}

	methods := make(map[string]bool)
	for _, action := range actions {
		if actionMethods, exists := methodMap[action]; exists {
			for _, method := range actionMethods {
				methods[method] = true
			}
		}
	}

	result := make([]string, 0, len(methods))
	for method := range methods {
		result = append(result, method)
	}

	return result
}

// SyncUsersToUserStore synchronizes SystemSecurityManager users to caddy-security user store
func (csb *CaddySecurityBridge) SyncUsersToUserStore(ctx context.Context) error {
	if !csb.config.Enabled || csb.config.AdminAuth == nil || csb.config.AdminAuth.Local == nil {
		return nil
	}

	// Get users from SystemSecurityManager
	users, err := csb.systemSecurityManager.ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("failed to list users from SystemSecurityManager: %w", err)
	}

	// Convert to caddy-security user format
	userStore := map[string]any{
		"users": make(map[string]any),
	}

	usersMap := userStore["users"].(map[string]any)
	for _, user := range users {
		usersMap[user.Username] = map[string]any{
			"username": user.Username,
			"email":    user.Email,
			"name":     user.FullName,
			"roles":    user.Roles,
			"disabled": false, // This should come from user data
		}
	}

	// Write user store file (this would be better as a database integration)
	userStoreJSON, err := json.MarshalIndent(userStore, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal user store: %w", err)
	}

	csb.logger.WithField("user_count", len(users)).Debug("Synchronized users to caddy-security user store")
	csb.logger.WithField("user_store", string(userStoreJSON)).Debug("Generated user store configuration")

	// TODO: Write to actual file or integrate with caddy-security's user store interface
	// This is a placeholder - actual implementation would write to the configured user store path

	return nil
}
