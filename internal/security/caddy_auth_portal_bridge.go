package security

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/sirupsen/logrus"

	"github.com/twinfer/twincore/internal/database"
	"github.com/twinfer/twincore/pkg/types"
)

// ConfigurationManager defines the interface for Caddy configuration management
// We define this here to avoid circular imports
type ConfigurationManager interface {
	UpdateCaddyConfig(logger logrus.FieldLogger, path string, config any) error
}

// CaddyAuthPortalBridge provides proper integration with caddy-auth-portal
// This replaces the old CaddySecurityBridge with correct caddy-security integration
type CaddyAuthPortalBridge struct {
	securityRepo   database.SecurityRepositoryInterface
	logger         *logrus.Logger
	config         *types.SystemSecurityConfig
	identityStore  *LocalIdentityStore
	configManager  ConfigurationManager
	dataDir        string
	licenseChecker types.UnifiedLicenseChecker
}

// NewCaddyAuthPortalBridge creates a new bridge that properly integrates with caddy-auth-portal
func NewCaddyAuthPortalBridge(
	securityRepo database.SecurityRepositoryInterface,
	logger *logrus.Logger,
	config *types.SystemSecurityConfig,
	licenseChecker types.UnifiedLicenseChecker,
	dataDir string,
) (*CaddyAuthPortalBridge, error) {

	// Create local identity store
	identityStore := NewLocalIdentityStore(securityRepo, logger, "twincore_local")

	return &CaddyAuthPortalBridge{
		securityRepo:   securityRepo,
		logger:         logger,
		config:         config,
		identityStore:  identityStore,
		dataDir:        dataDir,
		licenseChecker: licenseChecker,
	}, nil
}

// SetConfigManager sets the Caddy configuration manager
func (bridge *CaddyAuthPortalBridge) SetConfigManager(configManager ConfigurationManager) {
	bridge.configManager = configManager
}

// GenerateAuthPortalConfig generates proper caddy-auth-portal configuration
func (bridge *CaddyAuthPortalBridge) GenerateAuthPortalConfig(ctx context.Context) (json.RawMessage, error) {
	if !bridge.config.Enabled {
		bridge.logger.Debug("Authentication disabled, skipping auth portal configuration")
		return nil, nil
	}

	// Generate the auth portal app configuration
	authConfig := map[string]any{
		"crypto_key": map[string]any{
			"token_name":     "access_token",
			"token_secret":   bridge.generateTokenSecret(),
			"token_issuer":   "twincore-gateway",
			"token_audience": []string{"twincore-api"},
			"token_lifetime": bridge.getTokenLifetime(),
		},
		"authentication_portals": map[string]any{
			"twincore_portal": bridge.generatePortalConfig(),
		},
		"authorization_policies": map[string]any{
			"twincore_policy": bridge.generateAuthorizationPolicy(),
		},
	}

	// Add identity stores configuration
	authConfig["identity_stores"] = map[string]any{
		"twincore_local": bridge.generateLocalIdentityStoreConfig(),
	}

	configJSON, err := json.Marshal(authConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal auth portal config: %w", err)
	}

	bridge.logger.Info("Generated caddy-auth-portal configuration")
	return json.RawMessage(configJSON), nil
}

// generatePortalConfig creates the authentication portal configuration
func (bridge *CaddyAuthPortalBridge) generatePortalConfig() map[string]any {
	portalConfig := map[string]any{
		"name": "TwinCore Gateway Portal",
		"ui": map[string]any{
			"logo_url":      "/portal/assets/logo.png",
			"title":         "TwinCore Gateway",
			"auto_redirect": false,
			"theme":         "basic",
		},
		"cookie": map[string]any{
			"domain":   "",
			"path":     "/",
			"lifetime": bridge.getCookieLifetime(),
			"secure":   true,
			"httponly": true,
			"samesite": "strict",
		},
		"backends": []map[string]any{},
	}

	// Configure authentication backends based on available providers
	backends := []map[string]any{}

	// Local authentication backend
	if bridge.config.AdminAuth != nil && bridge.config.AdminAuth.Local != nil {
		localBackend := map[string]any{
			"name":            "twincore_local_backend",
			"method":          "form",
			"realm":           "twincore",
			"identity_stores": []string{"twincore_local"},
		}

		// Add password policy if configured
		if bridge.config.AdminAuth.Local.PasswordPolicy != nil {
			localBackend["password_policy"] = bridge.generatePasswordPolicy()
		}

		backends = append(backends, localBackend)
	}

	// LDAP backend (if licensed and configured)
	if bridge.licenseChecker.IsSystemFeatureEnabled(context.Background(), "ldap_auth") &&
		bridge.config.AdminAuth != nil && bridge.config.AdminAuth.LDAP != nil {
		ldapBackend := bridge.generateLDAPBackend()
		backends = append(backends, ldapBackend)
	}

	portalConfig["backends"] = backends

	// Configure transform rules for UI customization
	portalConfig["transform"] = map[string]any{
		"match": map[string]any{
			"realm": "twincore",
		},
		"ui": map[string]any{
			"links": []map[string]any{
				{
					"title": "TwinCore Portal",
					"link":  "/portal",
					"icon":  "las la-home",
				},
				{
					"title": "API Documentation",
					"link":  "/api/docs",
					"icon":  "las la-book",
				},
			},
		},
	}

	return portalConfig
}

// generateLocalIdentityStoreConfig creates configuration for our local identity store
func (bridge *CaddyAuthPortalBridge) generateLocalIdentityStoreConfig() map[string]any {
	return map[string]any{
		"name": "twincore_local",
		"kind": "local",
		"params": map[string]any{
			"path":           filepath.Join(bridge.dataDir, "users.json"), // For caddy-auth-portal compatibility
			"realm":          "twincore",
			"hash_algorithm": "bcrypt",
			"hash_cost":      12,
		},
	}
}

// generateAuthorizationPolicy creates authorization policies for API access
func (bridge *CaddyAuthPortalBridge) generateAuthorizationPolicy() map[string]any {
	policy := map[string]any{
		"default_action": "deny",
		"rules": []map[string]any{
			// Admin access
			{
				"comment": "Administrator access to all APIs",
				"conditions": []string{
					"match roles admin",
				},
				"action": "allow",
			},
			// Operator access
			{
				"comment": "Operator access to Things and Streams",
				"conditions": []string{
					"match roles operator",
					"match path /api/things* /api/streams*",
					"not match method DELETE",
				},
				"action": "allow",
			},
			// Viewer access
			{
				"comment": "Viewer read-only access",
				"conditions": []string{
					"match roles viewer",
					"match method GET HEAD OPTIONS",
					"match path /api/things* /api/streams*",
				},
				"action": "allow",
			},
			// Public endpoints
			{
				"comment": "Public health and assets",
				"conditions": []string{
					"match path /health /assets/* /favicon.ico /portal/*",
				},
				"action": "allow",
			},
		},
	}

	return policy
}

// generatePasswordPolicy creates password policy configuration
func (bridge *CaddyAuthPortalBridge) generatePasswordPolicy() map[string]any {
	policy := map[string]any{
		"min_length":        8,
		"require_uppercase": true,
		"require_lowercase": true,
		"require_number":    true,
		"require_symbol":    false,
	}

	// Override with configured policy if available
	if bridge.config.AdminAuth != nil &&
		bridge.config.AdminAuth.Local != nil &&
		bridge.config.AdminAuth.Local.PasswordPolicy != nil {

		configPolicy := bridge.config.AdminAuth.Local.PasswordPolicy
		policy["min_length"] = configPolicy.MinLength
		policy["require_uppercase"] = configPolicy.RequireUppercase
		policy["require_lowercase"] = configPolicy.RequireLowercase
		policy["require_number"] = configPolicy.RequireNumbers
		policy["require_symbol"] = configPolicy.RequireSymbols
	}

	return policy
}

// generateLDAPBackend creates LDAP authentication backend configuration
func (bridge *CaddyAuthPortalBridge) generateLDAPBackend() map[string]any {
	ldapConfig := bridge.config.AdminAuth.LDAP

	return map[string]any{
		"name":   "twincore_ldap_backend",
		"method": "form",
		"realm":  "twincore",
		"servers": []map[string]any{
			{
				"address":                ldapConfig.Server,
				"ignore_cert":            !ldapConfig.TLS.Enabled,
				"posix_groups":           true,
				"connection_timeout":     30,
				"request_timeout":        10,
				"search_filter_timeout":  5,
				"search_base_dn":         ldapConfig.BaseDN,
				"search_user_dn":         ldapConfig.BindDN,
				"search_user_password":   ldapConfig.BindPassword,
				"username_search_filter": fmt.Sprintf("(%s={input})", ldapConfig.Attributes.Username),
				"attributes": map[string]any{
					"name":      ldapConfig.Attributes.FullName,
					"surname":   "sn",
					"username":  ldapConfig.Attributes.Username,
					"member_of": ldapConfig.Attributes.Groups,
					"email":     ldapConfig.Attributes.Email,
				},
			},
		},
	}
}

// Helper methods

func (bridge *CaddyAuthPortalBridge) generateTokenSecret() string {
	// In production, this should be loaded from a secure location
	// For now, generate a deterministic secret based on configuration
	return "twincore-jwt-secret-key-placeholder" // TODO: Use proper secret management
}

func (bridge *CaddyAuthPortalBridge) getTokenLifetime() int {
	if bridge.config.APIAuth != nil && bridge.config.APIAuth.JWTConfig != nil {
		return int(bridge.config.APIAuth.JWTConfig.Expiry.Seconds())
	}
	return 3600 // 1 hour default
}

func (bridge *CaddyAuthPortalBridge) getCookieLifetime() int {
	if bridge.config.SessionConfig != nil && bridge.config.SessionConfig.Timeout > 0 {
		return int(bridge.config.SessionConfig.Timeout)
	}
	return 3600 // 1 hour default
}

// ApplyAuthConfiguration applies the authentication configuration to Caddy
func (bridge *CaddyAuthPortalBridge) ApplyAuthConfiguration(ctx context.Context) error {
	if bridge.configManager == nil {
		return fmt.Errorf("configuration manager not set")
	}

	// Generate auth portal configuration
	authConfig, err := bridge.GenerateAuthPortalConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate auth portal config: %w", err)
	}

	// Apply to Caddy's security app
	if err := bridge.configManager.UpdateCaddyConfig(bridge.logger, "/apps/security", authConfig); err != nil {
		return fmt.Errorf("failed to apply auth configuration: %w", err)
	}

	bridge.logger.Info("Applied caddy-auth-portal configuration to Caddy")
	return nil
}

// SyncUsersToIdentityStore synchronizes users from our database to the identity store
func (bridge *CaddyAuthPortalBridge) SyncUsersToIdentityStore(ctx context.Context) error {
	// This method ensures our database users are available to caddy-auth-portal
	// In our case, the LocalIdentityStore already reads directly from the database,
	// so no sync is needed. This method is here for compatibility.

	bridge.logger.Debug("Local identity store reads directly from database - no sync needed")
	return nil
}

// GetIdentityStore returns the local identity store for direct access
func (bridge *CaddyAuthPortalBridge) GetIdentityStore() *LocalIdentityStore {
	return bridge.identityStore
}

// ValidateConfiguration validates the authentication configuration
func (bridge *CaddyAuthPortalBridge) ValidateConfiguration() error {
	if bridge.config == nil {
		return fmt.Errorf("security configuration is nil")
	}

	if !bridge.config.Enabled {
		return nil // No validation needed when disabled
	}

	if bridge.config.AdminAuth == nil {
		return fmt.Errorf("admin authentication configuration is required when security is enabled")
	}

	// Validate at least one auth method is configured
	hasLocalAuth := bridge.config.AdminAuth.Local != nil
	hasLDAPAuth := bridge.config.AdminAuth.LDAP != nil &&
		bridge.licenseChecker.IsSystemFeatureEnabled(context.Background(), "ldap_auth")

	if !hasLocalAuth && !hasLDAPAuth {
		return fmt.Errorf("at least one authentication method must be configured and licensed")
	}

	return nil
}
