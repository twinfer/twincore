package security

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
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
	securityRepo      database.SecurityRepositoryInterface
	logger            *logrus.Logger
	config            *types.SystemSecurityConfig
	identityStore     *LocalIdentityStore
	configManager     ConfigurationManager
	dataDir           string
	licenseChecker    types.UnifiedLicenseChecker
	externalProviders []*types.AuthProvider // External auth providers
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

// UpdateExternalProviders updates the external auth providers and regenerates configuration
func (bridge *CaddyAuthPortalBridge) UpdateExternalProviders(ctx context.Context, providers []*types.AuthProvider) error {
	bridge.externalProviders = providers

	// Regenerate and apply auth configuration
	if bridge.configManager != nil {
		newConfig, err := bridge.GenerateAuthPortalConfig(ctx)
		if err != nil {
			return fmt.Errorf("failed to generate auth config: %w", err)
		}

		if err := bridge.configManager.UpdateCaddyConfig(bridge.logger, "/apps/security", newConfig); err != nil {
			return fmt.Errorf("failed to update caddy config: %w", err)
		}

		bridge.logger.WithField("provider_count", len(providers)).Info("Updated auth portal configuration with external providers")
	}

	return nil
}

// GetExternalProviders returns the current external providers
func (bridge *CaddyAuthPortalBridge) GetExternalProviders() []*types.AuthProvider {
	return bridge.externalProviders
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

	// Add external provider backends
	for _, provider := range bridge.externalProviders {
		if !provider.Enabled {
			continue
		}

		// Check if provider type is licensed
		if !bridge.isProviderTypeLicensed(provider.Type) {
			bridge.logger.WithFields(logrus.Fields{
				"provider_id":   provider.ID,
				"provider_type": provider.Type,
			}).Warn("Skipping unlicensed provider type")
			continue
		}

		backend := bridge.generateExternalProviderBackend(provider)
		if backend != nil {
			backends = append(backends, backend)
		}
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
	config := map[string]any{
		"name": "twincore_local",
		"kind": "local",
		"params": map[string]any{
			"realm":          "twincore",
			"hash_algorithm": "bcrypt",
			"hash_cost":      12,
		},
	}

	// Configure based on sync mode
	if bridge.shouldUseFileSyncMode() {
		// File sync mode: Point to synced users.json file for standard caddy-security compatibility
		config["params"].(map[string]any)["path"] = filepath.Join(bridge.dataDir, "users.json")
		bridge.logger.Info("Identity store configured for file sync mode (caddy-security standard)")
	} else {
		// Database mode: Advanced TwinCore database-backed identity store
		// This leverages our LocalIdentityStore which directly reads from DuckDB
		// Path provided for interface compatibility, but LocalIdentityStore uses database
		config["params"].(map[string]any)["path"] = filepath.Join(bridge.dataDir, "users.json")
		config["params"].(map[string]any)["database_backend"] = "twincore_local" // Reference to our LocalIdentityStore
		config["params"].(map[string]any)["backend_type"] = "database"           // Indicate advanced backend
		bridge.logger.Info("Identity store configured for database mode (TwinCore advanced)")
	}

	return config
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
	// Try to get secret from environment variable first (production)
	if secret := os.Getenv("TWINCORE_JWT_SECRET"); secret != "" {
		bridge.logger.Debug("Using JWT secret from environment variable")
		return secret
	}

	// Try to get secret from configuration (note: JWTConfig uses PublicKey for verification, not secret generation)
	// For HMAC algorithms, we could potentially use a configured secret, but for now skip this
	// if bridge.config.APIAuth != nil && bridge.config.APIAuth.JWTConfig != nil { ... }

	// Check if we have a persistent secret file
	secretFile := filepath.Join(bridge.dataDir, "jwt_secret.key")
	if data, err := os.ReadFile(secretFile); err == nil {
		bridge.logger.Debug("Using JWT secret from persistent file")
		return string(data)
	}

	// Generate a new random secret and persist it
	secret := bridge.generateRandomSecret()
	if err := os.MkdirAll(bridge.dataDir, 0700); err != nil {
		bridge.logger.WithError(err).Warn("Failed to create data directory, using temporary secret")
		return secret
	}

	if err := os.WriteFile(secretFile, []byte(secret), 0600); err != nil {
		bridge.logger.WithError(err).Warn("Failed to persist JWT secret, using temporary secret")
		return secret
	}

	bridge.logger.WithField("secret_file", secretFile).Info("Generated and persisted new JWT secret")
	return secret
}

// generateRandomSecret creates a cryptographically secure random secret
func (bridge *CaddyAuthPortalBridge) generateRandomSecret() string {
	// Generate 32 random bytes (256 bits)
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		// Fallback to deterministic secret if random generation fails
		bridge.logger.WithError(err).Error("Failed to generate random secret, falling back to deterministic")
		return bridge.generateDeterministicSecret()
	}

	// Hash the random bytes to ensure consistent format
	hash := sha256.Sum256(randomBytes)
	return hex.EncodeToString(hash[:])
}

// generateDeterministicSecret creates a deterministic secret based on system information
func (bridge *CaddyAuthPortalBridge) generateDeterministicSecret() string {
	// Create a deterministic but unique secret based on available system information
	// This is a fallback when random generation fails
	baseString := fmt.Sprintf("twincore-jwt-%s-%s", bridge.dataDir, "fallback-v1")
	hash := sha256.Sum256([]byte(baseString))
	return hex.EncodeToString(hash[:])
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
	//
	// DESIGN INSIGHTS: Based on go-authcrunch/user_registry.go, caddy-security supports
	// sophisticated identity backends beyond simple JSON files. Our approach aligns
	// with caddy-security's UserRegistry interface and identity.Database abstraction.
	//
	// TWO DEPLOYMENT MODES:
	//
	// 1. DATABASE MODE (Default): Advanced TwinCore LocalIdentityStore integration
	//    - Uses custom LocalIdentityStore that implements caddy-security interfaces
	//    - Reads directly from DuckDB via SecurityRepositoryInterface
	//    - Follows go-authcrunch's UserRegistry pattern for database-backed storage
	//    - Pros: Secure, scalable, no file duplication, real-time consistency
	//    - Best for: Production deployments, clustered environments
	//
	// 2. FILE SYNC MODE (Compatibility): Standard caddy-security JSON file mode
	//    - Syncs users to JSON file for vanilla caddy-security compatibility
	//    - Uses standard file-based identity store that ships with caddy-security
	//    - Pros: Works with any caddy-security version without custom components
	//    - Cons: File duplication, sync overhead, potential consistency issues
	//    - Best for: Simple deployments, testing, migration scenarios

	// Check if we should use file-based sync for compatibility
	if bridge.shouldUseFileSyncMode() {
		return bridge.syncUsersToFile(ctx)
	}

	// Default: Use database-backed identity store (no sync needed)
	bridge.logger.Debug("Using database-backed identity store - no file sync needed")
	return nil
}

// shouldUseFileSyncMode determines if we should sync users to files for compatibility
func (bridge *CaddyAuthPortalBridge) shouldUseFileSyncMode() bool {
	// Check environment variable to force file sync mode
	if os.Getenv("TWINCORE_FORCE_FILE_SYNC") == "true" {
		return true
	}

	// Could add other conditions here, such as:
	// - Configuration setting
	// - License tier (enterprise vs basic)
	// - Deployment mode (standalone vs clustered)

	return false // Default to database mode
}

// syncUsersToFile syncs users from database to caddy-security compatible JSON file
func (bridge *CaddyAuthPortalBridge) syncUsersToFile(ctx context.Context) error {
	bridge.logger.Info("Syncing users to file for caddy-security compatibility")

	// Get all users from database
	users, err := bridge.identityStore.ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("failed to list users from database: %w", err)
	}

	// Convert to caddy-security format
	caddyUsers := make(map[string]any)
	for _, user := range users {
		// Only include essential fields, exclude sensitive database metadata
		caddyUsers[user.Username] = map[string]any{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
			"name":     user.FullName,
			"roles":    user.Roles,
			"password": user.Password, // Already bcrypt hashed
			"disabled": user.Disabled,
			// Note: Exclude database-specific fields for security
		}
	}

	// Write to secure location with proper permissions
	usersFile := filepath.Join(bridge.dataDir, "users.json")
	if err := bridge.writeUsersFileSecurely(usersFile, caddyUsers); err != nil {
		return fmt.Errorf("failed to write users file: %w", err)
	}

	bridge.logger.WithFields(logrus.Fields{
		"user_count": len(users),
		"file_path":  usersFile,
		"mode":       "file_sync_compatibility",
	}).Info("Successfully synced users to caddy-security file")

	return nil
}

// writeUsersFileSecurely writes users data to file with proper security measures
func (bridge *CaddyAuthPortalBridge) writeUsersFileSecurely(filePath string, users map[string]any) error {
	// Ensure directory exists with secure permissions
	if err := os.MkdirAll(filepath.Dir(filePath), 0700); err != nil {
		return fmt.Errorf("failed to create users directory: %w", err)
	}

	// Marshal users data to JSON
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal users data: %w", err)
	}

	// Write to temporary file first (atomic operation)
	tempFile := filePath + ".tmp"
	if err := os.WriteFile(tempFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write temporary users file: %w", err)
	}

	// Atomic rename to final location
	if err := os.Rename(tempFile, filePath); err != nil {
		os.Remove(tempFile) // Clean up temp file on failure
		return fmt.Errorf("failed to rename users file: %w", err)
	}

	bridge.logger.WithField("file_path", filePath).Debug("Users file written securely")
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

// Helper methods for external provider backend generation

func (bridge *CaddyAuthPortalBridge) isProviderTypeLicensed(providerType string) bool {
	ctx := context.Background()
	switch providerType {
	case types.AuthProviderTypeLDAP:
		return bridge.licenseChecker.IsSystemFeatureEnabled(ctx, "ldap_auth")
	case types.AuthProviderTypeSAML:
		return bridge.licenseChecker.IsSystemFeatureEnabled(ctx, "saml_auth")
	case types.AuthProviderTypeOIDC:
		return bridge.licenseChecker.IsSystemFeatureEnabled(ctx, "oidc_auth")
	case types.AuthProviderTypeOAuth2:
		return bridge.licenseChecker.IsSystemFeatureEnabled(ctx, "oauth2_auth")
	default:
		return false
	}
}

func (bridge *CaddyAuthPortalBridge) generateExternalProviderBackend(provider *types.AuthProvider) map[string]any {
	switch provider.Type {
	case types.AuthProviderTypeLDAP:
		return bridge.generateLDAPBackendFromProvider(provider)
	case types.AuthProviderTypeSAML:
		return bridge.generateSAMLBackend(provider)
	case types.AuthProviderTypeOIDC:
		return bridge.generateOIDCBackend(provider)
	case types.AuthProviderTypeOAuth2:
		return bridge.generateOAuth2Backend(provider)
	default:
		bridge.logger.WithField("provider_type", provider.Type).Error("Unsupported provider type")
		return nil
	}
}

func (bridge *CaddyAuthPortalBridge) generateLDAPBackendFromProvider(provider *types.AuthProvider) map[string]any {
	config := provider.Config

	backend := map[string]any{
		"name":   fmt.Sprintf("%s_backend", provider.ID),
		"method": "ldap",
		"realm":  provider.ID,
	}

	// Map provider config to caddy-auth-portal LDAP config
	if server, ok := config["server"].(string); ok {
		backend["address"] = server
	}
	if port, ok := config["port"].(float64); ok {
		backend["port"] = int(port)
	}
	if baseDN, ok := config["base_dn"].(string); ok {
		backend["base_dn"] = baseDN
	}
	if bindDN, ok := config["bind_dn"].(string); ok {
		backend["bind_dn"] = bindDN
	}
	if bindPassword, ok := config["bind_password"].(string); ok {
		backend["bind_password"] = bindPassword
	}
	if userFilter, ok := config["user_filter"].(string); ok {
		backend["user_filter"] = userFilter
	}

	// Add TLS configuration if present
	if tlsConfig, ok := config["tls"].(map[string]any); ok {
		if enabled, ok := tlsConfig["enabled"].(bool); ok && enabled {
			backend["tls"] = map[string]any{
				"enabled": true,
			}
			if insecure, ok := tlsConfig["insecure_skip_verify"].(bool); ok {
				backend["tls"].(map[string]any)["insecure_skip_verify"] = insecure
			}
		}
	}

	return backend
}

func (bridge *CaddyAuthPortalBridge) generateSAMLBackend(provider *types.AuthProvider) map[string]any {
	config := provider.Config

	backend := map[string]any{
		"name":   fmt.Sprintf("%s_backend", provider.ID),
		"method": "saml",
		"realm":  provider.ID,
	}

	// Map provider config to caddy-auth-portal SAML config
	if entityID, ok := config["entity_id"].(string); ok {
		backend["entity_id"] = entityID
	}
	if metadataURL, ok := config["metadata_url"].(string); ok {
		backend["idp_metadata_location"] = metadataURL
	}
	if acsURL, ok := config["acs_url"].(string); ok {
		backend["acs_url"] = acsURL
	}

	// Add attribute mappings if present
	if attrs, ok := config["attributes"].(map[string]any); ok {
		backend["attributes"] = attrs
	} else {
		// Use default SAML attribute mapping
		backend["attributes"] = map[string]any{
			"name":  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
			"email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
			"roles": "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
		}
	}

	return backend
}

func (bridge *CaddyAuthPortalBridge) generateOIDCBackend(provider *types.AuthProvider) map[string]any {
	config := provider.Config

	backend := map[string]any{
		"name":     fmt.Sprintf("%s_backend", provider.ID),
		"method":   "oauth2",
		"realm":    provider.ID,
		"provider": "oidc",
	}

	// Map provider config to caddy-auth-portal OIDC config
	if issuer, ok := config["issuer"].(string); ok {
		backend["authorization_url"] = fmt.Sprintf("%s/auth", issuer)
		backend["token_url"] = fmt.Sprintf("%s/token", issuer)
		backend["user_info_url"] = fmt.Sprintf("%s/userinfo", issuer)
		backend["jwks_url"] = fmt.Sprintf("%s/certs", issuer)
		backend["discovery_url"] = fmt.Sprintf("%s/.well-known/openid_configuration", issuer)
	}
	if clientID, ok := config["client_id"].(string); ok {
		backend["client_id"] = clientID
	}
	if clientSecret, ok := config["client_secret"].(string); ok {
		backend["client_secret"] = clientSecret
	}
	if scopes, ok := config["scopes"].([]any); ok {
		backend["scopes"] = scopes
	} else {
		// Default OIDC scopes
		backend["scopes"] = []string{"openid", "profile", "email"}
	}

	// Add attribute mappings if present
	if attrs, ok := config["attributes"].(map[string]any); ok {
		backend["attributes"] = attrs
	} else {
		// Use default OIDC attribute mapping
		backend["attributes"] = map[string]any{
			"name":  "preferred_username",
			"email": "email",
			"roles": "roles",
		}
	}

	return backend
}

func (bridge *CaddyAuthPortalBridge) generateOAuth2Backend(provider *types.AuthProvider) map[string]any {
	config := provider.Config

	backend := map[string]any{
		"name":   fmt.Sprintf("%s_backend", provider.ID),
		"method": "oauth2",
		"realm":  provider.ID,
	}

	// Check if it's a known provider
	if providerName, ok := config["provider"].(string); ok {
		backend["provider"] = providerName
	} else {
		backend["provider"] = "generic"
	}

	// Map provider config to caddy-auth-portal OAuth2 config
	if clientID, ok := config["client_id"].(string); ok {
		backend["client_id"] = clientID
	}
	if clientSecret, ok := config["client_secret"].(string); ok {
		backend["client_secret"] = clientSecret
	}
	if authURL, ok := config["authorization_url"].(string); ok {
		backend["authorization_url"] = authURL
	}
	if tokenURL, ok := config["token_url"].(string); ok {
		backend["token_url"] = tokenURL
	}
	if userInfoURL, ok := config["user_info_url"].(string); ok {
		backend["user_info_url"] = userInfoURL
	}
	if scopes, ok := config["scopes"].([]any); ok {
		backend["scopes"] = scopes
	}

	// Add attribute mappings if present
	if attrs, ok := config["attributes"].(map[string]any); ok {
		backend["attributes"] = attrs
	} else {
		// Use default OAuth2 attribute mapping
		backend["attributes"] = map[string]any{
			"name":  "login",
			"email": "email",
			"roles": "roles",
		}
	}

	return backend
}
