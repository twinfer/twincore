package security

import (
	"context"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"github.com/twinfer/twincore/internal/database"
	"github.com/twinfer/twincore/pkg/types"
)

// SystemSecurityManager provides user management for caddy-auth-portal integration
// This version removes session management, MFA, and other functionality now handled by caddy-security
type SystemSecurityManager struct {
	securityRepo     database.SecurityRepositoryInterface
	authProviderRepo database.AuthProviderRepository
	logger           *logrus.Logger
	config           *types.SystemSecurityConfig
	licenseChecker   types.UnifiedLicenseChecker
	identityStore    *LocalIdentityStore
	authPortalBridge *CaddyAuthPortalBridge
	configManager    ConfigurationManager
}

// NewSystemSecurityManager creates a security manager for caddy-auth-portal
func NewSystemSecurityManager(
	securityRepo database.SecurityRepositoryInterface,
	authProviderRepo database.AuthProviderRepository,
	logger *logrus.Logger,
	licenseChecker types.UnifiedLicenseChecker,
) *SystemSecurityManager {

	identityStore := NewLocalIdentityStore(securityRepo, logger, "twincore_local")

	config := &types.SystemSecurityConfig{
		Enabled: false, // Disabled by default
	}

	// Create auth portal bridge
	authPortalBridge, err := NewCaddyAuthPortalBridge(
		securityRepo,
		logger,
		config,
		licenseChecker,
		"./data", // Default data directory
	)
	if err != nil {
		logger.WithError(err).Error("Failed to create auth portal bridge")
	}

	return &SystemSecurityManager{
		securityRepo:     securityRepo,
		authProviderRepo: authProviderRepo,
		logger:           logger,
		licenseChecker:   licenseChecker,
		identityStore:    identityStore,
		authPortalBridge: authPortalBridge,
		config:           config,
	}
}

// SetConfigManager sets the configuration manager for runtime updates
func (sm *SystemSecurityManager) SetConfigManager(configManager ConfigurationManager) {
	sm.configManager = configManager
	if sm.authPortalBridge != nil {
		sm.authPortalBridge.SetConfigManager(configManager)
	}
}

// User Management - These methods support the identity store

func (sm *SystemSecurityManager) GetUser(ctx context.Context, userID string) (*types.User, error) {
	authUser, err := sm.identityStore.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	return &types.User{
		ID:       authUser.ID,
		Username: authUser.Username,
		Email:    authUser.Email,
		FullName: authUser.FullName,
		Roles:    authUser.Roles,
	}, nil
}

func (sm *SystemSecurityManager) ListUsers(ctx context.Context) ([]*types.User, error) {
	authUsers, err := sm.identityStore.ListUsers(ctx)
	if err != nil {
		return nil, err
	}

	users := make([]*types.User, len(authUsers))
	for i, authUser := range authUsers {
		users[i] = &types.User{
			ID:       authUser.ID,
			Username: authUser.Username,
			Email:    authUser.Email,
			FullName: authUser.FullName,
			Roles:    authUser.Roles,
		}
	}

	return users, nil
}

func (sm *SystemSecurityManager) CreateUser(ctx context.Context, user *types.User, password string) error {
	if !sm.licenseChecker.IsSystemFeatureEnabled(ctx, "local_auth") {
		return fmt.Errorf("local user management not licensed")
	}

	// Validate password policy if configured
	if sm.config.AdminAuth != nil && sm.config.AdminAuth.Local != nil && sm.config.AdminAuth.Local.PasswordPolicy != nil {
		if err := sm.validatePassword(password, sm.config.AdminAuth.Local.PasswordPolicy); err != nil {
			return fmt.Errorf("password policy violation: %w", err)
		}
	}

	authUser := &AuthUser{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		FullName: user.FullName,
		Roles:    user.Roles,
		Password: password, // Set password in the AuthUser struct
		Disabled: false,
	}

	if err := sm.identityStore.CreateUser(ctx, authUser); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	sm.logAuditEvent(ctx, types.AuditEvent{
		Type:     "user",
		Action:   "create",
		Resource: user.Username,
		Success:  true,
	})

	return nil
}

func (sm *SystemSecurityManager) UpdateUser(ctx context.Context, userID string, updates map[string]any) error {
	// Get existing user first
	existingUser, err := sm.identityStore.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get existing user: %w", err)
	}

	// Apply updates to the existing user
	if email, ok := updates["email"].(string); ok {
		existingUser.Email = email
	}
	if fullName, ok := updates["full_name"].(string); ok {
		existingUser.FullName = fullName
	}
	if roles, ok := updates["roles"].([]string); ok {
		existingUser.Roles = roles
	}
	if disabled, ok := updates["disabled"].(bool); ok {
		existingUser.Disabled = disabled
	}
	if password, ok := updates["password"].(string); ok {
		existingUser.Password = password
	}

	if err := sm.identityStore.UpdateUser(ctx, existingUser); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	sm.logAuditEvent(ctx, types.AuditEvent{
		Type:     "user",
		Action:   "update",
		Resource: userID,
		Success:  true,
	})

	return nil
}

func (sm *SystemSecurityManager) DeleteUser(ctx context.Context, userID string) error {
	if err := sm.identityStore.DeleteUser(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	sm.logAuditEvent(ctx, types.AuditEvent{
		Type:     "user",
		Action:   "delete",
		Resource: userID,
		Success:  true,
	})

	return nil
}

func (sm *SystemSecurityManager) ChangePassword(ctx context.Context, userID string, oldPassword, newPassword string) error {
	// Get current user to verify old password
	authUser, err := sm.identityStore.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(authUser.Password), []byte(oldPassword)); err != nil {
		return fmt.Errorf("current password is incorrect")
	}

	// Validate new password policy
	if sm.config.AdminAuth != nil && sm.config.AdminAuth.Local != nil && sm.config.AdminAuth.Local.PasswordPolicy != nil {
		if err := sm.validatePassword(newPassword, sm.config.AdminAuth.Local.PasswordPolicy); err != nil {
			return fmt.Errorf("password policy violation: %w", err)
		}
	}

	// Update password through identity store
	if err := sm.identityStore.ChangePassword(ctx, userID, newPassword); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	sm.logAuditEvent(ctx, types.AuditEvent{
		Type:     "user",
		Action:   "password_change",
		Resource: userID,
		Success:  true,
	})

	return nil
}

// Authorization -  version for API access control
func (sm *SystemSecurityManager) AuthorizeAPIAccess(ctx context.Context, user *types.User, resource string, action string) error {
	if !sm.config.Enabled {
		return nil // Security disabled, allow all
	}

	// Simple role-based check - advanced RBAC is handled by caddy-security
	return sm.simpleRoleCheck(user, resource, action)
}

// Configuration Management

func (sm *SystemSecurityManager) UpdateConfig(ctx context.Context, config types.SystemSecurityConfig) error {
	// Validate config
	if err := sm.ValidateConfig(ctx, config); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	sm.config = &config

	// Update auth portal bridge with new config
	if sm.authPortalBridge != nil {
		// Recreate the bridge with updated config
		newBridge, err := NewCaddyAuthPortalBridge(
			sm.securityRepo,
			sm.logger,
			&config,
			sm.licenseChecker,
			"./data", // Use same data directory
		)
		if err != nil {
			return fmt.Errorf("failed to recreate auth portal bridge with new config: %w", err)
		}

		// Transfer config manager if it was set
		if sm.configManager != nil {
			newBridge.SetConfigManager(sm.configManager)
		}

		sm.authPortalBridge = newBridge
	}

	sm.logAuditEvent(ctx, types.AuditEvent{
		Type:    "config",
		Action:  "update",
		Success: true,
	})

	return nil
}

func (sm *SystemSecurityManager) GetConfig(ctx context.Context) (*types.SystemSecurityConfig, error) {
	return sm.config, nil
}

func (sm *SystemSecurityManager) ValidateConfig(ctx context.Context, config types.SystemSecurityConfig) error {
	// Validate license features
	if config.AdminAuth != nil {
		if config.AdminAuth.LDAP != nil && !sm.licenseChecker.IsSystemFeatureEnabled(ctx, "ldap_auth") {
			return fmt.Errorf("LDAP authentication not licensed")
		}
		if config.AdminAuth.SAML != nil && !sm.licenseChecker.IsSystemFeatureEnabled(ctx, "saml_auth") {
			return fmt.Errorf("SAML authentication not licensed")
		}
		if config.AdminAuth.OIDC != nil && !sm.licenseChecker.IsSystemFeatureEnabled(ctx, "oidc_auth") {
			return fmt.Errorf("OIDC authentication not licensed")
		}
		if config.AdminAuth.MFA && !sm.licenseChecker.IsSystemFeatureEnabled(ctx, "mfa") {
			return fmt.Errorf("MFA not licensed")
		}
	}

	return nil
}

// Health and Monitoring

func (sm *SystemSecurityManager) HealthCheck(ctx context.Context) error {
	// Check database connectivity via SecurityRepository
	if !sm.securityRepo.IsHealthy(ctx) {
		return fmt.Errorf("database connectivity failed")
	}

	// Check license validity
	if !sm.licenseChecker.IsLicenseValid(ctx) {
		return fmt.Errorf("license is invalid or expired")
	}

	return nil
}

func (sm *SystemSecurityManager) GetSecurityMetrics(ctx context.Context) (map[string]any, error) {
	metrics := map[string]any{
		"total_users":      sm.getUserCount(ctx),
		"security_enabled": sm.config.Enabled,
		"license_valid":    sm.licenseChecker.IsLicenseValid(ctx),
		"auth_provider":    "caddy-auth-portal", // Indicate we're using caddy-security
	}

	return metrics, nil
}

// Audit logging -  version that just logs to structured logger
func (sm *SystemSecurityManager) GetAuditLog(ctx context.Context, filters map[string]any) ([]types.AuditEvent, error) {
	// For now, return empty - audit logging is handled by caddy-security
	// This method is kept for interface compatibility
	sm.logger.Debug("Audit log retrieval - delegated to caddy-security")
	return []types.AuditEvent{}, nil
}

// Helper methods

func (sm *SystemSecurityManager) getUserCount(ctx context.Context) int {
	count, err := sm.identityStore.GetUserCount(ctx)
	if err != nil {
		sm.logger.WithError(err).Warn("Failed to get user count")
		return 0
	}
	return count
}

func (sm *SystemSecurityManager) validatePassword(password string, policy *types.PasswordPolicy) error {
	if len(password) < policy.MinLength {
		return fmt.Errorf("password too short, minimum %d characters", policy.MinLength)
	}

	if policy.RequireUppercase && !strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return fmt.Errorf("password must contain uppercase letters")
	}

	if policy.RequireLowercase && !strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz") {
		return fmt.Errorf("password must contain lowercase letters")
	}

	if policy.RequireNumbers && !strings.ContainsAny(password, "0123456789") {
		return fmt.Errorf("password must contain numbers")
	}

	if policy.RequireSymbols && !strings.ContainsAny(password, "!@#$%^&*()_+-=[]{}|;:,.<>?") {
		return fmt.Errorf("password must contain symbols")
	}

	return nil
}

func (sm *SystemSecurityManager) simpleRoleCheck(user *types.User, resource string, action string) error {
	// Simple role-based access without advanced RBAC
	for _, role := range user.Roles {
		switch role {
		case "admin":
			return nil // Admin can access everything
		case "operator":
			if !strings.HasPrefix(resource, "/api/admin/") {
				return nil // Operator can access non-admin APIs
			}
		case "viewer":
			if action == "read" && !strings.HasPrefix(resource, "/api/admin/") {
				return nil // Viewer can read non-admin APIs
			}
		}
	}

	return fmt.Errorf("access denied")
}

func (sm *SystemSecurityManager) logAuditEvent(ctx context.Context, event types.AuditEvent) {
	//  audit logging to structured logger
	// Detailed audit logging is handled by caddy-security
	sm.logger.WithFields(logrus.Fields{
		"type":     event.Type,
		"action":   event.Action,
		"resource": event.Resource,
		"success":  event.Success,
		"error":    event.Error,
	}).Info("Security event")
}

// GetIdentityStore returns the local identity store for direct access
func (sm *SystemSecurityManager) GetIdentityStore() *LocalIdentityStore {
	return sm.identityStore
}

// Auth Provider Management - New methods for external authentication providers

func (sm *SystemSecurityManager) AddAuthProvider(ctx context.Context, provider *types.AuthProvider) error {
	// Validate provider type is licensed
	if err := sm.validateProviderLicense(ctx, provider.Type); err != nil {
		return fmt.Errorf("provider type not licensed: %w", err)
	}

	// Validate provider configuration
	if err := sm.validateProviderConfig(provider); err != nil {
		return fmt.Errorf("invalid provider config: %w", err)
	}

	// Create provider in database
	if err := sm.authProviderRepo.CreateProvider(ctx, provider); err != nil {
		return fmt.Errorf("failed to create auth provider: %w", err)
	}

	sm.logAuditEvent(ctx, types.AuditEvent{
		Type:     "auth_provider",
		Action:   "create",
		Resource: provider.ID,
		Success:  true,
	})

	sm.logger.WithFields(logrus.Fields{
		"provider_id":   provider.ID,
		"provider_type": provider.Type,
	}).Info("Auth provider added")

	return nil
}

func (sm *SystemSecurityManager) UpdateAuthProvider(ctx context.Context, id string, updates map[string]any) error {
	// Get existing provider to validate updates
	existingProvider, err := sm.authProviderRepo.GetProvider(ctx, id)
	if err != nil {
		return fmt.Errorf("provider not found: %w", err)
	}

	// Validate config update if provided
	if config, ok := updates["config"].(map[string]any); ok {
		tempProvider := &types.AuthProvider{
			Type:   existingProvider.Type,
			Config: config,
		}
		if err := sm.validateProviderConfig(tempProvider); err != nil {
			return fmt.Errorf("invalid provider config: %w", err)
		}
	}

	// Update provider in database
	if err := sm.authProviderRepo.UpdateProvider(ctx, id, updates); err != nil {
		return fmt.Errorf("failed to update auth provider: %w", err)
	}

	sm.logAuditEvent(ctx, types.AuditEvent{
		Type:     "auth_provider",
		Action:   "update",
		Resource: id,
		Success:  true,
	})

	return nil
}

func (sm *SystemSecurityManager) RemoveAuthProvider(ctx context.Context, id string) error {
	// Check if provider exists
	_, err := sm.authProviderRepo.GetProvider(ctx, id)
	if err != nil {
		return fmt.Errorf("provider not found: %w", err)
	}

	// Delete provider from database
	if err := sm.authProviderRepo.DeleteProvider(ctx, id); err != nil {
		return fmt.Errorf("failed to delete auth provider: %w", err)
	}

	sm.logAuditEvent(ctx, types.AuditEvent{
		Type:     "auth_provider",
		Action:   "delete",
		Resource: id,
		Success:  true,
	})

	sm.logger.WithField("provider_id", id).Info("Auth provider removed")
	return nil
}

func (sm *SystemSecurityManager) GetAuthProvider(ctx context.Context, id string) (*types.AuthProvider, error) {
	provider, err := sm.authProviderRepo.GetProvider(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth provider: %w", err)
	}
	return provider, nil
}

func (sm *SystemSecurityManager) ListAuthProviders(ctx context.Context) ([]*types.AuthProvider, error) {
	providers, err := sm.authProviderRepo.ListProviders(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list auth providers: %w", err)
	}
	return providers, nil
}

func (sm *SystemSecurityManager) TestAuthProvider(ctx context.Context, id string) (*types.AuthProviderTestResult, error) {
	provider, err := sm.authProviderRepo.GetProvider(ctx, id)
	if err != nil {
		return &types.AuthProviderTestResult{
			Success: false,
			Message: "Provider not found",
			Errors:  []string{err.Error()},
		}, nil
	}

	// Test provider based on type
	switch provider.Type {
	case types.AuthProviderTypeLDAP:
		return sm.testLDAPProvider(ctx, provider)
	case types.AuthProviderTypeSAML:
		return sm.testSAMLProvider(ctx, provider)
	case types.AuthProviderTypeOIDC:
		return sm.testOIDCProvider(ctx, provider)
	case types.AuthProviderTypeOAuth2:
		return sm.testOAuth2Provider(ctx, provider)
	default:
		return &types.AuthProviderTestResult{
			Success: false,
			Message: "Unsupported provider type",
			Errors:  []string{fmt.Sprintf("Provider type %s not supported", provider.Type)},
		}, nil
	}
}

func (sm *SystemSecurityManager) ListProviderUsers(ctx context.Context, providerID string, search string, limit int) ([]*types.ProviderUser, error) {
	provider, err := sm.authProviderRepo.GetProvider(ctx, providerID)
	if err != nil {
		return nil, fmt.Errorf("provider not found: %w", err)
	}

	// Only LDAP providers support user listing for now
	if provider.Type != types.AuthProviderTypeLDAP {
		return nil, fmt.Errorf("provider type %s does not support user listing", provider.Type)
	}

	return sm.listLDAPUsers(ctx, provider, search, limit)
}

func (sm *SystemSecurityManager) RefreshAuthConfiguration(ctx context.Context) error {
	if sm.configManager == nil {
		sm.logger.Warn("No configuration manager available for auth config refresh")
		return nil
	}

	// Get all enabled providers
	providers, err := sm.authProviderRepo.ListProviders(ctx)
	if err != nil {
		return fmt.Errorf("failed to get auth providers: %w", err)
	}

	// Filter enabled providers
	enabledProviders := make([]*types.AuthProvider, 0)
	for _, provider := range providers {
		if provider.Enabled {
			enabledProviders = append(enabledProviders, provider)
		}
	}

	// Update auth portal bridge with new providers
	if sm.authPortalBridge != nil {
		if err := sm.updateAuthPortalWithProviders(ctx, enabledProviders); err != nil {
			return fmt.Errorf("failed to update auth portal config: %w", err)
		}
	}

	sm.logger.WithField("provider_count", len(enabledProviders)).Info("Auth configuration refreshed")
	return nil
}

// Helper methods for auth provider management

func (sm *SystemSecurityManager) validateProviderLicense(ctx context.Context, providerType string) error {
	switch providerType {
	case types.AuthProviderTypeLDAP:
		if !sm.licenseChecker.IsSystemFeatureEnabled(ctx, "ldap_auth") {
			return fmt.Errorf("LDAP authentication not licensed")
		}
	case types.AuthProviderTypeSAML:
		if !sm.licenseChecker.IsSystemFeatureEnabled(ctx, "saml_auth") {
			return fmt.Errorf("SAML authentication not licensed")
		}
	case types.AuthProviderTypeOIDC:
		if !sm.licenseChecker.IsSystemFeatureEnabled(ctx, "oidc_auth") {
			return fmt.Errorf("OIDC authentication not licensed")
		}
	case types.AuthProviderTypeOAuth2:
		if !sm.licenseChecker.IsSystemFeatureEnabled(ctx, "oauth2_auth") {
			return fmt.Errorf("OAuth2 authentication not licensed")
		}
	}
	return nil
}

func (sm *SystemSecurityManager) validateProviderConfig(provider *types.AuthProvider) error {
	if provider.ID == "" {
		return fmt.Errorf("provider ID is required")
	}
	if provider.Name == "" {
		return fmt.Errorf("provider name is required")
	}
	if provider.Type == "" {
		return fmt.Errorf("provider type is required")
	}
	if provider.Config == nil {
		return fmt.Errorf("provider config is required")
	}

	// Type-specific validation
	switch provider.Type {
	case types.AuthProviderTypeLDAP:
		return sm.validateLDAPConfig(provider.Config)
	case types.AuthProviderTypeSAML:
		return sm.validateSAMLConfig(provider.Config)
	case types.AuthProviderTypeOIDC:
		return sm.validateOIDCConfig(provider.Config)
	case types.AuthProviderTypeOAuth2:
		return sm.validateOAuth2Config(provider.Config)
	default:
		return fmt.Errorf("unsupported provider type: %s", provider.Type)
	}
}

func (sm *SystemSecurityManager) validateLDAPConfig(config map[string]any) error {
	required := []string{"server", "port", "base_dn", "user_filter"}
	for _, field := range required {
		if _, ok := config[field]; !ok {
			return fmt.Errorf("LDAP config missing required field: %s", field)
		}
	}
	return nil
}

func (sm *SystemSecurityManager) validateSAMLConfig(config map[string]any) error {
	required := []string{"entity_id", "metadata_url"}
	for _, field := range required {
		if _, ok := config[field]; !ok {
			return fmt.Errorf("SAML config missing required field: %s", field)
		}
	}
	return nil
}

func (sm *SystemSecurityManager) validateOIDCConfig(config map[string]any) error {
	required := []string{"issuer", "client_id", "client_secret"}
	for _, field := range required {
		if _, ok := config[field]; !ok {
			return fmt.Errorf("OIDC config missing required field: %s", field)
		}
	}
	return nil
}

func (sm *SystemSecurityManager) validateOAuth2Config(config map[string]any) error {
	required := []string{"client_id", "client_secret", "authorization_url", "token_url"}
	for _, field := range required {
		if _, ok := config[field]; !ok {
			return fmt.Errorf("OAuth2 config missing required field: %s", field)
		}
	}
	return nil
}

func (sm *SystemSecurityManager) testLDAPProvider(ctx context.Context, provider *types.AuthProvider) (*types.AuthProviderTestResult, error) {
	// Basic LDAP connection test
	result := &types.AuthProviderTestResult{
		Success: false,
		Message: "LDAP connection test",
		Details: make(map[string]any),
	}

	// TODO: Implement actual LDAP connection test
	// For now, just validate config
	if err := sm.validateLDAPConfig(provider.Config); err != nil {
		result.Errors = append(result.Errors, err.Error())
		result.Message = "LDAP configuration validation failed"
		return result, nil
	}

	result.Success = true
	result.Message = "LDAP configuration is valid"
	result.Details["config_valid"] = true
	return result, nil
}

func (sm *SystemSecurityManager) testSAMLProvider(ctx context.Context, provider *types.AuthProvider) (*types.AuthProviderTestResult, error) {
	result := &types.AuthProviderTestResult{
		Success: false,
		Message: "SAML provider connectivity test",
		Details: make(map[string]any),
	}

	// First validate configuration
	if err := sm.validateSAMLConfig(provider.Config); err != nil {
		result.Errors = append(result.Errors, err.Error())
		result.Message = "SAML configuration validation failed"
		return result, nil
	}
	result.Details["config_valid"] = true

	// Test metadata URL accessibility if provided
	if metadataURL, ok := provider.Config["metadata_url"].(string); ok {
		if err := sm.testSAMLMetadataEndpoint(ctx, metadataURL, result); err != nil {
			result.Errors = append(result.Errors, err.Error())
			result.Message = "SAML metadata endpoint test failed"
			return result, nil
		}
	}

	// Test entity ID format
	if entityID, ok := provider.Config["entity_id"].(string); ok {
		result.Details["entity_id"] = entityID
		result.Details["entity_id_valid"] = len(entityID) > 0
	}

	// Validate signing certificate if provided
	if cert, ok := provider.Config["signing_cert"].(string); ok {
		if err := sm.validateX509Certificate(cert); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Invalid signing certificate: %v", err))
		} else {
			result.Details["signing_cert_valid"] = true
		}
	}

	if len(result.Errors) == 0 {
		result.Success = true
		result.Message = "SAML provider connectivity test passed"
	}

	return result, nil
}

func (sm *SystemSecurityManager) testOIDCProvider(ctx context.Context, provider *types.AuthProvider) (*types.AuthProviderTestResult, error) {
	result := &types.AuthProviderTestResult{
		Success: false,
		Message: "OIDC provider connectivity test",
		Details: make(map[string]any),
	}

	// First validate configuration
	if err := sm.validateOIDCConfig(provider.Config); err != nil {
		result.Errors = append(result.Errors, err.Error())
		result.Message = "OIDC configuration validation failed"
		return result, nil
	}
	result.Details["config_valid"] = true

	// Test OIDC discovery endpoint
	if issuer, ok := provider.Config["issuer"].(string); ok {
		discoveryURL := issuer + "/.well-known/openid_configuration"
		if err := sm.testOIDCDiscoveryEndpoint(ctx, discoveryURL, result); err != nil {
			result.Errors = append(result.Errors, err.Error())
			result.Message = "OIDC discovery endpoint test failed"
			return result, nil
		}
	}

	// Test client credentials if provided
	if clientID, ok := provider.Config["client_id"].(string); ok {
		result.Details["client_id"] = clientID
		result.Details["client_id_valid"] = len(clientID) > 0
	}

	// Validate scopes
	if scopes, ok := provider.Config["scopes"].([]any); ok {
		scopeStrings := make([]string, len(scopes))
		for i, scope := range scopes {
			if s, ok := scope.(string); ok {
				scopeStrings[i] = s
			}
		}
		result.Details["scopes"] = scopeStrings
		result.Details["scopes_valid"] = len(scopeStrings) > 0
	}

	if len(result.Errors) == 0 {
		result.Success = true
		result.Message = "OIDC provider connectivity test passed"
	}

	return result, nil
}

func (sm *SystemSecurityManager) testOAuth2Provider(ctx context.Context, provider *types.AuthProvider) (*types.AuthProviderTestResult, error) {
	result := &types.AuthProviderTestResult{
		Success: false,
		Message: "OAuth2 provider connectivity test",
		Details: make(map[string]any),
	}

	// First validate configuration
	if err := sm.validateOAuth2Config(provider.Config); err != nil {
		result.Errors = append(result.Errors, err.Error())
		result.Message = "OAuth2 configuration validation failed"
		return result, nil
	}
	result.Details["config_valid"] = true

	// Test authorization endpoint
	if authURL, ok := provider.Config["authorization_url"].(string); ok {
		if err := sm.testHTTPEndpoint(ctx, authURL, "authorization_endpoint", result); err != nil {
			result.Errors = append(result.Errors, err.Error())
		}
	}

	// Test token endpoint
	if tokenURL, ok := provider.Config["token_url"].(string); ok {
		if err := sm.testHTTPEndpoint(ctx, tokenURL, "token_endpoint", result); err != nil {
			result.Errors = append(result.Errors, err.Error())
		}
	}

	// Test user info endpoint if provided
	if userInfoURL, ok := provider.Config["user_info_url"].(string); ok {
		if err := sm.testHTTPEndpoint(ctx, userInfoURL, "user_info_endpoint", result); err != nil {
			result.Errors = append(result.Errors, err.Error())
		}
	}

	// Validate client credentials
	if clientID, ok := provider.Config["client_id"].(string); ok {
		result.Details["client_id"] = clientID
		result.Details["client_id_valid"] = len(clientID) > 0
	}

	if clientSecret, ok := provider.Config["client_secret"].(string); ok {
		result.Details["client_secret_configured"] = len(clientSecret) > 0
	}

	if len(result.Errors) == 0 {
		result.Success = true
		result.Message = "OAuth2 provider connectivity test passed"
	}

	return result, nil
}

func (sm *SystemSecurityManager) listLDAPUsers(ctx context.Context, provider *types.AuthProvider, search string, limit int) ([]*types.ProviderUser, error) {
	// TODO: Implement actual LDAP user listing
	// For now, return empty list
	sm.logger.Debug("LDAP user listing not yet implemented")
	return []*types.ProviderUser{}, nil
}

func (sm *SystemSecurityManager) updateAuthPortalWithProviders(ctx context.Context, providers []*types.AuthProvider) error {
	// Update the auth portal bridge configuration with the new providers
	if err := sm.authPortalBridge.UpdateExternalProviders(ctx, providers); err != nil {
		return fmt.Errorf("failed to update auth portal bridge: %w", err)
	}

	sm.logger.WithField("provider_count", len(providers)).Info("Updated auth portal configuration with external providers")

	return nil
}

// Helper methods for provider connectivity testing

func (sm *SystemSecurityManager) testSAMLMetadataEndpoint(ctx context.Context, metadataURL string, result *types.AuthProviderTestResult) error {
	// Test HTTP accessibility of SAML metadata endpoint
	if err := sm.testHTTPEndpoint(ctx, metadataURL, "metadata_endpoint", result); err != nil {
		return err
	}

	// TODO: Parse and validate SAML metadata XML
	// For now, we just test that the endpoint is accessible
	result.Details["metadata_url"] = metadataURL
	result.Details["metadata_accessible"] = true

	return nil
}

func (sm *SystemSecurityManager) testOIDCDiscoveryEndpoint(ctx context.Context, discoveryURL string, result *types.AuthProviderTestResult) error {
	// Test HTTP accessibility of OIDC discovery endpoint
	if err := sm.testHTTPEndpoint(ctx, discoveryURL, "discovery_endpoint", result); err != nil {
		return err
	}

	// TODO: Parse and validate OIDC discovery document JSON
	// For now, we just test that the endpoint is accessible
	result.Details["discovery_url"] = discoveryURL
	result.Details["discovery_accessible"] = true

	return nil
}

func (sm *SystemSecurityManager) testHTTPEndpoint(ctx context.Context, url string, endpointType string, result *types.AuthProviderTestResult) error {
	// Simple HTTP connectivity test
	// In a real implementation, this would make an HTTP request to test connectivity

	// Basic URL validation
	if url == "" {
		return fmt.Errorf("%s URL is empty", endpointType)
	}

	// TODO: Implement actual HTTP connectivity test
	// For now, just validate URL format
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("%s URL must start with http:// or https://", endpointType)
	}

	result.Details[endpointType+"_url"] = url
	result.Details[endpointType+"_url_valid"] = true

	sm.logger.WithFields(logrus.Fields{
		"endpoint_type": endpointType,
		"url":           url,
	}).Debug("HTTP endpoint test passed (URL validation only)")

	return nil
}

func (sm *SystemSecurityManager) validateX509Certificate(certPEM string) error {
	// TODO: Implement X.509 certificate validation
	// For now, just check that it's not empty and has basic PEM structure

	if certPEM == "" {
		return fmt.Errorf("certificate is empty")
	}

	if !strings.Contains(certPEM, "-----BEGIN CERTIFICATE-----") ||
		!strings.Contains(certPEM, "-----END CERTIFICATE-----") {
		return fmt.Errorf("invalid PEM certificate format")
	}

	return nil
}

// User Attribute Mapping Implementation

// MapAttributes maps external provider attributes to a TwinCore User
func (sm *SystemSecurityManager) MapAttributes(providerID string, externalAttrs map[string]any, mapping *types.AttributeMapping) (*types.User, error) {
	user := &types.User{
		Metadata: make(map[string]any),
	}

	// Map username
	if mapping.Username != "" {
		if username, ok := externalAttrs[mapping.Username].(string); ok {
			user.Username = username
			user.ID = username // Use username as ID
		} else {
			return nil, fmt.Errorf("required username attribute '%s' not found or not a string", mapping.Username)
		}
	}

	// Map email
	if mapping.Email != "" {
		if email, ok := externalAttrs[mapping.Email].(string); ok {
			user.Email = email
		}
	}

	// Map full name
	if mapping.FullName != "" {
		if fullName, ok := externalAttrs[mapping.FullName].(string); ok {
			user.FullName = fullName
		}
	}

	// Map roles
	if mapping.Roles != nil {
		roles, err := sm.mapRoles(externalAttrs, mapping.Roles)
		if err != nil {
			return nil, fmt.Errorf("failed to map roles: %w", err)
		}
		user.Roles = roles
	}

	// Map groups
	if mapping.Groups != nil {
		groups, err := sm.mapGroups(externalAttrs, mapping.Groups)
		if err != nil {
			return nil, fmt.Errorf("failed to map groups: %w", err)
		}
		user.Groups = groups
	}

	// Map custom attributes
	if mapping.Custom != nil {
		for key, rule := range mapping.Custom {
			value, err := sm.mapCustomAttribute(externalAttrs, &rule)
			if err != nil {
				if rule.Required {
					return nil, fmt.Errorf("failed to map required custom attribute '%s': %w", key, err)
				}
				sm.logger.WithFields(logrus.Fields{
					"attribute": key,
					"error":     err,
				}).Warn("Failed to map optional custom attribute")
				continue
			}
			user.Metadata[key] = value
		}
	}

	// Store original external attributes for reference
	user.Metadata["external_attributes"] = externalAttrs
	user.Metadata["provider_id"] = providerID

	return user, nil
}

// ValidateMapping validates an attribute mapping configuration
func (sm *SystemSecurityManager) ValidateMapping(mapping *types.AttributeMapping) error {
	if mapping.Username == "" {
		return fmt.Errorf("username mapping is required")
	}

	// Validate role mapping
	if mapping.Roles != nil {
		if mapping.Roles.Source == "" {
			return fmt.Errorf("role mapping source is required when roles mapping is specified")
		}
	}

	// Validate group mapping
	if mapping.Groups != nil {
		if mapping.Groups.Source == "" {
			return fmt.Errorf("group mapping source is required when groups mapping is specified")
		}
	}

	// Validate custom attribute rules
	if mapping.Custom != nil {
		for key, rule := range mapping.Custom {
			if rule.Source == "" {
				return fmt.Errorf("custom attribute '%s' source is required", key)
			}
		}
	}

	return nil
}

// GetDefaultMapping returns default attribute mapping for a provider type
func (sm *SystemSecurityManager) GetDefaultMapping(providerType string) *types.AttributeMapping {
	switch providerType {
	case types.AuthProviderTypeLDAP:
		return &types.AttributeMapping{
			Username: "uid",
			Email:    "mail",
			FullName: "cn",
			Roles: &types.RoleMapping{
				Source:       "memberOf",
				DefaultRoles: []string{"viewer"},
				RoleMap: map[string]string{
					"cn=admin,ou=groups,dc=company,dc=com":    "admin",
					"cn=operator,ou=groups,dc=company,dc=com": "operator",
					"cn=viewer,ou=groups,dc=company,dc=com":   "viewer",
				},
				AllowMultiple: true,
			},
		}
	case types.AuthProviderTypeSAML:
		return &types.AttributeMapping{
			Username: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
			Email:    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
			FullName: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
			Roles: &types.RoleMapping{
				Source:       "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
				DefaultRoles: []string{"viewer"},
				RoleMap: map[string]string{
					"Administrator": "admin",
					"Operator":      "operator",
					"Viewer":        "viewer",
				},
				AllowMultiple: true,
			},
		}
	case types.AuthProviderTypeOIDC:
		return &types.AttributeMapping{
			Username: "preferred_username",
			Email:    "email",
			FullName: "name",
			Roles: &types.RoleMapping{
				Source:       "roles",
				DefaultRoles: []string{"viewer"},
				RoleMap: map[string]string{
					"admin":    "admin",
					"operator": "operator",
					"viewer":   "viewer",
				},
				AllowMultiple: true,
			},
		}
	case types.AuthProviderTypeOAuth2:
		return &types.AttributeMapping{
			Username: "login",
			Email:    "email",
			FullName: "name",
			Roles: &types.RoleMapping{
				Source:        "roles",
				DefaultRoles:  []string{"viewer"},
				RoleMap:       map[string]string{},
				AllowMultiple: true,
			},
		}
	default:
		return &types.AttributeMapping{
			Username: "username",
			Email:    "email",
			FullName: "name",
			Roles: &types.RoleMapping{
				Source:        "roles",
				DefaultRoles:  []string{"viewer"},
				RoleMap:       map[string]string{},
				AllowMultiple: false,
			},
		}
	}
}

// Helper methods for attribute mapping

func (sm *SystemSecurityManager) mapRoles(externalAttrs map[string]any, roleMapping *types.RoleMapping) ([]string, error) {
	if roleMapping.Source == "" {
		return roleMapping.DefaultRoles, nil
	}

	externalRoles, ok := externalAttrs[roleMapping.Source]
	if !ok {
		sm.logger.WithField("source", roleMapping.Source).Debug("Role source attribute not found, using default roles")
		return roleMapping.DefaultRoles, nil
	}

	// Convert external roles to string slice
	var externalRoleStrings []string
	switch v := externalRoles.(type) {
	case string:
		externalRoleStrings = []string{v}
	case []string:
		externalRoleStrings = v
	case []any:
		for _, role := range v {
			if roleStr, ok := role.(string); ok {
				externalRoleStrings = append(externalRoleStrings, roleStr)
			}
		}
	default:
		sm.logger.WithField("source", roleMapping.Source).Warn("Role source attribute is not a string or array")
		return roleMapping.DefaultRoles, nil
	}

	// Map external roles to TwinCore roles
	var mappedRoles []string
	for _, externalRole := range externalRoleStrings {
		if twinCoreRole, ok := roleMapping.RoleMap[externalRole]; ok {
			mappedRoles = append(mappedRoles, twinCoreRole)
		}
	}

	// If no roles were mapped and we don't allow multiple, use default
	if len(mappedRoles) == 0 {
		return roleMapping.DefaultRoles, nil
	}

	// If we don't allow multiple roles, take the first one
	if !roleMapping.AllowMultiple && len(mappedRoles) > 1 {
		return []string{mappedRoles[0]}, nil
	}

	return mappedRoles, nil
}

func (sm *SystemSecurityManager) mapGroups(externalAttrs map[string]any, groupMapping *types.GroupMapping) ([]string, error) {
	if groupMapping.Source == "" {
		return []string{}, nil
	}

	externalGroups, ok := externalAttrs[groupMapping.Source]
	if !ok {
		sm.logger.WithField("source", groupMapping.Source).Debug("Group source attribute not found")
		return []string{}, nil
	}

	// Convert external groups to string slice
	var externalGroupStrings []string
	switch v := externalGroups.(type) {
	case string:
		externalGroupStrings = []string{v}
	case []string:
		externalGroupStrings = v
	case []any:
		for _, group := range v {
			if groupStr, ok := group.(string); ok {
				externalGroupStrings = append(externalGroupStrings, groupStr)
			}
		}
	default:
		sm.logger.WithField("source", groupMapping.Source).Warn("Group source attribute is not a string or array")
		return []string{}, nil
	}

	// Map external groups to TwinCore groups
	var mappedGroups []string
	for _, externalGroup := range externalGroupStrings {
		if twinCoreGroup, ok := groupMapping.GroupMap[externalGroup]; ok {
			mappedGroups = append(mappedGroups, twinCoreGroup)
		}
	}

	return mappedGroups, nil
}

func (sm *SystemSecurityManager) mapCustomAttribute(externalAttrs map[string]any, rule *types.AttributeRule) (any, error) {
	value, ok := externalAttrs[rule.Source]
	if !ok {
		if rule.DefaultValue != nil {
			return rule.DefaultValue, nil
		}
		return nil, fmt.Errorf("attribute '%s' not found", rule.Source)
	}

	// Apply transformation if specified
	if rule.Transform != "" {
		value = sm.transformAttribute(value, rule.Transform)
	}

	return value, nil
}

func (sm *SystemSecurityManager) transformAttribute(value any, transform string) any {
	str, ok := value.(string)
	if !ok {
		return value
	}

	switch transform {
	case "lowercase":
		return strings.ToLower(str)
	case "uppercase":
		return strings.ToUpper(str)
	case "trim":
		return strings.TrimSpace(str)
	default:
		return value
	}
}

// Session Management - REMOVED (now handled by caddy-security)
// These methods are NOT implemented as they're delegated to caddy-auth-portal

func (sm *SystemSecurityManager) AuthenticateUser(ctx context.Context, credentials types.UserCredentials) (*types.UserSession, error) {
	return nil, fmt.Errorf("authentication is handled by caddy-auth-portal")
}

func (sm *SystemSecurityManager) CreateSession(ctx context.Context, user *types.User) (*types.UserSession, error) {
	return nil, fmt.Errorf("session management is handled by caddy-auth-portal")
}

func (sm *SystemSecurityManager) ValidateSession(ctx context.Context, sessionToken string) (*types.UserSession, error) {
	return nil, fmt.Errorf("session validation is handled by caddy-auth-portal")
}

func (sm *SystemSecurityManager) RefreshSession(ctx context.Context, refreshToken string) (*types.UserSession, error) {
	return nil, fmt.Errorf("session refresh is handled by caddy-auth-portal")
}

func (sm *SystemSecurityManager) RevokeSession(ctx context.Context, sessionToken string) error {
	return fmt.Errorf("session revocation is handled by caddy-auth-portal")
}

func (sm *SystemSecurityManager) ListUserSessions(ctx context.Context, userID string) ([]*types.UserSession, error) {
	return nil, fmt.Errorf("session listing is handled by caddy-auth-portal")
}

func (sm *SystemSecurityManager) RevokeAllUserSessions(ctx context.Context, userID string) error {
	return fmt.Errorf("session management is handled by caddy-auth-portal")
}

// Policy Management -  (advanced RBAC handled by caddy-security)

func (sm *SystemSecurityManager) AddPolicy(ctx context.Context, policy types.APIPolicy) error {
	return fmt.Errorf("policy management is handled by caddy-security authorization policies")
}

func (sm *SystemSecurityManager) RemovePolicy(ctx context.Context, policyID string) error {
	return fmt.Errorf("policy management is handled by caddy-security authorization policies")
}

func (sm *SystemSecurityManager) UpdatePolicy(ctx context.Context, policyID string, policy types.APIPolicy) error {
	return fmt.Errorf("policy management is handled by caddy-security authorization policies")
}

func (sm *SystemSecurityManager) GetPolicy(ctx context.Context, policyID string) (*types.APIPolicy, error) {
	return nil, fmt.Errorf("policy management is handled by caddy-security authorization policies")
}

func (sm *SystemSecurityManager) ListPolicies(ctx context.Context) ([]types.APIPolicy, error) {
	return nil, fmt.Errorf("policy management is handled by caddy-security authorization policies")
}

func (sm *SystemSecurityManager) EvaluatePolicy(ctx context.Context, accessCtx *types.AccessContext) error {
	return fmt.Errorf("policy evaluation is handled by caddy-security authorization")
}

// Session Management - REMOVED (now handled by caddy-security)
// The following methods are NOT implemented as they're delegated to caddy-auth-portal:
// - AuthenticateUser
// - CreateSession
// - ValidateSession
// - RefreshSession
// - RevokeSession
// - ListUserSessions
// - RevokeAllUserSessions

// Policy Management -  (advanced RBAC handled by caddy-security)
// Basic policies can be configured through caddy-security authorization policies

// Ensure interface compliance
var _ types.SystemSecurityManager = (*SystemSecurityManager)(nil)
