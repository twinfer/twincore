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
	securityRepo   database.SecurityRepositoryInterface
	logger         *logrus.Logger
	config         *types.SystemSecurityConfig
	licenseChecker types.UnifiedLicenseChecker
	identityStore  *LocalIdentityStore
}

// NewSystemSecurityManager creates a  security manager for caddy-auth-portal
func NewSystemSecurityManager(
	securityRepo database.SecurityRepositoryInterface,
	logger *logrus.Logger,
	licenseChecker types.UnifiedLicenseChecker,
) *SystemSecurityManager {

	identityStore := NewLocalIdentityStore(securityRepo, logger, "twincore_local")

	return &SystemSecurityManager{
		securityRepo:   securityRepo,
		logger:         logger,
		licenseChecker: licenseChecker,
		identityStore:  identityStore,
		config: &types.SystemSecurityConfig{
			Enabled: false, // Disabled by default
		},
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
