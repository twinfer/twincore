package security

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"github.com/twinfer/twincore/pkg/types"
)

// DefaultSystemSecurityManager implements SystemSecurityManager interface
type DefaultSystemSecurityManager struct {
	db             *sql.DB
	logger         *logrus.Logger
	config         *types.SystemSecurityConfig
	jwtSecret      []byte
	sessions       map[string]*types.UserSession // In-memory session store (TODO: move to persistent store)
	licenseChecker types.UnifiedLicenseChecker
}

// NewDefaultSystemSecurityManager creates a new system security manager
func NewDefaultSystemSecurityManager(db *sql.DB, logger *logrus.Logger, licenseChecker types.UnifiedLicenseChecker) *DefaultSystemSecurityManager {
	// Generate random JWT secret if not provided
	jwtSecret := make([]byte, 32)
	rand.Read(jwtSecret)

	return &DefaultSystemSecurityManager{
		db:             db,
		logger:         logger,
		sessions:       make(map[string]*types.UserSession),
		jwtSecret:      jwtSecret,
		licenseChecker: licenseChecker,
		config: &types.SystemSecurityConfig{
			Enabled: false, // Disabled by default
		},
	}
}

// User Management

func (sm *DefaultSystemSecurityManager) AuthenticateUser(ctx context.Context, credentials types.UserCredentials) (*types.UserSession, error) {
	if !sm.config.Enabled {
		return nil, fmt.Errorf("system security is disabled")
	}

	// Check if local auth is enabled by license
	if !sm.licenseChecker.IsSystemFeatureEnabled(ctx, "local_auth") {
		return nil, fmt.Errorf("local authentication not licensed")
	}

	sm.logger.WithField("username", credentials.Username).Debug("Authenticating user")

	// Get user from database
	user, err := sm.getUserByUsername(ctx, credentials.Username)
	if err != nil {
		sm.logAuditEvent(ctx, types.AuditEvent{
			Type:      "auth",
			Action:    "login",
			Username:  credentials.Username,
			Success:   false,
			Error:     "user not found",
			IPAddress: sm.getClientIP(ctx),
		})
		return nil, fmt.Errorf("authentication failed")
	}

	if user.Disabled {
		sm.logAuditEvent(ctx, types.AuditEvent{
			Type:      "auth",
			Action:    "login",
			Username:  credentials.Username,
			Success:   false,
			Error:     "user disabled",
			IPAddress: sm.getClientIP(ctx),
		})
		return nil, fmt.Errorf("user account disabled")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(credentials.Password)); err != nil {
		sm.logAuditEvent(ctx, types.AuditEvent{
			Type:      "auth",
			Action:    "login",
			Username:  credentials.Username,
			Success:   false,
			Error:     "invalid password",
			IPAddress: sm.getClientIP(ctx),
		})
		return nil, fmt.Errorf("authentication failed")
	}

	// Check MFA if enabled
	if sm.config.AdminAuth != nil && sm.config.AdminAuth.MFA {
		if !sm.licenseChecker.IsSystemFeatureEnabled(ctx, "mfa") {
			return nil, fmt.Errorf("MFA not licensed")
		}
		// TODO: Implement MFA verification
		if credentials.MFACode == "" {
			return nil, fmt.Errorf("MFA code required")
		}
	}

	// Create session
	session, err := sm.CreateSession(ctx, &types.User{
		ID:       user.Username, // Use username as ID since LocalUser doesn't have separate ID field
		Username: user.Username,
		Email:    user.Email,
		FullName: user.FullName,
		Roles:    user.Roles,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Update last login
	if err := sm.updateLastLogin(ctx, user.Username); err != nil {
		sm.logger.WithError(err).Warn("Failed to update last login")
	}

	sm.logAuditEvent(ctx, types.AuditEvent{
		Type:      "auth",
		Action:    "login",
		UserID:    user.Username,
		Username:  credentials.Username,
		Success:   true,
		IPAddress: sm.getClientIP(ctx),
	})

	return session, nil
}

func (sm *DefaultSystemSecurityManager) AuthorizeAPIAccess(ctx context.Context, user *types.User, resource string, action string) error {
	if !sm.config.Enabled {
		return nil // Security disabled, allow all
	}

	// Check if RBAC is enabled by license
	if !sm.licenseChecker.IsSystemFeatureEnabled(ctx, "rbac") {
		// Simple role-based check without advanced RBAC
		return sm.simpleRoleCheck(user, resource, action)
	}

	// Advanced RBAC evaluation
	accessCtx := &types.AccessContext{
		User:      user,
		IPAddress: sm.getClientIP(ctx),
		UserAgent: sm.getUserAgent(ctx),
		Timestamp: time.Now(),
		Resource:  resource,
		Action:    action,
	}

	return sm.EvaluatePolicy(ctx, accessCtx)
}

func (sm *DefaultSystemSecurityManager) GetUser(ctx context.Context, userID string) (*types.User, error) {
	return sm.getUserByID(ctx, userID)
}

func (sm *DefaultSystemSecurityManager) ListUsers(ctx context.Context) ([]*types.User, error) {
	rows, err := sm.db.QueryContext(ctx, `
		SELECT username, email, name, roles, disabled, created_at, updated_at 
		FROM local_users ORDER BY username
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*types.User
	for rows.Next() {
		var user types.LocalUser
		var rolesJSON string

		err := rows.Scan(&user.Username, &user.Email, &user.FullName, &rolesJSON,
			&user.Disabled, &user.CreatedAt, &user.UpdatedAt)
		if err != nil {
			continue
		}

		var roles []string
		if err := json.Unmarshal([]byte(rolesJSON), &roles); err != nil {
			roles = []string{}
		}

		users = append(users, &types.User{
			ID:       user.Username, // Using username as ID for simplicity
			Username: user.Username,
			Email:    user.Email,
			FullName: user.FullName,
			Roles:    roles,
		})
	}

	return users, nil
}

func (sm *DefaultSystemSecurityManager) CreateUser(ctx context.Context, user *types.User, password string) error {
	if !sm.licenseChecker.IsSystemFeatureEnabled(ctx, "local_auth") {
		return fmt.Errorf("local user management not licensed")
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Validate password policy if enabled
	if sm.config.AdminAuth != nil && sm.config.AdminAuth.Local != nil && sm.config.AdminAuth.Local.PasswordPolicy != nil {
		if err := sm.validatePassword(password, sm.config.AdminAuth.Local.PasswordPolicy); err != nil {
			return fmt.Errorf("password policy violation: %w", err)
		}
	}

	rolesJSON, _ := json.Marshal(user.Roles)

	_, err = sm.db.ExecContext(ctx, `
		INSERT INTO local_users (username, password_hash, email, name, roles, disabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, user.Username, string(hashedPassword), user.Email, user.FullName, string(rolesJSON),
		false, time.Now(), time.Now())

	if err != nil {
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

func (sm *DefaultSystemSecurityManager) UpdateUser(ctx context.Context, userID string, updates map[string]interface{}) error {
	// Build dynamic update query
	setParts := []string{}
	args := []interface{}{}

	for field, value := range updates {
		switch field {
		case "email", "name", "disabled":
			setParts = append(setParts, fmt.Sprintf("%s = ?", field))
			args = append(args, value)
		case "roles":
			if roles, ok := value.([]string); ok {
				rolesJSON, _ := json.Marshal(roles)
				setParts = append(setParts, "roles = ?")
				args = append(args, string(rolesJSON))
			}
		}
	}

	if len(setParts) == 0 {
		return fmt.Errorf("no valid fields to update")
	}

	setParts = append(setParts, "updated_at = ?")
	args = append(args, time.Now())
	args = append(args, userID)

	query := fmt.Sprintf("UPDATE local_users SET %s WHERE username = ?", strings.Join(setParts, ", "))

	_, err := sm.db.ExecContext(ctx, query, args...)
	if err != nil {
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

func (sm *DefaultSystemSecurityManager) DeleteUser(ctx context.Context, userID string) error {
	_, err := sm.db.ExecContext(ctx, "DELETE FROM local_users WHERE username = ?", userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	// Revoke all user sessions
	sm.RevokeAllUserSessions(ctx, userID)

	sm.logAuditEvent(ctx, types.AuditEvent{
		Type:     "user",
		Action:   "delete",
		Resource: userID,
		Success:  true,
	})

	return nil
}

func (sm *DefaultSystemSecurityManager) ChangePassword(ctx context.Context, userID string, oldPassword, newPassword string) error {
	// Get current user
	user, err := sm.getUserByUsername(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	// Verify old password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)); err != nil {
		return fmt.Errorf("current password is incorrect")
	}

	// Validate new password policy
	if sm.config.AdminAuth != nil && sm.config.AdminAuth.Local != nil && sm.config.AdminAuth.Local.PasswordPolicy != nil {
		if err := sm.validatePassword(newPassword, sm.config.AdminAuth.Local.PasswordPolicy); err != nil {
			return fmt.Errorf("password policy violation: %w", err)
		}
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	_, err = sm.db.ExecContext(ctx, "UPDATE local_users SET password_hash = ?, updated_at = ? WHERE username = ?",
		string(hashedPassword), time.Now(), userID)
	if err != nil {
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

// Session Management

func (sm *DefaultSystemSecurityManager) CreateSession(ctx context.Context, user *types.User) (*types.UserSession, error) {
	sessionID := sm.generateSessionID()
	token := sm.generateToken(user)

	expiresAt := time.Now().Add(24 * time.Hour) // Default 24h
	if sm.config.SessionConfig != nil && sm.config.SessionConfig.Timeout > 0 {
		expiresAt = time.Now().Add(sm.config.SessionConfig.Timeout)
	}

	session := &types.UserSession{
		ID:           sessionID,
		UserID:       user.Username,
		Username:     user.Username,
		Token:        token,
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		IPAddress:    sm.getClientIP(ctx),
		UserAgent:    sm.getUserAgent(ctx),
	}

	// Store session (in-memory for now, should be persistent)
	sm.sessions[sessionID] = session

	sm.logAuditEvent(ctx, types.AuditEvent{
		Type:     "session",
		Action:   "create",
		UserID:   user.Username,
		Username: user.Username,
		Success:  true,
	})

	return session, nil
}

func (sm *DefaultSystemSecurityManager) ValidateSession(ctx context.Context, sessionToken string) (*types.UserSession, error) {
	// Find session by token
	var session *types.UserSession
	for _, s := range sm.sessions {
		if s.Token == sessionToken {
			session = s
			break
		}
	}

	if session == nil {
		return nil, fmt.Errorf("invalid session token")
	}

	// Check expiry
	if time.Now().After(session.ExpiresAt) {
		delete(sm.sessions, session.ID)
		return nil, fmt.Errorf("session expired")
	}

	// Update last activity
	session.LastActivity = time.Now()

	return session, nil
}

func (sm *DefaultSystemSecurityManager) RefreshSession(ctx context.Context, refreshToken string) (*types.UserSession, error) {
	// TODO: Implement refresh token logic
	return nil, fmt.Errorf("refresh tokens not implemented")
}

func (sm *DefaultSystemSecurityManager) RevokeSession(ctx context.Context, sessionToken string) error {
	for id, session := range sm.sessions {
		if session.Token == sessionToken {
			delete(sm.sessions, id)
			sm.logAuditEvent(ctx, types.AuditEvent{
				Type:     "session",
				Action:   "revoke",
				UserID:   session.UserID,
				Username: session.Username,
				Success:  true,
			})
			return nil
		}
	}
	return fmt.Errorf("session not found")
}

func (sm *DefaultSystemSecurityManager) ListUserSessions(ctx context.Context, userID string) ([]*types.UserSession, error) {
	var sessions []*types.UserSession
	for _, session := range sm.sessions {
		if session.UserID == userID {
			sessions = append(sessions, session)
		}
	}
	return sessions, nil
}

func (sm *DefaultSystemSecurityManager) RevokeAllUserSessions(ctx context.Context, userID string) error {
	count := 0
	for id, session := range sm.sessions {
		if session.UserID == userID {
			delete(sm.sessions, id)
			count++
		}
	}

	sm.logAuditEvent(ctx, types.AuditEvent{
		Type:    "session",
		Action:  "revoke_all",
		UserID:  userID,
		Success: true,
		Details: map[string]interface{}{"sessions_revoked": count},
	})

	return nil
}

// Policy Management (Basic implementation)

func (sm *DefaultSystemSecurityManager) AddPolicy(ctx context.Context, policy types.APIPolicy) error {
	// TODO: Implement policy storage
	return fmt.Errorf("policy management not implemented")
}

func (sm *DefaultSystemSecurityManager) RemovePolicy(ctx context.Context, policyID string) error {
	// TODO: Implement policy storage
	return fmt.Errorf("policy management not implemented")
}

func (sm *DefaultSystemSecurityManager) UpdatePolicy(ctx context.Context, policyID string, policy types.APIPolicy) error {
	// TODO: Implement policy storage
	return fmt.Errorf("policy management not implemented")
}

func (sm *DefaultSystemSecurityManager) GetPolicy(ctx context.Context, policyID string) (*types.APIPolicy, error) {
	// TODO: Implement policy storage
	return nil, fmt.Errorf("policy management not implemented")
}

func (sm *DefaultSystemSecurityManager) ListPolicies(ctx context.Context) ([]types.APIPolicy, error) {
	// TODO: Implement policy storage
	return nil, fmt.Errorf("policy management not implemented")
}

func (sm *DefaultSystemSecurityManager) EvaluatePolicy(ctx context.Context, accessCtx *types.AccessContext) error {
	// Basic policy evaluation - admin role can access everything
	for _, role := range accessCtx.User.Roles {
		if role == "admin" {
			return nil
		}
	}

	// Other roles get limited access
	if strings.HasPrefix(accessCtx.Resource, "/api/admin/") {
		return fmt.Errorf("admin access required")
	}

	return nil
}

// Configuration Management

func (sm *DefaultSystemSecurityManager) UpdateConfig(ctx context.Context, config types.SystemSecurityConfig) error {
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

func (sm *DefaultSystemSecurityManager) GetConfig(ctx context.Context) (*types.SystemSecurityConfig, error) {
	return sm.config, nil
}

func (sm *DefaultSystemSecurityManager) ValidateConfig(ctx context.Context, config types.SystemSecurityConfig) error {
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

func (sm *DefaultSystemSecurityManager) HealthCheck(ctx context.Context) error {
	// Check database connectivity
	if err := sm.db.PingContext(ctx); err != nil {
		return fmt.Errorf("database connectivity failed: %w", err)
	}

	// Check license validity
	if !sm.licenseChecker.IsLicenseValid(ctx) {
		return fmt.Errorf("license is invalid or expired")
	}

	return nil
}

func (sm *DefaultSystemSecurityManager) GetSecurityMetrics(ctx context.Context) (map[string]interface{}, error) {
	metrics := map[string]interface{}{
		"active_sessions":  len(sm.sessions),
		"total_users":      sm.getUserCount(ctx),
		"security_enabled": sm.config.Enabled,
		"license_valid":    sm.licenseChecker.IsLicenseValid(ctx),
	}

	return metrics, nil
}

func (sm *DefaultSystemSecurityManager) GetAuditLog(ctx context.Context, filters map[string]interface{}) ([]types.AuditEvent, error) {
	// TODO: Implement audit log retrieval
	return nil, fmt.Errorf("audit log retrieval not implemented")
}

// Helper methods

func (sm *DefaultSystemSecurityManager) getUserByUsername(ctx context.Context, username string) (*types.LocalUser, error) {
	var user types.LocalUser
	var rolesJSON string

	err := sm.db.QueryRowContext(ctx, `
		SELECT username, password_hash, email, name, roles, disabled, last_login, created_at, updated_at 
		FROM local_users WHERE username = ?
	`, username).Scan(&user.Username, &user.PasswordHash, &user.Email, &user.FullName,
		&rolesJSON, &user.Disabled, &user.LastLogin, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		return nil, err
	}

	// Parse roles JSON
	if err := json.Unmarshal([]byte(rolesJSON), &user.Roles); err != nil {
		user.Roles = []string{}
	}

	return &user, nil
}

func (sm *DefaultSystemSecurityManager) getUserByID(ctx context.Context, userID string) (*types.User, error) {
	localUser, err := sm.getUserByUsername(ctx, userID)
	if err != nil {
		return nil, err
	}

	return &types.User{
		ID:       localUser.Username,
		Username: localUser.Username,
		Email:    localUser.Email,
		FullName: localUser.FullName,
		Roles:    localUser.Roles,
	}, nil
}

func (sm *DefaultSystemSecurityManager) updateLastLogin(ctx context.Context, userID string) error {
	_, err := sm.db.ExecContext(ctx, "UPDATE local_users SET last_login = ? WHERE username = ?",
		time.Now(), userID)
	return err
}

func (sm *DefaultSystemSecurityManager) getUserCount(ctx context.Context) int {
	var count int
	sm.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM local_users").Scan(&count)
	return count
}

func (sm *DefaultSystemSecurityManager) generateSessionID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (sm *DefaultSystemSecurityManager) generateToken(user *types.User) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":   user.Username,
		"name":  user.Username,
		"roles": user.Roles,
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	})

	tokenString, _ := token.SignedString(sm.jwtSecret)
	return tokenString
}

func (sm *DefaultSystemSecurityManager) validatePassword(password string, policy *types.PasswordPolicy) error {
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

func (sm *DefaultSystemSecurityManager) simpleRoleCheck(user *types.User, resource string, action string) error {
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

func (sm *DefaultSystemSecurityManager) getClientIP(ctx context.Context) string {
	// Try to extract IP from context
	if ip, ok := ctx.Value("client_ip").(string); ok {
		return ip
	}
	return "unknown"
}

func (sm *DefaultSystemSecurityManager) getUserAgent(ctx context.Context) string {
	// Try to extract User-Agent from context
	if ua, ok := ctx.Value("user_agent").(string); ok {
		return ua
	}
	return "unknown"
}

func (sm *DefaultSystemSecurityManager) logAuditEvent(ctx context.Context, event types.AuditEvent) {
	event.ID = sm.generateSessionID()
	event.Timestamp = time.Now()

	// Log to structured logger
	sm.logger.WithFields(logrus.Fields{
		"audit_event_id": event.ID,
		"type":           event.Type,
		"action":         event.Action,
		"user_id":        event.UserID,
		"username":       event.Username,
		"resource":       event.Resource,
		"success":        event.Success,
		"error":          event.Error,
		"ip_address":     event.IPAddress,
	}).Info("Security audit event")

	// TODO: Store in audit log table for persistence
}

// Ensure interface compliance
var _ types.SystemSecurityManager = (*DefaultSystemSecurityManager)(nil)
