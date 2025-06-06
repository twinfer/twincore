package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/database"
	"github.com/twinfer/twincore/pkg/types"
)

// SecurityRepository provides data access operations for security management
type SecurityRepository struct {
	manager database.DatabaseManager
	logger  *logrus.Logger
}

// NewSecurityRepository creates a new Security repository
func NewSecurityRepository(manager database.DatabaseManager, logger *logrus.Logger) *SecurityRepository {
	return &SecurityRepository{
		manager: manager,
		logger:  logger,
	}
}

// IsHealthy checks if the repository is healthy
func (sr *SecurityRepository) IsHealthy(ctx context.Context) bool {
	return sr.manager.IsHealthy()
}

// User management operations

// CreateUser creates a new local user
func (sr *SecurityRepository) CreateUser(ctx context.Context, user *types.LocalUser) error {
	// Marshal roles to JSON for database storage
	rolesJSON, err := json.Marshal(user.Roles)
	if err != nil {
		sr.logger.WithError(err).WithField("username", user.Username).Error("Failed to marshal roles")
		return fmt.Errorf("failed to marshal roles for user %s: %w", user.Username, err)
	}

	_, err = sr.manager.Execute(ctx, "CreateUser",
		user.Username, user.PasswordHash, string(rolesJSON), user.Email, user.FullName, user.Disabled)

	if err != nil {
		sr.logger.WithError(err).WithField("username", user.Username).Error("Failed to create user")
		return fmt.Errorf("failed to create user %s: %w", user.Username, err)
	}

	sr.logger.WithField("username", user.Username).Info("User created successfully")
	return nil
}

// GetUser retrieves a user by username
func (sr *SecurityRepository) GetUser(ctx context.Context, username string) (*types.LocalUser, error) {
	row := sr.manager.QueryRow(ctx, "GetUser", username)

	var user types.LocalUser
	var lastLogin sql.NullTime
	var roles string

	err := row.Scan(&user.Username, &user.PasswordHash, &roles, &user.Email,
		&user.FullName, &user.Disabled, &lastLogin, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user %s not found", username)
		}
		sr.logger.WithError(err).WithField("username", username).Error("Failed to get user")
		return nil, fmt.Errorf("failed to get user %s: %w", username, err)
	}

	// Handle nullable last_login
	if lastLogin.Valid {
		user.LastLogin = lastLogin.Time
	}

	// Unmarshal roles from JSON
	if roles != "" {
		err = json.Unmarshal([]byte(roles), &user.Roles)
		if err != nil {
			sr.logger.WithError(err).WithField("username", username).Error("Failed to unmarshal roles")
			return nil, fmt.Errorf("failed to unmarshal roles for user %s: %w", username, err)
		}
	} else {
		user.Roles = []string{} // Default to empty slice
	}

	return &user, nil
}

// GetUserForAuth retrieves minimal user data for authentication
func (sr *SecurityRepository) GetUserForAuth(ctx context.Context, username string) (*database.UserAuthData, error) {
	row := sr.manager.QueryRow(ctx, "GetUserForAuth", username)

	var authData database.UserAuthData
	err := row.Scan(&authData.Username, &authData.PasswordHash, &authData.Roles, &authData.Disabled)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user %s not found", username)
		}
		sr.logger.WithError(err).WithField("username", username).Error("Failed to get user for auth")
		return nil, fmt.Errorf("failed to get user for auth %s: %w", username, err)
	}

	return &authData, nil
}

// UpdateUser updates an existing user
func (sr *SecurityRepository) UpdateUser(ctx context.Context, user *types.LocalUser) error {
	// Marshal roles to JSON for database storage
	rolesJSON, err := json.Marshal(user.Roles)
	if err != nil {
		sr.logger.WithError(err).WithField("username", user.Username).Error("Failed to marshal roles")
		return fmt.Errorf("failed to marshal roles for user %s: %w", user.Username, err)
	}

	result, err := sr.manager.Execute(ctx, "UpdateUser",
		user.PasswordHash, string(rolesJSON), user.Email, user.FullName, user.Disabled, user.Username)

	if err != nil {
		sr.logger.WithError(err).WithField("username", user.Username).Error("Failed to update user")
		return fmt.Errorf("failed to update user %s: %w", user.Username, err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user %s not found", user.Username)
	}

	sr.logger.WithField("username", user.Username).Info("User updated successfully")
	return nil
}

// UpdateLastLogin updates the last login time for a user
func (sr *SecurityRepository) UpdateLastLogin(ctx context.Context, username string) error {
	_, err := sr.manager.Execute(ctx, "UpdateUserLastLogin", username)
	if err != nil {
		sr.logger.WithError(err).WithField("username", username).Error("Failed to update last login")
		return fmt.Errorf("failed to update last login for %s: %w", username, err)
	}

	sr.logger.WithField("username", username).Debug("Last login updated")
	return nil
}

// DeleteUser removes a user
func (sr *SecurityRepository) DeleteUser(ctx context.Context, username string) error {
	result, err := sr.manager.Execute(ctx, "DeleteUser", username)
	if err != nil {
		sr.logger.WithError(err).WithField("username", username).Error("Failed to delete user")
		return fmt.Errorf("failed to delete user %s: %w", username, err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("user %s not found", username)
	}

	sr.logger.WithField("username", username).Info("User deleted successfully")
	return nil
}

// ListUsers retrieves all users
func (sr *SecurityRepository) ListUsers(ctx context.Context) ([]*types.LocalUser, error) {
	rows, err := sr.manager.Query(ctx, "ListUsers")
	if err != nil {
		sr.logger.WithError(err).Error("Failed to list users")
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*types.LocalUser
	for rows.Next() {
		var user types.LocalUser
		var lastLogin sql.NullTime
		var roles string

		err := rows.Scan(&user.Username, &roles, &user.Email, &user.FullName,
			&user.Disabled, &lastLogin, &user.CreatedAt, &user.UpdatedAt)
		if err != nil {
			sr.logger.WithError(err).Error("Failed to scan user")
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}

		// Handle nullable last_login
		if lastLogin.Valid {
			user.LastLogin = lastLogin.Time
		}

		// Set roles as string (will be parsed by caller if needed as []string)
		user.Roles = []string{roles}

		users = append(users, &user)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating users: %w", err)
	}

	sr.logger.WithField("count", len(users)).Debug("Listed users successfully")
	return users, nil
}

// UserExists checks if a user exists
func (sr *SecurityRepository) UserExists(ctx context.Context, username string) (bool, error) {
	row := sr.manager.QueryRow(ctx, "UserExists", username)

	var exists bool
	err := row.Scan(&exists)
	if err != nil {
		sr.logger.WithError(err).WithField("username", username).Error("Failed to check user existence")
		return false, fmt.Errorf("failed to check if user %s exists: %w", username, err)
	}

	return exists, nil
}

// Session management operations

// CreateSession creates a new user session
func (sr *SecurityRepository) CreateSession(ctx context.Context, session *types.UserSession) error {
	_, err := sr.manager.Execute(ctx, "CreateSession",
		session.ID, session.UserID, session.Username, session.Token,
		session.RefreshToken, session.ExpiresAt, session.IPAddress, session.UserAgent)

	if err != nil {
		sr.logger.WithError(err).WithField("session_id", session.ID).Error("Failed to create session")
		return fmt.Errorf("failed to create session: %w", err)
	}

	sr.logger.WithField("session_id", session.ID).Debug("Session created successfully")
	return nil
}

// GetSession retrieves a session by ID
func (sr *SecurityRepository) GetSession(ctx context.Context, sessionID string) (*types.UserSession, error) {
	row := sr.manager.QueryRow(ctx, "GetSession", sessionID)

	var session types.UserSession
	err := row.Scan(&session.ID, &session.UserID, &session.Username, &session.Token,
		&session.RefreshToken, &session.ExpiresAt, &session.CreatedAt,
		&session.LastActivity, &session.IPAddress, &session.UserAgent)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session %s not found or expired", sessionID)
		}
		sr.logger.WithError(err).WithField("session_id", sessionID).Error("Failed to get session")
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return &session, nil
}

// GetSessionByToken retrieves a session by token
func (sr *SecurityRepository) GetSessionByToken(ctx context.Context, token string) (*types.UserSession, error) {
	row := sr.manager.QueryRow(ctx, "GetSessionByToken", token)

	var session types.UserSession
	err := row.Scan(&session.ID, &session.UserID, &session.Username, &session.Token,
		&session.RefreshToken, &session.ExpiresAt, &session.CreatedAt,
		&session.LastActivity, &session.IPAddress, &session.UserAgent)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session with token not found or expired")
		}
		sr.logger.WithError(err).Error("Failed to get session by token")
		return nil, fmt.Errorf("failed to get session by token: %w", err)
	}

	return &session, nil
}

// UpdateSessionActivity updates the last activity time for a session
func (sr *SecurityRepository) UpdateSessionActivity(ctx context.Context, sessionID string) error {
	_, err := sr.manager.Execute(ctx, "UpdateSessionActivity", sessionID)
	if err != nil {
		sr.logger.WithError(err).WithField("session_id", sessionID).Error("Failed to update session activity")
		return fmt.Errorf("failed to update session activity: %w", err)
	}

	sr.logger.WithField("session_id", sessionID).Debug("Session activity updated")
	return nil
}

// DeleteSession removes a session
func (sr *SecurityRepository) DeleteSession(ctx context.Context, sessionID string) error {
	result, err := sr.manager.Execute(ctx, "DeleteSession", sessionID)
	if err != nil {
		sr.logger.WithError(err).WithField("session_id", sessionID).Error("Failed to delete session")
		return fmt.Errorf("failed to delete session: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("session %s not found", sessionID)
	}

	sr.logger.WithField("session_id", sessionID).Debug("Session deleted successfully")
	return nil
}

// DeleteExpiredSessions removes expired sessions
func (sr *SecurityRepository) DeleteExpiredSessions(ctx context.Context) error {
	_, err := sr.manager.Execute(ctx, "DeleteExpiredSessions")
	if err != nil {
		sr.logger.WithError(err).Error("Failed to delete expired sessions")
		return fmt.Errorf("failed to delete expired sessions: %w", err)
	}

	sr.logger.Debug("Expired sessions deleted successfully")
	return nil
}

// DeleteUserSessions removes all sessions for a user
func (sr *SecurityRepository) DeleteUserSessions(ctx context.Context, username string) error {
	_, err := sr.manager.Execute(ctx, "DeleteUserSessions", username)
	if err != nil {
		sr.logger.WithError(err).WithField("username", username).Error("Failed to delete user sessions")
		return fmt.Errorf("failed to delete sessions for user %s: %w", username, err)
	}

	sr.logger.WithField("username", username).Debug("User sessions deleted successfully")
	return nil
}

// API Policy operations

// CreateAPIPolicy creates a new API policy
func (sr *SecurityRepository) CreateAPIPolicy(ctx context.Context, policy *types.APIPolicy) error {
	_, err := sr.manager.Execute(ctx, "CreateAPIPolicy",
		policy.ID, policy.Name, policy.Description, policy.Principal,
		policy.Resources, policy.Actions, policy.Conditions, true) // enabled by default

	if err != nil {
		sr.logger.WithError(err).WithField("policy_id", policy.ID).Error("Failed to create API policy")
		return fmt.Errorf("failed to create API policy: %w", err)
	}

	sr.logger.WithField("policy_id", policy.ID).Info("API policy created successfully")
	return nil
}

// GetAPIPolicy retrieves an API policy by ID
func (sr *SecurityRepository) GetAPIPolicy(ctx context.Context, id string) (*types.APIPolicy, error) {
	row := sr.manager.QueryRow(ctx, "GetAPIPolicy", id)

	var policy types.APIPolicy
	var enabled bool
	var createdAt, updatedAt time.Time

	err := row.Scan(&policy.ID, &policy.Name, &policy.Description, &policy.Principal,
		&policy.Resources, &policy.Actions, &policy.Conditions, &enabled, &createdAt, &updatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("API policy %s not found", id)
		}
		sr.logger.WithError(err).WithField("policy_id", id).Error("Failed to get API policy")
		return nil, fmt.Errorf("failed to get API policy: %w", err)
	}

	return &policy, nil
}

// ListEnabledAPIPolicies retrieves all enabled API policies
func (sr *SecurityRepository) ListEnabledAPIPolicies(ctx context.Context) ([]*types.APIPolicy, error) {
	rows, err := sr.manager.Query(ctx, "ListEnabledAPIPolicies")
	if err != nil {
		sr.logger.WithError(err).Error("Failed to list enabled API policies")
		return nil, fmt.Errorf("failed to list enabled API policies: %w", err)
	}
	defer rows.Close()

	var policies []*types.APIPolicy
	for rows.Next() {
		var policy types.APIPolicy
		var enabled bool
		var createdAt, updatedAt time.Time

		err := rows.Scan(&policy.ID, &policy.Name, &policy.Description, &policy.Principal,
			&policy.Resources, &policy.Actions, &policy.Conditions, &enabled, &createdAt, &updatedAt)
		if err != nil {
			sr.logger.WithError(err).Error("Failed to scan API policy")
			return nil, fmt.Errorf("failed to scan API policy: %w", err)
		}

		policies = append(policies, &policy)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating API policies: %w", err)
	}

	sr.logger.WithField("count", len(policies)).Debug("Listed enabled API policies successfully")
	return policies, nil
}

// UpdateAPIPolicy updates an existing API policy
func (sr *SecurityRepository) UpdateAPIPolicy(ctx context.Context, policy *types.APIPolicy) error {
	result, err := sr.manager.Execute(ctx, "UpdateAPIPolicy",
		policy.Name, policy.Description, policy.Principal, policy.Resources,
		policy.Actions, policy.Conditions, true, policy.ID) // enabled by default

	if err != nil {
		sr.logger.WithError(err).WithField("policy_id", policy.ID).Error("Failed to update API policy")
		return fmt.Errorf("failed to update API policy: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("API policy %s not found", policy.ID)
	}

	sr.logger.WithField("policy_id", policy.ID).Info("API policy updated successfully")
	return nil
}

// DeleteAPIPolicy removes an API policy
func (sr *SecurityRepository) DeleteAPIPolicy(ctx context.Context, id string) error {
	result, err := sr.manager.Execute(ctx, "DeleteAPIPolicy", id)
	if err != nil {
		sr.logger.WithError(err).WithField("policy_id", id).Error("Failed to delete API policy")
		return fmt.Errorf("failed to delete API policy: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("API policy %s not found", id)
	}

	sr.logger.WithField("policy_id", id).Info("API policy deleted successfully")
	return nil
}

// Audit logging operations

// CreateAuditEvent creates a new audit event
func (sr *SecurityRepository) CreateAuditEvent(ctx context.Context, event *types.AuditEvent) error {
	_, err := sr.manager.Execute(ctx, "CreateAuditEvent",
		event.ID, event.Type, event.UserID, event.Username, event.Action,
		event.Resource, event.Success, event.Error, event.IPAddress,
		event.UserAgent, event.Details)

	if err != nil {
		sr.logger.WithError(err).WithField("event_id", event.ID).Error("Failed to create audit event")
		return fmt.Errorf("failed to create audit event: %w", err)
	}

	sr.logger.WithField("event_id", event.ID).Debug("Audit event created successfully")
	return nil
}

// GetAuditEvents retrieves audit events within a time range
func (sr *SecurityRepository) GetAuditEvents(ctx context.Context, startTime, endTime time.Time, limit int) ([]*types.AuditEvent, error) {
	rows, err := sr.manager.Query(ctx, "GetAuditEvents", startTime, endTime, limit)
	if err != nil {
		sr.logger.WithError(err).Error("Failed to get audit events")
		return nil, fmt.Errorf("failed to get audit events: %w", err)
	}
	defer rows.Close()

	var events []*types.AuditEvent
	for rows.Next() {
		var event types.AuditEvent
		err := rows.Scan(&event.ID, &event.Type, &event.Timestamp, &event.UserID,
			&event.Username, &event.Action, &event.Resource, &event.Success,
			&event.Error, &event.IPAddress, &event.UserAgent, &event.Details)
		if err != nil {
			sr.logger.WithError(err).Error("Failed to scan audit event")
			return nil, fmt.Errorf("failed to scan audit event: %w", err)
		}

		events = append(events, &event)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating audit events: %w", err)
	}

	sr.logger.WithField("count", len(events)).Debug("Retrieved audit events successfully")
	return events, nil
}

// GetUserAuditEvents retrieves audit events for a specific user
func (sr *SecurityRepository) GetUserAuditEvents(ctx context.Context, userID string, since time.Time, limit int) ([]*types.AuditEvent, error) {
	rows, err := sr.manager.Query(ctx, "GetUserAuditEvents", userID, since, limit)
	if err != nil {
		sr.logger.WithError(err).WithField("user_id", userID).Error("Failed to get user audit events")
		return nil, fmt.Errorf("failed to get user audit events: %w", err)
	}
	defer rows.Close()

	var events []*types.AuditEvent
	for rows.Next() {
		var event types.AuditEvent
		err := rows.Scan(&event.ID, &event.Type, &event.Timestamp, &event.UserID,
			&event.Username, &event.Action, &event.Resource, &event.Success,
			&event.Error, &event.IPAddress, &event.UserAgent, &event.Details)
		if err != nil {
			sr.logger.WithError(err).Error("Failed to scan audit event")
			return nil, fmt.Errorf("failed to scan audit event: %w", err)
		}

		events = append(events, &event)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating user audit events: %w", err)
	}

	sr.logger.WithFields(logrus.Fields{
		"user_id": userID,
		"count":   len(events),
	}).Debug("Retrieved user audit events successfully")
	return events, nil
}

// DeleteOldAuditEvents removes audit events before a given time
func (sr *SecurityRepository) DeleteOldAuditEvents(ctx context.Context, before time.Time) error {
	_, err := sr.manager.Execute(ctx, "DeleteOldAuditEvents", before)
	if err != nil {
		sr.logger.WithError(err).WithField("before", before).Error("Failed to delete old audit events")
		return fmt.Errorf("failed to delete old audit events: %w", err)
	}

	sr.logger.WithField("before", before).Debug("Old audit events deleted successfully")
	return nil
}

// Security policies operations

// CreateThingSecurityPolicy creates or updates a security policy for a Thing
func (sr *SecurityRepository) CreateThingSecurityPolicy(ctx context.Context, thingID, policyData string) error {
	_, err := sr.manager.Execute(ctx, "CreateThingSecurityPolicy", thingID, policyData)
	if err != nil {
		sr.logger.WithError(err).WithField("thing_id", thingID).Error("Failed to create thing security policy")
		return fmt.Errorf("failed to create thing security policy: %w", err)
	}

	sr.logger.WithField("thing_id", thingID).Info("Thing security policy created successfully")
	return nil
}

// GetThingSecurityPolicy retrieves a security policy for a Thing
func (sr *SecurityRepository) GetThingSecurityPolicy(ctx context.Context, thingID string) (string, error) {
	row := sr.manager.QueryRow(ctx, "GetThingSecurityPolicy", thingID)

	var thingIDResult, policyData string
	var createdAt, updatedAt time.Time

	err := row.Scan(&thingIDResult, &policyData, &createdAt, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("security policy not found for thing: %s", thingID)
		}
		sr.logger.WithError(err).WithField("thing_id", thingID).Error("Failed to get thing security policy")
		return "", fmt.Errorf("failed to get thing security policy: %w", err)
	}

	sr.logger.WithField("thing_id", thingID).Debug("Thing security policy retrieved successfully")
	return policyData, nil
}

// DeleteThingSecurityPolicy removes a security policy for a Thing
func (sr *SecurityRepository) DeleteThingSecurityPolicy(ctx context.Context, thingID string) error {
	result, err := sr.manager.Execute(ctx, "DeleteThingSecurityPolicy", thingID)
	if err != nil {
		sr.logger.WithError(err).WithField("thing_id", thingID).Error("Failed to delete thing security policy")
		return fmt.Errorf("failed to delete thing security policy: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("security policy not found for thing: %s", thingID)
	}

	sr.logger.WithField("thing_id", thingID).Info("Thing security policy deleted successfully")
	return nil
}

// Device credentials management operations

// GetDeviceCredentials retrieves device credentials by key
func (sr *SecurityRepository) GetDeviceCredentials(ctx context.Context, credentialKey string) (*types.DeviceCredentials, error) {
	row := sr.manager.QueryRow(ctx, "GetDeviceCredentials", credentialKey)

	var key, credentialsData string
	var encrypted bool
	var expiresAt sql.NullTime
	var createdAt, updatedAt time.Time

	err := row.Scan(&key, &credentialsData, &encrypted, &expiresAt, &createdAt, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("credentials not found: %s", credentialKey)
		}
		sr.logger.WithError(err).WithField("credential_key", credentialKey).Error("Failed to get device credentials")
		return nil, fmt.Errorf("failed to get device credentials: %w", err)
	}

	var credentials types.DeviceCredentials
	if err := json.Unmarshal([]byte(credentialsData), &credentials); err != nil {
		return nil, fmt.Errorf("failed to parse credentials: %w", err)
	}

	sr.logger.WithField("credential_key", credentialKey).Debug("Device credentials retrieved successfully")
	return &credentials, nil
}

// SetDeviceCredentials stores or updates device credentials
func (sr *SecurityRepository) SetDeviceCredentials(ctx context.Context, credentialKey string, credentials *types.DeviceCredentials) error {
	credentialsJSON, err := json.Marshal(credentials)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	// Default to encrypted credentials
	encrypted := true
	var expiresAt *time.Time

	// Check if credentials have an expiration (zero time means no expiration)
	if !credentials.ExpiresAt.IsZero() {
		expiresAt = &credentials.ExpiresAt
	}

	_, err = sr.manager.Execute(ctx, "SetDeviceCredentials",
		credentialKey, string(credentialsJSON), encrypted, expiresAt)
	if err != nil {
		sr.logger.WithError(err).WithField("credential_key", credentialKey).Error("Failed to set device credentials")
		return fmt.Errorf("failed to set device credentials: %w", err)
	}

	sr.logger.WithField("credential_key", credentialKey).Info("Device credentials stored successfully")
	return nil
}

// DeleteDeviceCredentials removes device credentials
func (sr *SecurityRepository) DeleteDeviceCredentials(ctx context.Context, credentialKey string) error {
	result, err := sr.manager.Execute(ctx, "DeleteDeviceCredentials", credentialKey)
	if err != nil {
		sr.logger.WithError(err).WithField("credential_key", credentialKey).Error("Failed to delete device credentials")
		return fmt.Errorf("failed to delete device credentials: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("credentials not found: %s", credentialKey)
	}

	sr.logger.WithField("credential_key", credentialKey).Info("Device credentials deleted successfully")
	return nil
}

// Security templates management operations

// GetSecurityTemplate retrieves a security template by name
func (sr *SecurityRepository) GetSecurityTemplate(ctx context.Context, name string) (*types.SecurityTemplate, error) {
	row := sr.manager.QueryRow(ctx, "GetSecurityTemplate", name)

	var templateName, templateData string
	var createdAt, updatedAt time.Time

	err := row.Scan(&templateName, &templateData, &createdAt, &updatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("security template not found: %s", name)
		}
		sr.logger.WithError(err).WithField("template_name", name).Error("Failed to get security template")
		return nil, fmt.Errorf("failed to get security template: %w", err)
	}

	var template types.SecurityTemplate
	if err := json.Unmarshal([]byte(templateData), &template); err != nil {
		return nil, fmt.Errorf("failed to parse security template: %w", err)
	}

	sr.logger.WithField("template_name", name).Debug("Security template retrieved successfully")
	return &template, nil
}

// SetSecurityTemplate stores or updates a security template
func (sr *SecurityRepository) SetSecurityTemplate(ctx context.Context, name string, template *types.SecurityTemplate) error {
	templateJSON, err := json.Marshal(template)
	if err != nil {
		return fmt.Errorf("failed to marshal template: %w", err)
	}

	_, err = sr.manager.Execute(ctx, "SetSecurityTemplate", name, string(templateJSON))
	if err != nil {
		sr.logger.WithError(err).WithField("template_name", name).Error("Failed to set security template")
		return fmt.Errorf("failed to set security template: %w", err)
	}

	sr.logger.WithField("template_name", name).Info("Security template stored successfully")
	return nil
}

// ListSecurityTemplates retrieves all security templates
func (sr *SecurityRepository) ListSecurityTemplates(ctx context.Context) ([]*types.SecurityTemplate, error) {
	rows, err := sr.manager.Query(ctx, "ListSecurityTemplates")
	if err != nil {
		sr.logger.WithError(err).Error("Failed to list security templates")
		return nil, fmt.Errorf("failed to list security templates: %w", err)
	}
	defer rows.Close()

	var templates []*types.SecurityTemplate
	for rows.Next() {
		var name, templateData string
		var createdAt, updatedAt time.Time

		err := rows.Scan(&name, &templateData, &createdAt, &updatedAt)
		if err != nil {
			sr.logger.WithError(err).Error("Failed to scan security template")
			return nil, fmt.Errorf("failed to scan security template: %w", err)
		}

		var template types.SecurityTemplate
		if err := json.Unmarshal([]byte(templateData), &template); err != nil {
			sr.logger.WithError(err).WithField("template_name", name).Warn("Failed to parse security template, skipping")
			continue
		}

		templates = append(templates, &template)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating security templates: %w", err)
	}

	sr.logger.WithField("count", len(templates)).Debug("Security templates listed successfully")
	return templates, nil
}

// DeleteSecurityTemplate removes a security template
func (sr *SecurityRepository) DeleteSecurityTemplate(ctx context.Context, name string) error {
	result, err := sr.manager.Execute(ctx, "DeleteSecurityTemplate", name)
	if err != nil {
		sr.logger.WithError(err).WithField("template_name", name).Error("Failed to delete security template")
		return fmt.Errorf("failed to delete security template: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("security template not found: %s", name)
	}

	sr.logger.WithField("template_name", name).Info("Security template deleted successfully")
	return nil
}
