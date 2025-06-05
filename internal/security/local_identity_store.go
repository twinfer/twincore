package security

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"github.com/twinfer/twincore/pkg/types"
)

// LocalIdentityStore implements a local identity store for caddy-auth-portal
// This bridges our local user database to caddy-security's authentication system
type LocalIdentityStore struct {
	db     *sql.DB
	logger *logrus.Logger
	name   string
}

// NewLocalIdentityStore creates a new local identity store
func NewLocalIdentityStore(db *sql.DB, logger *logrus.Logger, name string) *LocalIdentityStore {
	return &LocalIdentityStore{
		db:     db,
		logger: logger,
		name:   name,
	}
}

// AuthUser represents a user in the identity store format expected by caddy-auth-portal
type AuthUser struct {
	ID          string            `json:"id"`
	Username    string            `json:"username"`
	Email       string            `json:"email,omitempty"`
	FullName    string            `json:"name,omitempty"`
	Roles       []string          `json:"roles,omitempty"`
	Password    string            `json:"password,omitempty"` // Hashed password
	Disabled    bool              `json:"disabled,omitempty"`
	CreatedAt   time.Time         `json:"created_at,omitempty"`
	UpdatedAt   time.Time         `json:"updated_at,omitempty"`
	LastLogin   *time.Time        `json:"last_login,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	MFAEnabled  bool              `json:"mfa_enabled,omitempty"`
	MFASecret   string            `json:"mfa_secret,omitempty"`
	APIKeys     []string          `json:"api_keys,omitempty"`
}

// GetUser retrieves a user by username for authentication
func (lis *LocalIdentityStore) GetUser(ctx context.Context, username string) (*AuthUser, error) {
	var user types.LocalUser
	var rolesJSON string
	var lastLogin sql.NullTime // Handle NULL values properly

	err := lis.db.QueryRowContext(ctx, `
		SELECT username, password_hash, email, name, roles, disabled, last_login, created_at, updated_at 
		FROM local_users WHERE username = ?
	`, username).Scan(&user.Username, &user.PasswordHash, &user.Email, &user.FullName,
		&rolesJSON, &user.Disabled, &lastLogin, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Parse roles JSON
	var roles []string
	if err := json.Unmarshal([]byte(rolesJSON), &roles); err != nil {
		lis.logger.WithError(err).Warn("Failed to parse user roles, using empty roles")
		roles = []string{}
	}

	authUser := &AuthUser{
		ID:        user.Username, // Using username as ID for simplicity
		Username:  user.Username,
		Email:     user.Email,
		FullName:  user.FullName,
		Roles:     roles,
		Password:  user.PasswordHash, // Already hashed
		Disabled:  user.Disabled,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Metadata:  make(map[string]string),
	}

	// Handle NULL last_login
	if lastLogin.Valid {
		authUser.LastLogin = &lastLogin.Time
	}

	return authUser, nil
}

// ValidateUser validates user credentials for authentication
func (lis *LocalIdentityStore) ValidateUser(ctx context.Context, username, password string) (*AuthUser, error) {
	user, err := lis.GetUser(ctx, username)
	if err != nil {
		return nil, err
	}

	if user.Disabled {
		return nil, fmt.Errorf("user account is disabled")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Update last login
	if err := lis.updateLastLogin(ctx, username); err != nil {
		lis.logger.WithError(err).Warn("Failed to update last login time")
	}

	return user, nil
}

// CreateUser creates a new user in the identity store
func (lis *LocalIdentityStore) CreateUser(ctx context.Context, user *AuthUser, password string) error {
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	rolesJSON, _ := json.Marshal(user.Roles)

	_, err = lis.db.ExecContext(ctx, `
		INSERT INTO local_users (username, password_hash, email, name, roles, disabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, user.Username, string(hashedPassword), user.Email, user.FullName, string(rolesJSON),
		user.Disabled, time.Now(), time.Now())

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	lis.logger.WithField("username", user.Username).Info("Created user in local identity store")
	return nil
}

// UpdateUser updates an existing user in the identity store
func (lis *LocalIdentityStore) UpdateUser(ctx context.Context, username string, updates map[string]any) error {
	setParts := []string{}
	args := []any{}

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
		case "password":
			if password, ok := value.(string); ok {
				hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
				if err != nil {
					return fmt.Errorf("failed to hash password: %w", err)
				}
				setParts = append(setParts, "password_hash = ?")
				args = append(args, string(hashedPassword))
			}
		}
	}

	if len(setParts) == 0 {
		return fmt.Errorf("no valid fields to update")
	}

	setParts = append(setParts, "updated_at = ?")
	args = append(args, time.Now())
	args = append(args, username)

	query := fmt.Sprintf("UPDATE local_users SET %s WHERE username = ?", 
		strings.Join(setParts, ", "))

	_, err := lis.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	lis.logger.WithField("username", username).Info("Updated user in local identity store")
	return nil
}

// DeleteUser removes a user from the identity store
func (lis *LocalIdentityStore) DeleteUser(ctx context.Context, username string) error {
	_, err := lis.db.ExecContext(ctx, "DELETE FROM local_users WHERE username = ?", username)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	lis.logger.WithField("username", username).Info("Deleted user from local identity store")
	return nil
}

// ListUsers returns all users from the identity store
func (lis *LocalIdentityStore) ListUsers(ctx context.Context) ([]*AuthUser, error) {
	rows, err := lis.db.QueryContext(ctx, `
		SELECT username, email, name, roles, disabled, created_at, updated_at, last_login
		FROM local_users ORDER BY username
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*AuthUser
	for rows.Next() {
		var user AuthUser
		var rolesJSON string
		var lastLogin sql.NullTime

		err := rows.Scan(&user.Username, &user.Email, &user.FullName, &rolesJSON,
			&user.Disabled, &user.CreatedAt, &user.UpdatedAt, &lastLogin)
		if err != nil {
			continue
		}

		// Parse roles JSON
		if err := json.Unmarshal([]byte(rolesJSON), &user.Roles); err != nil {
			user.Roles = []string{}
		}

		user.ID = user.Username // Using username as ID
		if lastLogin.Valid {
			user.LastLogin = &lastLogin.Time
		}
		user.Metadata = make(map[string]string)

		users = append(users, &user)
	}

	return users, nil
}

// GetName returns the name of this identity store
func (lis *LocalIdentityStore) GetName() string {
	return lis.name
}

// GetType returns the type of this identity store
func (lis *LocalIdentityStore) GetType() string {
	return "local"
}

// Validate validates the identity store configuration
func (lis *LocalIdentityStore) Validate() error {
	if lis.db == nil {
		return fmt.Errorf("database connection is required")
	}
	if lis.name == "" {
		return fmt.Errorf("identity store name is required")
	}
	return nil
}

// Helper methods

func (lis *LocalIdentityStore) updateLastLogin(ctx context.Context, username string) error {
	_, err := lis.db.ExecContext(ctx, 
		"UPDATE local_users SET last_login = ? WHERE username = ?",
		time.Now(), username)
	return err
}

// SupportsPasswordChange indicates if this store supports password changes
func (lis *LocalIdentityStore) SupportsPasswordChange() bool {
	return true
}

// SupportsUserCreation indicates if this store supports user creation
func (lis *LocalIdentityStore) SupportsUserCreation() bool {
	return true
}

// SupportsUserDeletion indicates if this store supports user deletion
func (lis *LocalIdentityStore) SupportsUserDeletion() bool {
	return true
}