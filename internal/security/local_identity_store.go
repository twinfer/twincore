package security

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"

	"github.com/twinfer/twincore/internal/database"
	"github.com/twinfer/twincore/pkg/types"
)

// LocalIdentityStore implements a local identity store for caddy-auth-portal
// This bridges our local user database to caddy-security's authentication system
type LocalIdentityStore struct {
	securityRepo database.SecurityRepositoryInterface
	logger       *logrus.Logger
	name         string
}

// NewLocalIdentityStore creates a new local identity store
func NewLocalIdentityStore(securityRepo database.SecurityRepositoryInterface, logger *logrus.Logger, name string) *LocalIdentityStore {
	return &LocalIdentityStore{
		securityRepo: securityRepo,
		logger:       logger,
		name:         name,
	}
}

// AuthUser represents a user in the identity store format expected by caddy-auth-portal
type AuthUser struct {
	ID        string            `json:"id"`
	Username  string            `json:"username"`
	Email     string            `json:"email,omitempty"`
	FullName  string            `json:"name,omitempty"`
	Roles     []string          `json:"roles,omitempty"`
	Password  string            `json:"password,omitempty"` // Hashed password
	Disabled  bool              `json:"disabled,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
	LastLogin *time.Time        `json:"last_login,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

// GetUser retrieves a user for authentication purposes
func (lis *LocalIdentityStore) GetUser(ctx context.Context, username string) (*AuthUser, error) {
	lis.logger.WithField("username", username).Debug("Getting user from local identity store")

	user, err := lis.securityRepo.GetUser(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Roles are already parsed as []string in types.LocalUser
	roles := user.Roles

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
	}

	if !user.LastLogin.IsZero() {
		authUser.LastLogin = &user.LastLogin
	}

	return authUser, nil
}

// AuthenticateUser verifies user credentials
func (lis *LocalIdentityStore) AuthenticateUser(ctx context.Context, username, password string) (*AuthUser, error) {
	lis.logger.WithField("username", username).Debug("Authenticating user")

	// Get user data for authentication
	userAuth, err := lis.securityRepo.GetUserForAuth(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(userAuth.PasswordHash), []byte(password)); err != nil {
		lis.logger.WithField("username", username).Warn("Password verification failed")
		return nil, fmt.Errorf("invalid credentials")
	}

	// Update last login
	if err := lis.securityRepo.UpdateLastLogin(ctx, username); err != nil {
		lis.logger.WithError(err).WithField("username", username).Warn("Failed to update last login")
		// Don't fail authentication for this
	}

	// Get full user info and convert to AuthUser
	user, err := lis.GetUser(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info after authentication: %w", err)
	}

	lis.logger.WithField("username", username).Info("User authenticated successfully")
	return user, nil
}

// CreateUser creates a new user in the identity store
func (lis *LocalIdentityStore) CreateUser(ctx context.Context, authUser *AuthUser) error {
	lis.logger.WithField("username", authUser.Username).Debug("Creating user in local identity store")

	// Hash password if provided
	var passwordHash string
	if authUser.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(authUser.Password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}
		passwordHash = string(hash)
	}

	// Create types.LocalUser for repository
	user := &types.LocalUser{
		Username:     authUser.Username,
		PasswordHash: passwordHash,
		Email:        authUser.Email,
		FullName:     authUser.FullName,
		Roles:        authUser.Roles,
		Disabled:     authUser.Disabled,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := lis.securityRepo.CreateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	lis.logger.WithField("username", authUser.Username).Info("User created successfully")
	return nil
}

// UpdateUser updates an existing user
func (lis *LocalIdentityStore) UpdateUser(ctx context.Context, authUser *AuthUser) error {
	lis.logger.WithField("username", authUser.Username).Debug("Updating user in local identity store")

	// Hash password if provided and changed
	var passwordHash string
	if authUser.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(authUser.Password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash password: %w", err)
		}
		passwordHash = string(hash)
	} else {
		// Get existing password hash if no new password provided
		existingUser, err := lis.securityRepo.GetUser(ctx, authUser.Username)
		if err != nil {
			return fmt.Errorf("failed to get existing user: %w", err)
		}
		passwordHash = existingUser.PasswordHash
	}

	// Create types.LocalUser for repository
	user := &types.LocalUser{
		Username:     authUser.Username,
		PasswordHash: passwordHash,
		Email:        authUser.Email,
		FullName:     authUser.FullName,
		Roles:        authUser.Roles,
		Disabled:     authUser.Disabled,
		UpdatedAt:    time.Now(),
	}

	if err := lis.securityRepo.UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	lis.logger.WithField("username", authUser.Username).Info("User updated successfully")
	return nil
}

// DeleteUser removes a user from the identity store
func (lis *LocalIdentityStore) DeleteUser(ctx context.Context, username string) error {
	lis.logger.WithField("username", username).Debug("Deleting user from local identity store")

	if err := lis.securityRepo.DeleteUser(ctx, username); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	lis.logger.WithField("username", username).Info("User deleted successfully")
	return nil
}

// ListUsers returns all users in the identity store
func (lis *LocalIdentityStore) ListUsers(ctx context.Context) ([]*AuthUser, error) {
	lis.logger.Debug("Listing all users from local identity store")

	users, err := lis.securityRepo.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	var authUsers []*AuthUser
	for _, user := range users {
		// Roles are already parsed as []string in types.LocalUser
		roles := user.Roles

		authUser := &AuthUser{
			ID:        user.Username,
			Username:  user.Username,
			Email:     user.Email,
			FullName:  user.FullName,
			Roles:     roles,
			Disabled:  user.Disabled,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
		}

		if !user.LastLogin.IsZero() {
			authUser.LastLogin = &user.LastLogin
		}

		authUsers = append(authUsers, authUser)
	}

	lis.logger.WithField("count", len(authUsers)).Debug("Listed users successfully")
	return authUsers, nil
}

// UserExists checks if a user exists in the identity store
func (lis *LocalIdentityStore) UserExists(ctx context.Context, username string) (bool, error) {
	return lis.securityRepo.UserExists(ctx, username)
}

// GetName returns the name of this identity store
func (lis *LocalIdentityStore) GetName() string {
	return lis.name
}

// ChangePassword changes a user's password
func (lis *LocalIdentityStore) ChangePassword(ctx context.Context, username, newPassword string) error {
	lis.logger.WithField("username", username).Debug("Changing user password")

	// Get existing user
	user, err := lis.securityRepo.GetUser(ctx, username)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Hash new password
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	user.PasswordHash = string(hash)
	user.UpdatedAt = time.Now()

	if err := lis.securityRepo.UpdateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	lis.logger.WithField("username", username).Info("Password changed successfully")
	return nil
}

// ValidateUserRole checks if a user has a specific role
func (lis *LocalIdentityStore) ValidateUserRole(ctx context.Context, username string, requiredRole string) (bool, error) {
	user, err := lis.GetUser(ctx, username)
	if err != nil {
		return false, err
	}

	for _, role := range user.Roles {
		if strings.EqualFold(role, requiredRole) {
			return true, nil
		}
	}

	return false, nil
}

// GetUserCount returns the total number of users
func (lis *LocalIdentityStore) GetUserCount(ctx context.Context) (int, error) {
	users, err := lis.securityRepo.ListUsers(ctx)
	if err != nil {
		return 0, err
	}
	return len(users), nil
}
