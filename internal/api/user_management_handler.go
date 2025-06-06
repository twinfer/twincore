package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/sirupsen/logrus"

	"github.com/twinfer/twincore/pkg/types"
)

// UserManagementHandler handles user management operations
// This integrates with the existing caddy-security infrastructure
type UserManagementHandler struct {
	securityManager types.SystemSecurityManager
	logger          *logrus.Logger
}

// NewUserManagementHandler creates a new user management handler
func NewUserManagementHandler(
	securityManager types.SystemSecurityManager,
	logger *logrus.Logger,
) *UserManagementHandler {
	return &UserManagementHandler{
		securityManager: securityManager,
		logger:          logger,
	}
}

// handleUserRoutes handles /api/users/* routes
func (h *UserManagementHandler) handleUserRoutes(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, path string) error {
	logger.Debug("Routing user management request")

	// Remove /users prefix
	path = strings.TrimPrefix(path, "/users")

	switch {
	case path == "" && r.Method == http.MethodGet:
		return h.listUsers(logger, w, r)
	case path == "" && r.Method == http.MethodPost:
		return h.createUser(logger, w, r)
	case strings.HasPrefix(path, "/") && len(path) > 1:
		// Extract user ID
		userID := strings.TrimPrefix(path, "/")
		parts := strings.Split(userID, "/")
		userID = parts[0]

		if len(parts) == 1 {
			// Direct user operations: /users/{id}
			switch r.Method {
			case http.MethodGet:
				return h.getUser(logger, w, r, userID)
			case http.MethodPut:
				return h.updateUser(logger, w, r, userID)
			case http.MethodDelete:
				return h.deleteUser(logger, w, r, userID)
			default:
				return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
			}
		} else if len(parts) == 2 && parts[1] == "password" {
			// Password change: /users/{id}/password
			if r.Method == http.MethodPut {
				return h.changePassword(logger, w, r, userID)
			}
			return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		}
	}

	return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("unknown user management endpoint"))
}

// @Summary List all users
// @Description Retrieve all registered user accounts (admin only)
// @Tags Users
// @Produce json
// @Param page query int false "Page number (default: 1)"
// @Param limit query int false "Items per page (default: 10, max: 100)"
// @Success 200 {object} types.UserListResponse
// @Failure 403 {object} types.ErrorResponse "Insufficient permissions"
// @Failure 500 {object} types.ErrorResponse
// @Security BearerAuth
// @Router /users [get]
func (h *UserManagementHandler) listUsers(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	// TODO: Extract user from JWT token for authorization
	// For now, we'll proceed - authorization should be handled by caddy-security middleware

	// Parse pagination parameters
	page := 1
	limit := 10

	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	// Get all users from security manager
	systemUsers, err := h.securityManager.ListUsers(ctx)
	if err != nil {
		logger.WithError(err).Error("Failed to list users")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	// Convert to API response format
	var users []types.UserResponse
	for _, user := range systemUsers {
		userResponse := types.NewUserResponse(
			user.ID,
			user.Username,
			user.Email,
			user.FullName,
			user.Roles,
			false, // disabled - we'll need to get this from somewhere else or default to false
			// For now, using placeholder timestamps - ideally these would come from the User struct
			time.Now(), time.Now(), nil,
		)
		users = append(users, *userResponse)
	}

	// Apply pagination
	total := len(users)
	start := (page - 1) * limit
	end := start + limit

	if start >= total {
		users = []types.UserResponse{}
	} else {
		if end > total {
			end = total
		}
		users = users[start:end]
	}

	response := types.NewUserListResponse(users, total, page, limit)

	w.Header().Set(headerContentType, contentTypeJSON)
	return json.NewEncoder(w).Encode(response)
}

// @Summary Create new user
// @Description Create a new user account with specified roles (admin only)
// @Tags Users
// @Accept json
// @Produce json
// @Param user body types.CreateUserRequest true "User details"
// @Success 201 {object} types.UserResponse
// @Failure 400 {object} types.ErrorResponse "Invalid request"
// @Failure 409 {object} types.ErrorResponse "User already exists"
// @Failure 500 {object} types.ErrorResponse
// @Security BearerAuth
// @Router /users [post]
func (h *UserManagementHandler) createUser(logger *logrus.Entry, w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	// Parse request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.WithError(err).Error("Failed to read request body")
		return caddyhttp.Error(http.StatusBadRequest, err)
	}
	defer r.Body.Close()

	var createReq types.CreateUserRequest
	if err := json.Unmarshal(body, &createReq); err != nil {
		logger.WithError(err).Error("Failed to parse request body")
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
	}

	// Basic validation
	if createReq.Username == "" || createReq.Email == "" || createReq.Password == "" {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("username, email, and password are required"))
	}

	// Check if user already exists by trying to get it
	if existingUser, err := h.securityManager.GetUser(ctx, createReq.Username); err == nil && existingUser != nil {
		return caddyhttp.Error(http.StatusConflict, fmt.Errorf("user already exists"))
	}

	// Convert to User and create
	user := &types.User{
		ID:       createReq.Username, // Using username as ID
		Username: createReq.Username,
		Email:    createReq.Email,
		FullName: createReq.FullName,
		Roles:    createReq.Roles,
	}

	if err := h.securityManager.CreateUser(ctx, user, createReq.Password); err != nil {
		logger.WithError(err).WithField("username", createReq.Username).Error("Failed to create user")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	// Get the created user (to get populated fields like timestamps)
	createdUser, err := h.securityManager.GetUser(ctx, createReq.Username)
	if err != nil {
		logger.WithError(err).WithField("username", createReq.Username).Error("Failed to retrieve created user")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	response := types.NewUserResponse(
		createdUser.ID,
		createdUser.Username,
		createdUser.Email,
		createdUser.FullName,
		createdUser.Roles,
		false,                       // disabled - we'll need to get this from somewhere else or default to false
		time.Now(), time.Now(), nil, // placeholder timestamps
	)
	w.Header().Set(headerContentType, contentTypeJSON)
	w.WriteHeader(http.StatusCreated)
	return json.NewEncoder(w).Encode(response)
}

// @Summary Get user by ID
// @Description Retrieve a specific user account by username
// @Tags Users
// @Produce json
// @Param id path string true "Username"
// @Success 200 {object} types.UserResponse
// @Failure 404 {object} types.ErrorResponse "User not found"
// @Failure 500 {object} types.ErrorResponse
// @Security BearerAuth
// @Router /users/{id} [get]
func (h *UserManagementHandler) getUser(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, userID string) error {
	ctx := r.Context()

	// Get user from security manager
	user, err := h.securityManager.GetUser(ctx, userID)
	if err != nil {
		logger.WithError(err).WithField("user_id", userID).Error("Failed to get user")
		return caddyhttp.Error(http.StatusNotFound, err)
	}

	response := types.NewUserResponse(
		user.ID,
		user.Username,
		user.Email,
		user.FullName,
		user.Roles,
		false,                       // disabled - placeholder
		time.Now(), time.Now(), nil, // placeholder timestamps
	)
	w.Header().Set(headerContentType, contentTypeJSON)
	return json.NewEncoder(w).Encode(response)
}

// @Summary Update user
// @Description Update user account details and roles (admin only)
// @Tags Users
// @Accept json
// @Produce json
// @Param id path string true "Username"
// @Param user body types.UpdateUserRequest true "Updated user details"
// @Success 200 {object} types.UserResponse
// @Failure 400 {object} types.ErrorResponse "Invalid request"
// @Failure 404 {object} types.ErrorResponse "User not found"
// @Failure 500 {object} types.ErrorResponse
// @Security BearerAuth
// @Router /users/{id} [put]
func (h *UserManagementHandler) updateUser(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, userID string) error {
	ctx := r.Context()

	// Parse request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.WithError(err).Error("Failed to read request body")
		return caddyhttp.Error(http.StatusBadRequest, err)
	}
	defer r.Body.Close()

	var updateReq types.UpdateUserRequest
	if err := json.Unmarshal(body, &updateReq); err != nil {
		logger.WithError(err).Error("Failed to parse request body")
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
	}

	// Check that user exists
	_, err = h.securityManager.GetUser(ctx, userID)
	if err != nil {
		logger.WithError(err).WithField("user_id", userID).Error("Failed to get user for update")
		return caddyhttp.Error(http.StatusNotFound, err)
	}

	// Convert update request to map
	updates := make(map[string]any)
	if updateReq.Email != "" {
		updates["email"] = updateReq.Email
	}
	if updateReq.FullName != "" {
		updates["full_name"] = updateReq.FullName
	}
	if updateReq.Roles != nil {
		updates["roles"] = updateReq.Roles
	}
	if updateReq.Disabled != nil {
		updates["disabled"] = *updateReq.Disabled
	}

	// Update user in security manager
	if err := h.securityManager.UpdateUser(ctx, userID, updates); err != nil {
		logger.WithError(err).WithField("user_id", userID).Error("Failed to update user")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	// Get updated user
	updatedUser, err := h.securityManager.GetUser(ctx, userID)
	if err != nil {
		logger.WithError(err).WithField("user_id", userID).Error("Failed to retrieve updated user")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	response := types.NewUserResponse(
		updatedUser.ID,
		updatedUser.Username,
		updatedUser.Email,
		updatedUser.FullName,
		updatedUser.Roles,
		false,                       // disabled - placeholder
		time.Now(), time.Now(), nil, // placeholder timestamps
	)
	w.Header().Set(headerContentType, contentTypeJSON)
	return json.NewEncoder(w).Encode(response)
}

// @Summary Delete user
// @Description Delete a user account (admin only)
// @Tags Users
// @Param id path string true "Username"
// @Success 204 "No Content"
// @Failure 404 {object} types.ErrorResponse "User not found"
// @Failure 500 {object} types.ErrorResponse
// @Security BearerAuth
// @Router /users/{id} [delete]
func (h *UserManagementHandler) deleteUser(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, userID string) error {
	ctx := r.Context()

	// Check if user exists first
	_, err := h.securityManager.GetUser(ctx, userID)
	if err != nil {
		logger.WithError(err).WithField("user_id", userID).Debug("User not found for deletion")
		return caddyhttp.Error(http.StatusNotFound, fmt.Errorf("user not found"))
	}

	// Delete user from security manager
	if err := h.securityManager.DeleteUser(ctx, userID); err != nil {
		logger.WithError(err).WithField("user_id", userID).Error("Failed to delete user")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

// @Summary Change user password
// @Description Change a user's password
// @Tags Users
// @Accept json
// @Param id path string true "Username"
// @Param password body types.ChangePasswordRequest true "Password change request"
// @Success 204 "No Content"
// @Failure 400 {object} types.ErrorResponse "Invalid request"
// @Failure 401 {object} types.ErrorResponse "Current password incorrect"
// @Failure 404 {object} types.ErrorResponse "User not found"
// @Failure 500 {object} types.ErrorResponse
// @Security BearerAuth
// @Router /users/{id}/password [put]
func (h *UserManagementHandler) changePassword(logger *logrus.Entry, w http.ResponseWriter, r *http.Request, userID string) error {
	ctx := r.Context()

	// Parse request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.WithError(err).Error("Failed to read request body")
		return caddyhttp.Error(http.StatusBadRequest, err)
	}
	defer r.Body.Close()

	var changeReq types.ChangePasswordRequest
	if err := json.Unmarshal(body, &changeReq); err != nil {
		logger.WithError(err).Error("Failed to parse request body")
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
	}

	// Basic validation
	if changeReq.CurrentPassword == "" || changeReq.NewPassword == "" {
		return caddyhttp.Error(http.StatusBadRequest, fmt.Errorf("current_password and new_password are required"))
	}

	// Change password using security manager (it should verify the current password internally)
	if err := h.securityManager.ChangePassword(ctx, userID, changeReq.CurrentPassword, changeReq.NewPassword); err != nil {
		logger.WithError(err).WithField("user_id", userID).Error("Failed to change password")
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	logger.WithField("user_id", userID).Info("Password changed successfully")
	w.WriteHeader(http.StatusNoContent)
	return nil
}
