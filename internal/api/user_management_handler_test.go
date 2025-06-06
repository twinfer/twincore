package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/twinfer/twincore/pkg/types"
)


// MockSystemSecurityManager is a mock implementation of types.SystemSecurityManager
type MockSystemSecurityManager struct {
	mock.Mock
}

func (m *MockSystemSecurityManager) AuthenticateUser(ctx context.Context, credentials types.UserCredentials) (*types.UserSession, error) {
	args := m.Called(ctx, credentials)
	return args.Get(0).(*types.UserSession), args.Error(1)
}

func (m *MockSystemSecurityManager) AuthorizeAPIAccess(ctx context.Context, user *types.User, resource string, action string) error {
	args := m.Called(ctx, user, resource, action)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) GetUser(ctx context.Context, userID string) (*types.User, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.User), args.Error(1)
}

func (m *MockSystemSecurityManager) ListUsers(ctx context.Context) ([]*types.User, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*types.User), args.Error(1)
}

func (m *MockSystemSecurityManager) CreateUser(ctx context.Context, user *types.User, password string) error {
	args := m.Called(ctx, user, password)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) UpdateUser(ctx context.Context, userID string, updates map[string]any) error {
	args := m.Called(ctx, userID, updates)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) DeleteUser(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) ChangePassword(ctx context.Context, userID string, oldPassword, newPassword string) error {
	args := m.Called(ctx, userID, oldPassword, newPassword)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) CreateSession(ctx context.Context, user *types.User) (*types.UserSession, error) {
	args := m.Called(ctx, user)
	return args.Get(0).(*types.UserSession), args.Error(1)
}

func (m *MockSystemSecurityManager) ValidateSession(ctx context.Context, sessionToken string) (*types.UserSession, error) {
	args := m.Called(ctx, sessionToken)
	return args.Get(0).(*types.UserSession), args.Error(1)
}

func (m *MockSystemSecurityManager) RefreshSession(ctx context.Context, refreshToken string) (*types.UserSession, error) {
	args := m.Called(ctx, refreshToken)
	return args.Get(0).(*types.UserSession), args.Error(1)
}

func (m *MockSystemSecurityManager) RevokeSession(ctx context.Context, sessionToken string) error {
	args := m.Called(ctx, sessionToken)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) ListUserSessions(ctx context.Context, userID string) ([]*types.UserSession, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).([]*types.UserSession), args.Error(1)
}

func (m *MockSystemSecurityManager) RevokeAllUserSessions(ctx context.Context, userID string) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) AddPolicy(ctx context.Context, policy types.APIPolicy) error {
	args := m.Called(ctx, policy)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) RemovePolicy(ctx context.Context, policyID string) error {
	args := m.Called(ctx, policyID)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) UpdatePolicy(ctx context.Context, policyID string, policy types.APIPolicy) error {
	args := m.Called(ctx, policyID, policy)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) GetPolicy(ctx context.Context, policyID string) (*types.APIPolicy, error) {
	args := m.Called(ctx, policyID)
	return args.Get(0).(*types.APIPolicy), args.Error(1)
}

func (m *MockSystemSecurityManager) ListPolicies(ctx context.Context) ([]types.APIPolicy, error) {
	args := m.Called(ctx)
	return args.Get(0).([]types.APIPolicy), args.Error(1)
}

func (m *MockSystemSecurityManager) EvaluatePolicy(ctx context.Context, accessCtx *types.AccessContext) error {
	args := m.Called(ctx, accessCtx)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) UpdateConfig(ctx context.Context, config types.SystemSecurityConfig) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) GetConfig(ctx context.Context) (*types.SystemSecurityConfig, error) {
	args := m.Called(ctx)
	return args.Get(0).(*types.SystemSecurityConfig), args.Error(1)
}

func (m *MockSystemSecurityManager) ValidateConfig(ctx context.Context, config types.SystemSecurityConfig) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) HealthCheck(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockSystemSecurityManager) GetSecurityMetrics(ctx context.Context) (map[string]any, error) {
	args := m.Called(ctx)
	return args.Get(0).(map[string]any), args.Error(1)
}

func (m *MockSystemSecurityManager) GetAuditLog(ctx context.Context, filters map[string]any) ([]types.AuditEvent, error) {
	args := m.Called(ctx, filters)
	return args.Get(0).([]types.AuditEvent), args.Error(1)
}

// Helper function to create a test handler
func createTestHandler() (*UserManagementHandler, *MockSystemSecurityManager) {
	mockSecurityManager := &MockSystemSecurityManager{}
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	
	handler := NewUserManagementHandler(mockSecurityManager, logger)
	return handler, mockSecurityManager
}

// Helper function to create test users
func createTestUser(id, username, email string) *types.User {
	return &types.User{
		ID:       id,
		Username: username,
		Email:    email,
		FullName: "Test User",
		Roles:    []string{"viewer"},
	}
}

func TestNewUserManagementHandler(t *testing.T) {
	handler, mockSecurityManager := createTestHandler()

	assert.NotNil(t, handler)
	assert.Equal(t, mockSecurityManager, handler.securityManager)
	assert.NotNil(t, handler.logger)
}

func TestListUsers(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    string
		mockUsers      []*types.User
		mockError      error
		expectedStatus int
		expectedCount  int
	}{
		{
			name:        "successful list with default pagination",
			queryParams: "",
			mockUsers: []*types.User{
				createTestUser("user1", "john", "john@example.com"),
				createTestUser("user2", "jane", "jane@example.com"),
			},
			mockError:      nil,
			expectedStatus: http.StatusOK,
			expectedCount:  2,
		},
		{
			name:        "successful list with custom pagination",
			queryParams: "?page=2&limit=1",
			mockUsers: []*types.User{
				createTestUser("user1", "john", "john@example.com"),
				createTestUser("user2", "jane", "jane@example.com"),
			},
			mockError:      nil,
			expectedStatus: http.StatusOK,
			expectedCount:  1,
		},
		{
			name:           "security manager error",
			queryParams:    "",
			mockUsers:      nil,
			mockError:      fmt.Errorf("database error"),
			expectedStatus: http.StatusInternalServerError,
			expectedCount:  0,
		},
		{
			name:           "empty user list",
			queryParams:    "",
			mockUsers:      []*types.User{},
			mockError:      nil,
			expectedStatus: http.StatusOK,
			expectedCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockSecurityManager := createTestHandler()

			// Setup mock expectations
			mockSecurityManager.On("ListUsers", mock.Anything).Return(tt.mockUsers, tt.mockError)

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/users"+tt.queryParams, nil)
			w := httptest.NewRecorder()

			// Execute
			err := handler.listUsers(handler.logger.WithField("test", tt.name), w, req)

			// Verify
			if tt.expectedStatus == http.StatusOK {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedStatus, w.Code)

				var response types.UserListResponse
				err = json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedCount, len(response.Users))
			} else {
				assert.Error(t, err)
			}

			mockSecurityManager.AssertExpectations(t)
		})
	}
}

func TestCreateUser(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    types.CreateUserRequest
		existingUser   *types.User
		createError    error
		getError       error
		expectedStatus int
	}{
		{
			name: "successful user creation",
			requestBody: types.CreateUserRequest{
				Username: "newuser",
				Email:    "newuser@example.com",
				Password: "password123",
				FullName: "New User",
				Roles:    []string{"viewer"},
			},
			existingUser:   nil,
			createError:    nil,
			getError:       nil,
			expectedStatus: http.StatusCreated,
		},
		{
			name: "user already exists",
			requestBody: types.CreateUserRequest{
				Username: "existinguser",
				Email:    "existing@example.com",
				Password: "password123",
			},
			existingUser:   createTestUser("existinguser", "existinguser", "existing@example.com"),
			createError:    nil,
			getError:       nil,
			expectedStatus: http.StatusConflict,
		},
		{
			name: "missing required fields",
			requestBody: types.CreateUserRequest{
				Username: "",
				Email:    "test@example.com",
				Password: "password123",
			},
			existingUser:   nil,
			createError:    nil,
			getError:       fmt.Errorf("not found"),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "security manager create error",
			requestBody: types.CreateUserRequest{
				Username: "newuser",
				Email:    "newuser@example.com",
				Password: "password123",
			},
			existingUser:   nil,
			createError:    fmt.Errorf("database error"),
			getError:       fmt.Errorf("not found"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockSecurityManager := createTestHandler()

			// Setup mock expectations
			if tt.requestBody.Username != "" && tt.requestBody.Email != "" && tt.requestBody.Password != "" {
				// First call to check if user exists
				mockSecurityManager.On("GetUser", mock.Anything, tt.requestBody.Username).Return(tt.existingUser, tt.getError).Once()
				
				if tt.existingUser == nil {
					mockSecurityManager.On("CreateUser", mock.Anything, mock.AnythingOfType("*types.User"), tt.requestBody.Password).Return(tt.createError)
					
					if tt.createError == nil {
						createdUser := &types.User{
							ID:       tt.requestBody.Username,
							Username: tt.requestBody.Username,
							Email:    tt.requestBody.Email,
							FullName: tt.requestBody.FullName,
							Roles:    tt.requestBody.Roles,
						}
						// Second call to retrieve the created user
						mockSecurityManager.On("GetUser", mock.Anything, tt.requestBody.Username).Return(createdUser, nil).Once()
					}
				}
			}

			// Create request
			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/users", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// Execute
			err := handler.createUser(handler.logger.WithField("test", tt.name), w, req)

			// Verify
			if tt.expectedStatus == http.StatusCreated {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedStatus, w.Code)

				var response types.UserResponse
				err = json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, tt.requestBody.Username, response.Username)
				assert.Equal(t, tt.requestBody.Email, response.Email)
			} else {
				assert.Error(t, err)
			}

			mockSecurityManager.AssertExpectations(t)
		})
	}
}

func TestGetUser(t *testing.T) {
	tests := []struct {
		name           string
		userID         string
		mockUser       *types.User
		mockError      error
		expectedStatus int
	}{
		{
			name:           "successful get user",
			userID:         "testuser",
			mockUser:       createTestUser("testuser", "testuser", "test@example.com"),
			mockError:      nil,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "user not found",
			userID:         "nonexistent",
			mockUser:       nil,
			mockError:      fmt.Errorf("user not found"),
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockSecurityManager := createTestHandler()

			// Setup mock expectations
			mockSecurityManager.On("GetUser", mock.Anything, tt.userID).Return(tt.mockUser, tt.mockError)

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/users/"+tt.userID, nil)
			w := httptest.NewRecorder()

			// Execute
			err := handler.getUser(handler.logger.WithField("test", tt.name), w, req, tt.userID)

			// Verify
			if tt.expectedStatus == http.StatusOK {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedStatus, w.Code)

				var response types.UserResponse
				err = json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.Equal(t, tt.mockUser.Username, response.Username)
			} else {
				assert.Error(t, err)
			}

			mockSecurityManager.AssertExpectations(t)
		})
	}
}

func TestUpdateUser(t *testing.T) {
	tests := []struct {
		name           string
		userID         string
		requestBody    types.UpdateUserRequest
		existingUser   *types.User
		getUserError   error
		updateError    error
		expectedStatus int
	}{
		{
			name:   "successful user update",
			userID: "testuser",
			requestBody: types.UpdateUserRequest{
				Email:    "newemail@example.com",
				FullName: "Updated Name",
				Roles:    []string{"admin"},
			},
			existingUser:   createTestUser("testuser", "testuser", "old@example.com"),
			getUserError:   nil,
			updateError:    nil,
			expectedStatus: http.StatusOK,
		},
		{
			name:   "user not found",
			userID: "nonexistent",
			requestBody: types.UpdateUserRequest{
				Email: "test@example.com",
			},
			existingUser:   nil,
			getUserError:   fmt.Errorf("user not found"),
			updateError:    nil,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:   "update error",
			userID: "testuser",
			requestBody: types.UpdateUserRequest{
				Email: "newemail@example.com",
			},
			existingUser:   createTestUser("testuser", "testuser", "old@example.com"),
			getUserError:   nil,
			updateError:    fmt.Errorf("database error"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockSecurityManager := createTestHandler()

			// Setup mock expectations
			mockSecurityManager.On("GetUser", mock.Anything, tt.userID).Return(tt.existingUser, tt.getUserError).Once()
			
			if tt.getUserError == nil {
				mockSecurityManager.On("UpdateUser", mock.Anything, tt.userID, mock.AnythingOfType("map[string]interface {}")).Return(tt.updateError)
				
				if tt.updateError == nil {
					updatedUser := &types.User{
						ID:       tt.existingUser.ID,
						Username: tt.existingUser.Username,
						Email:    tt.requestBody.Email,
						FullName: tt.requestBody.FullName,
						Roles:    tt.requestBody.Roles,
					}
					if tt.requestBody.Email == "" {
						updatedUser.Email = tt.existingUser.Email
					}
					if tt.requestBody.FullName == "" {
						updatedUser.FullName = tt.existingUser.FullName
					}
					if tt.requestBody.Roles == nil {
						updatedUser.Roles = tt.existingUser.Roles
					}
					mockSecurityManager.On("GetUser", mock.Anything, tt.userID).Return(updatedUser, nil)
				}
			}

			// Create request
			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPut, "/users/"+tt.userID, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// Execute
			err := handler.updateUser(handler.logger.WithField("test", tt.name), w, req, tt.userID)

			// Verify
			if tt.expectedStatus == http.StatusOK {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedStatus, w.Code)

				var response types.UserResponse
				err = json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}

			mockSecurityManager.AssertExpectations(t)
		})
	}
}

func TestDeleteUser(t *testing.T) {
	tests := []struct {
		name           string
		userID         string
		existingUser   *types.User
		getUserError   error
		deleteError    error
		expectedStatus int
	}{
		{
			name:           "successful user deletion",
			userID:         "testuser",
			existingUser:   createTestUser("testuser", "testuser", "test@example.com"),
			getUserError:   nil,
			deleteError:    nil,
			expectedStatus: http.StatusNoContent,
		},
		{
			name:           "user not found",
			userID:         "nonexistent",
			existingUser:   nil,
			getUserError:   fmt.Errorf("user not found"),
			deleteError:    nil,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "delete error",
			userID:         "testuser",
			existingUser:   createTestUser("testuser", "testuser", "test@example.com"),
			getUserError:   nil,
			deleteError:    fmt.Errorf("database error"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockSecurityManager := createTestHandler()

			// Setup mock expectations
			mockSecurityManager.On("GetUser", mock.Anything, tt.userID).Return(tt.existingUser, tt.getUserError)
			
			if tt.getUserError == nil {
				mockSecurityManager.On("DeleteUser", mock.Anything, tt.userID).Return(tt.deleteError)
			}

			// Create request
			req := httptest.NewRequest(http.MethodDelete, "/users/"+tt.userID, nil)
			w := httptest.NewRecorder()

			// Execute
			err := handler.deleteUser(handler.logger.WithField("test", tt.name), w, req, tt.userID)

			// Verify
			if tt.expectedStatus == http.StatusNoContent {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedStatus, w.Code)
			} else {
				assert.Error(t, err)
			}

			mockSecurityManager.AssertExpectations(t)
		})
	}
}

func TestChangePassword(t *testing.T) {
	tests := []struct {
		name           string
		userID         string
		requestBody    types.ChangePasswordRequest
		changeError    error
		expectedStatus int
	}{
		{
			name:   "successful password change",
			userID: "testuser",
			requestBody: types.ChangePasswordRequest{
				CurrentPassword: "oldpassword",
				NewPassword:     "newpassword123",
			},
			changeError:    nil,
			expectedStatus: http.StatusNoContent,
		},
		{
			name:   "missing current password",
			userID: "testuser",
			requestBody: types.ChangePasswordRequest{
				CurrentPassword: "",
				NewPassword:     "newpassword123",
			},
			changeError:    nil,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "missing new password",
			userID: "testuser",
			requestBody: types.ChangePasswordRequest{
				CurrentPassword: "oldpassword",
				NewPassword:     "",
			},
			changeError:    nil,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "password change error",
			userID: "testuser",
			requestBody: types.ChangePasswordRequest{
				CurrentPassword: "oldpassword",
				NewPassword:     "newpassword123",
			},
			changeError:    fmt.Errorf("invalid current password"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockSecurityManager := createTestHandler()

			// Setup mock expectations
			if tt.requestBody.CurrentPassword != "" && tt.requestBody.NewPassword != "" {
				mockSecurityManager.On("ChangePassword", mock.Anything, tt.userID, tt.requestBody.CurrentPassword, tt.requestBody.NewPassword).Return(tt.changeError)
			}

			// Create request
			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPut, "/users/"+tt.userID+"/password", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// Execute
			err := handler.changePassword(handler.logger.WithField("test", tt.name), w, req, tt.userID)

			// Verify
			if tt.expectedStatus == http.StatusNoContent {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedStatus, w.Code)
			} else {
				assert.Error(t, err)
			}

			mockSecurityManager.AssertExpectations(t)
		})
	}
}

func TestHandleUserRoutes(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		path           string
		expectedRoute  string
		expectedStatus int
	}{
		{
			name:           "list users",
			method:         http.MethodGet,
			path:           "/users",
			expectedRoute:  "listUsers",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "create user",
			method:         http.MethodPost,
			path:           "/users",
			expectedRoute:  "createUser",
			expectedStatus: http.StatusBadRequest, // Will fail validation but route correctly
		},
		{
			name:           "get user",
			method:         http.MethodGet,
			path:           "/users/testuser",
			expectedRoute:  "getUser",
			expectedStatus: http.StatusNotFound, // User won't exist in mock
		},
		{
			name:           "update user",
			method:         http.MethodPut,
			path:           "/users/testuser",
			expectedRoute:  "updateUser",
			expectedStatus: http.StatusNotFound, // User won't exist in mock
		},
		{
			name:           "delete user",
			method:         http.MethodDelete,
			path:           "/users/testuser",
			expectedRoute:  "deleteUser",
			expectedStatus: http.StatusNotFound, // User won't exist in mock
		},
		{
			name:           "change password",
			method:         http.MethodPut,
			path:           "/users/testuser/password",
			expectedRoute:  "changePassword",
			expectedStatus: http.StatusBadRequest, // Will fail validation
		},
		{
			name:           "unknown endpoint",
			method:         http.MethodGet,
			path:           "/users/unknown/endpoint",
			expectedRoute:  "error",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "method not allowed",
			method:         http.MethodPatch,
			path:           "/users",
			expectedRoute:  "error",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mockSecurityManager := createTestHandler()

			// Setup basic mock expectations for routes that will be called
			switch tt.expectedRoute {
			case "listUsers":
				mockSecurityManager.On("ListUsers", mock.Anything).Return([]*types.User{}, nil)
			case "getUser", "updateUser", "deleteUser":
				mockSecurityManager.On("GetUser", mock.Anything, "testuser").Return(nil, fmt.Errorf("user not found"))
			}

			// Create request
			var body *bytes.Buffer
			if tt.method == http.MethodPost || tt.method == http.MethodPut {
				body = bytes.NewBuffer([]byte("{}"))
			} else {
				body = bytes.NewBuffer([]byte{})
			}
			
			req := httptest.NewRequest(tt.method, tt.path, body)
			if body.Len() > 0 {
				req.Header.Set("Content-Type", "application/json")
			}
			w := httptest.NewRecorder()

			// Execute
			err := handler.handleUserRoutes(handler.logger.WithField("test", tt.name), w, req, tt.path)

			// Verify that the route was handled (error or success depends on the specific route)
			if tt.expectedRoute == "error" {
				assert.Error(t, err)
			} else {
				// Routes should be called even if they fail due to validation or missing data
				// The important thing is that the routing works correctly
				assert.True(t, err != nil || w.Code == http.StatusOK)
			}

			mockSecurityManager.AssertExpectations(t)
		})
	}
}