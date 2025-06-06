package types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCreateUserRequest_ToLocalUser(t *testing.T) {
	tests := []struct {
		name     string
		request  CreateUserRequest
		expected LocalUser
	}{
		{
			name: "complete user request",
			request: CreateUserRequest{
				Username: "testuser",
				Email:    "test@example.com",
				FullName: "Test User",
				Password: "password123",
				Roles:    []string{"admin", "viewer"},
				Disabled: false,
			},
			expected: LocalUser{
				Username: "testuser",
				Email:    "test@example.com",
				FullName: "Test User",
				Roles:    []string{"admin", "viewer"},
				Disabled: false,
			},
		},
		{
			name: "minimal user request",
			request: CreateUserRequest{
				Username: "minimaluser",
				Email:    "minimal@example.com",
				Password: "password123",
			},
			expected: LocalUser{
				Username: "minimaluser",
				Email:    "minimal@example.com",
				FullName: "",
				Roles:    nil,
				Disabled: false,
			},
		},
		{
			name: "disabled user request",
			request: CreateUserRequest{
				Username: "disableduser",
				Email:    "disabled@example.com",
				Password: "password123",
				Disabled: true,
			},
			expected: LocalUser{
				Username: "disableduser",
				Email:    "disabled@example.com",
				FullName: "",
				Roles:    nil,
				Disabled: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.request.ToLocalUser()

			assert.Equal(t, tt.expected.Username, result.Username)
			assert.Equal(t, tt.expected.Email, result.Email)
			assert.Equal(t, tt.expected.FullName, result.FullName)
			assert.Equal(t, tt.expected.Roles, result.Roles)
			assert.Equal(t, tt.expected.Disabled, result.Disabled)
			
			// Check that timestamps are set
			assert.False(t, result.CreatedAt.IsZero())
			assert.False(t, result.UpdatedAt.IsZero())
			assert.True(t, result.LastLogin.IsZero()) // Should be zero initially
		})
	}
}

func TestFromLocalUser(t *testing.T) {
	now := time.Now()
	lastLogin := now.Add(-24 * time.Hour)

	tests := []struct {
		name     string
		user     LocalUser
		expected UserResponse
	}{
		{
			name: "complete local user",
			user: LocalUser{
				Username:  "testuser",
				Email:     "test@example.com",
				FullName:  "Test User",
				Roles:     []string{"admin", "viewer"},
				Disabled:  false,
				CreatedAt: now,
				UpdatedAt: now,
				LastLogin: lastLogin,
			},
			expected: UserResponse{
				ID:        "testuser", // Username used as ID
				Username:  "testuser",
				Email:     "test@example.com",
				FullName:  "Test User",
				Roles:     []string{"admin", "viewer"},
				Disabled:  false,
				CreatedAt: now.UTC().Format(time.RFC3339),
				UpdatedAt: now.UTC().Format(time.RFC3339),
			},
		},
		{
			name: "local user without last login",
			user: LocalUser{
				Username:  "nologinuser",
				Email:     "nologin@example.com",
				FullName:  "No Login User",
				Roles:     []string{"viewer"},
				Disabled:  false,
				CreatedAt: now,
				UpdatedAt: now,
				LastLogin: time.Time{}, // Zero time
			},
			expected: UserResponse{
				ID:        "nologinuser",
				Username:  "nologinuser",
				Email:     "nologin@example.com",
				FullName:  "No Login User",
				Roles:     []string{"viewer"},
				Disabled:  false,
				CreatedAt: now.UTC().Format(time.RFC3339),
				UpdatedAt: now.UTC().Format(time.RFC3339),
				LastLogin: nil, // Should be nil for zero time
			},
		},
		{
			name: "disabled local user",
			user: LocalUser{
				Username:  "disableduser",
				Email:     "disabled@example.com",
				FullName:  "Disabled User",
				Roles:     []string{},
				Disabled:  true,
				CreatedAt: now,
				UpdatedAt: now,
				LastLogin: lastLogin,
			},
			expected: UserResponse{
				ID:        "disableduser",
				Username:  "disableduser",
				Email:     "disabled@example.com",
				FullName:  "Disabled User",
				Roles:     []string{},
				Disabled:  true,
				CreatedAt: now.UTC().Format(time.RFC3339),
				UpdatedAt: now.UTC().Format(time.RFC3339),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FromLocalUser(&tt.user)

			assert.Equal(t, tt.expected.ID, result.ID)
			assert.Equal(t, tt.expected.Username, result.Username)
			assert.Equal(t, tt.expected.Email, result.Email)
			assert.Equal(t, tt.expected.FullName, result.FullName)
			assert.Equal(t, tt.expected.Roles, result.Roles)
			assert.Equal(t, tt.expected.Disabled, result.Disabled)
			assert.Equal(t, tt.expected.CreatedAt, result.CreatedAt)
			assert.Equal(t, tt.expected.UpdatedAt, result.UpdatedAt)

			if !tt.user.LastLogin.IsZero() {
				assert.NotNil(t, result.LastLogin)
				assert.Equal(t, tt.user.LastLogin.UTC().Format(time.RFC3339), *result.LastLogin)
			} else {
				assert.Nil(t, result.LastLogin)
			}
		})
	}
}

func TestUpdateUserRequest_ApplyUpdate(t *testing.T) {
	now := time.Now()
	originalUser := &LocalUser{
		Username:  "testuser",
		Email:     "old@example.com",
		FullName:  "Old Name",
		Roles:     []string{"viewer"},
		Disabled:  false,
		CreatedAt: now,
		UpdatedAt: now,
	}

	tests := []struct {
		name           string
		updateRequest  UpdateUserRequest
		expectedEmail  string
		expectedName   string
		expectedRoles  []string
		expectedDisabled bool
	}{
		{
			name: "update all fields",
			updateRequest: UpdateUserRequest{
				Email:    "new@example.com",
				FullName: "New Name",
				Roles:    []string{"admin", "operator"},
				Disabled: boolPtr(true),
			},
			expectedEmail:    "new@example.com",
			expectedName:     "New Name",
			expectedRoles:    []string{"admin", "operator"},
			expectedDisabled: true,
		},
		{
			name: "update only email",
			updateRequest: UpdateUserRequest{
				Email: "newemail@example.com",
			},
			expectedEmail:    "newemail@example.com",
			expectedName:     "Old Name", // Should remain unchanged
			expectedRoles:    []string{"viewer"},
			expectedDisabled: false,
		},
		{
			name: "update only roles",
			updateRequest: UpdateUserRequest{
				Roles: []string{"superadmin"},
			},
			expectedEmail:    "old@example.com",
			expectedName:     "Old Name",
			expectedRoles:    []string{"superadmin"},
			expectedDisabled: false,
		},
		{
			name: "disable user only",
			updateRequest: UpdateUserRequest{
				Disabled: boolPtr(true),
			},
			expectedEmail:    "old@example.com",
			expectedName:     "Old Name",
			expectedRoles:    []string{"viewer"},
			expectedDisabled: true,
		},
		{
			name: "empty update request",
			updateRequest: UpdateUserRequest{
				// All fields empty/nil
			},
			expectedEmail:    "old@example.com", // All should remain unchanged
			expectedName:     "Old Name",
			expectedRoles:    []string{"viewer"},
			expectedDisabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a copy of the original user for each test
			testUser := *originalUser
			beforeUpdate := testUser.UpdatedAt

			// Apply the update
			tt.updateRequest.ApplyUpdate(&testUser)

			// Verify the results
			assert.Equal(t, tt.expectedEmail, testUser.Email)
			assert.Equal(t, tt.expectedName, testUser.FullName)
			assert.Equal(t, tt.expectedRoles, testUser.Roles)
			assert.Equal(t, tt.expectedDisabled, testUser.Disabled)

			// Verify UpdatedAt was changed
			assert.True(t, testUser.UpdatedAt.After(beforeUpdate))

			// Verify other fields remain unchanged
			assert.Equal(t, originalUser.Username, testUser.Username)
			assert.Equal(t, originalUser.CreatedAt, testUser.CreatedAt)
		})
	}
}

func TestNewUserResponse(t *testing.T) {
	now := time.Now()
	lastLogin := now.Add(-24 * time.Hour)

	tests := []struct {
		name              string
		id                string
		username          string
		email             string
		fullName          string
		roles             []string
		disabled          bool
		createdAt         time.Time
		updatedAt         time.Time
		lastLogin         *time.Time
		expectedLastLogin *string
	}{
		{
			name:              "user with last login",
			id:                "user1",
			username:          "testuser",
			email:             "test@example.com",
			fullName:          "Test User",
			roles:             []string{"admin"},
			disabled:          false,
			createdAt:         now,
			updatedAt:         now,
			lastLogin:         &lastLogin,
			expectedLastLogin: stringPtr(lastLogin.UTC().Format(time.RFC3339)),
		},
		{
			name:              "user without last login",
			id:                "user2",
			username:          "newuser",
			email:             "new@example.com",
			fullName:          "New User",
			roles:             []string{"viewer"},
			disabled:          false,
			createdAt:         now,
			updatedAt:         now,
			lastLogin:         nil,
			expectedLastLogin: nil,
		},
		{
			name:              "user with zero last login",
			id:                "user3",
			username:          "zerouser",
			email:             "zero@example.com",
			fullName:          "Zero User",
			roles:             []string{},
			disabled:          true,
			createdAt:         now,
			updatedAt:         now,
			lastLogin:         &time.Time{}, // Zero time
			expectedLastLogin: nil,          // Should be nil for zero time
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewUserResponse(
				tt.id,
				tt.username,
				tt.email,
				tt.fullName,
				tt.roles,
				tt.disabled,
				tt.createdAt,
				tt.updatedAt,
				tt.lastLogin,
			)

			assert.Equal(t, tt.id, result.ID)
			assert.Equal(t, tt.username, result.Username)
			assert.Equal(t, tt.email, result.Email)
			assert.Equal(t, tt.fullName, result.FullName)
			assert.Equal(t, tt.roles, result.Roles)
			assert.Equal(t, tt.disabled, result.Disabled)
			assert.Equal(t, tt.createdAt.UTC().Format(time.RFC3339), result.CreatedAt)
			assert.Equal(t, tt.updatedAt.UTC().Format(time.RFC3339), result.UpdatedAt)

			if tt.expectedLastLogin != nil {
				assert.NotNil(t, result.LastLogin)
				assert.Equal(t, *tt.expectedLastLogin, *result.LastLogin)
			} else {
				assert.Nil(t, result.LastLogin)
			}
		})
	}
}

func TestNewLoginResponse(t *testing.T) {
	user := UserResponse{
		ID:       "user1",
		Username: "testuser",
		Email:    "test@example.com",
		FullName: "Test User",
		Roles:    []string{"admin"},
	}

	tests := []struct {
		name         string
		accessToken  string
		refreshToken string
		expiresIn    int
		user         UserResponse
	}{
		{
			name:         "complete login response",
			accessToken:  "access_token_123",
			refreshToken: "refresh_token_456",
			expiresIn:    3600,
			user:         user,
		},
		{
			name:         "login response without refresh token",
			accessToken:  "access_token_789",
			refreshToken: "",
			expiresIn:    1800,
			user:         user,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewLoginResponse(tt.accessToken, tt.refreshToken, tt.expiresIn, tt.user)

			assert.Equal(t, tt.accessToken, result.AccessToken)
			assert.Equal(t, tt.refreshToken, result.RefreshToken)
			assert.Equal(t, "Bearer", result.TokenType)
			assert.Equal(t, tt.expiresIn, result.ExpiresIn)
			assert.Equal(t, tt.user, result.User)
		})
	}
}

func TestNewUserListResponse(t *testing.T) {
	users := []UserResponse{
		{
			ID:       "user1",
			Username: "testuser1",
			Email:    "test1@example.com",
		},
		{
			ID:       "user2",
			Username: "testuser2",
			Email:    "test2@example.com",
		},
	}

	tests := []struct {
		name          string
		users         []UserResponse
		total         int
		page          int
		limit         int
		expectedUsers int
	}{
		{
			name:          "standard user list",
			users:         users,
			total:         10,
			page:          1,
			limit:         5,
			expectedUsers: 2,
		},
		{
			name:          "empty user list",
			users:         []UserResponse{},
			total:         0,
			page:          1,
			limit:         10,
			expectedUsers: 0,
		},
		{
			name:          "single user list",
			users:         users[:1],
			total:         1,
			page:          1,
			limit:         10,
			expectedUsers: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewUserListResponse(tt.users, tt.total, tt.page, tt.limit)

			assert.Equal(t, tt.expectedUsers, len(result.Users))
			assert.Equal(t, tt.total, result.Total)
			assert.Equal(t, tt.page, result.Page)
			assert.Equal(t, tt.limit, result.Limit)
			assert.Equal(t, tt.users, result.Users)
		})
	}
}

func TestUserResponseStructValidation(t *testing.T) {
	// Test that UserResponse struct can be properly marshaled/unmarshaled
	original := UserResponse{
		ID:        "user1",
		Username:  "testuser",
		Email:     "test@example.com",
		FullName:  "Test User",
		Roles:     []string{"admin", "viewer"},
		Disabled:  false,
		CreatedAt: "2023-12-01T10:30:00Z",
		UpdatedAt: "2023-12-01T10:30:00Z",
		LastLogin: stringPtr("2023-12-01T09:30:00Z"),
		Metadata:  map[string]string{"source": "test"},
	}

	// Test all required fields are present
	assert.Equal(t, "user1", original.ID)
	assert.Equal(t, "testuser", original.Username)
	assert.Equal(t, "test@example.com", original.Email)
	assert.Equal(t, "Test User", original.FullName)
	assert.Equal(t, []string{"admin", "viewer"}, original.Roles)
	assert.Equal(t, false, original.Disabled)
	assert.Equal(t, "2023-12-01T10:30:00Z", original.CreatedAt)
	assert.Equal(t, "2023-12-01T10:30:00Z", original.UpdatedAt)
	assert.NotNil(t, original.LastLogin)
	assert.Equal(t, "2023-12-01T09:30:00Z", *original.LastLogin)
	assert.Equal(t, map[string]string{"source": "test"}, original.Metadata)
}

func TestRequestValidation(t *testing.T) {
	// Test CreateUserRequest validation
	t.Run("CreateUserRequest validation", func(t *testing.T) {
		validRequest := CreateUserRequest{
			Username: "validuser",
			Email:    "valid@example.com",
			Password: "validpassword123",
			FullName: "Valid User",
			Roles:    []string{"viewer"},
			Disabled: false,
		}

		assert.Equal(t, "validuser", validRequest.Username)
		assert.Equal(t, "valid@example.com", validRequest.Email)
		assert.Equal(t, "validpassword123", validRequest.Password)
		assert.Equal(t, "Valid User", validRequest.FullName)
		assert.Equal(t, []string{"viewer"}, validRequest.Roles)
		assert.Equal(t, false, validRequest.Disabled)
	})

	// Test UpdateUserRequest validation
	t.Run("UpdateUserRequest validation", func(t *testing.T) {
		validRequest := UpdateUserRequest{
			Email:    "newemail@example.com",
			FullName: "New Name",
			Roles:    []string{"admin"},
			Disabled: boolPtr(true),
		}

		assert.Equal(t, "newemail@example.com", validRequest.Email)
		assert.Equal(t, "New Name", validRequest.FullName)
		assert.Equal(t, []string{"admin"}, validRequest.Roles)
		assert.NotNil(t, validRequest.Disabled)
		assert.Equal(t, true, *validRequest.Disabled)
	})

	// Test ChangePasswordRequest validation
	t.Run("ChangePasswordRequest validation", func(t *testing.T) {
		validRequest := ChangePasswordRequest{
			CurrentPassword: "currentpass123",
			NewPassword:     "newpass456",
		}

		assert.Equal(t, "currentpass123", validRequest.CurrentPassword)
		assert.Equal(t, "newpass456", validRequest.NewPassword)
	})
}

// Helper functions for tests
func boolPtr(b bool) *bool {
	return &b
}

func stringPtr(s string) *string {
	return &s
}