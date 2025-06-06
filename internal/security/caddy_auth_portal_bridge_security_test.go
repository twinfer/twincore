package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/twinfer/twincore/pkg/types"
)

func TestCaddyAuthPortalBridge_TokenSecretGeneration(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	// Create test database
	db, securityRepo := setupTestDB(t)
	defer db.Close()

	mockLicenseChecker := &MockUnifiedLicenseChecker{valid: true}

	t.Run("Environment Variable Secret", func(t *testing.T) {
		// Set environment variable
		testSecret := "env-test-secret-12345"
		os.Setenv("TWINCORE_JWT_SECRET", testSecret)
		defer os.Unsetenv("TWINCORE_JWT_SECRET")

		config := &types.SystemSecurityConfig{Enabled: true}
		bridge, err := NewCaddyAuthPortalBridge(securityRepo, logger, config, mockLicenseChecker, "/tmp/test-env")
		require.NoError(t, err)

		secret := bridge.generateTokenSecret()
		assert.Equal(t, testSecret, secret, "Should use environment variable secret")
	})

	t.Run("Persistent Secret File", func(t *testing.T) {
		// Ensure no environment variable
		os.Unsetenv("TWINCORE_JWT_SECRET")

		// Create temporary directory
		tempDir := t.TempDir()

		config := &types.SystemSecurityConfig{Enabled: true}
		bridge, err := NewCaddyAuthPortalBridge(securityRepo, logger, config, mockLicenseChecker, tempDir)
		require.NoError(t, err)

		// First call should generate and persist secret
		secret1 := bridge.generateTokenSecret()
		assert.NotEmpty(t, secret1, "Should generate non-empty secret")
		assert.Len(t, secret1, 64, "Should generate 64-character hex string")

		// Verify secret was persisted
		secretFile := filepath.Join(tempDir, "jwt_secret.key")
		assert.FileExists(t, secretFile, "Secret file should be created")

		fileContent, err := os.ReadFile(secretFile)
		require.NoError(t, err)
		assert.Equal(t, secret1, string(fileContent), "File content should match generated secret")

		// Second call should use persisted secret
		secret2 := bridge.generateTokenSecret()
		assert.Equal(t, secret1, secret2, "Should reuse persisted secret")
	})

	t.Run("Random Secret Generation", func(t *testing.T) {
		os.Unsetenv("TWINCORE_JWT_SECRET")

		config := &types.SystemSecurityConfig{Enabled: true}

		// Generate multiple secrets to ensure they're different (random)
		secrets := make(map[string]bool)
		for range 5 {
			// Create new bridge instances to simulate fresh generation
			tempDir := t.TempDir()
			newBridge, err := NewCaddyAuthPortalBridge(securityRepo, logger, config, mockLicenseChecker, tempDir)
			require.NoError(t, err)

			secret := newBridge.generateTokenSecret()
			secrets[secret] = true

			// Validate secret format
			assert.Len(t, secret, 64, "Secret should be 64 characters (hex-encoded SHA256)")
			assert.Regexp(t, "^[a-f0-9]{64}$", secret, "Secret should be lowercase hex")
		}

		// All secrets should be unique
		assert.Len(t, secrets, 5, "All generated secrets should be unique")
	})

	t.Run("Deterministic Fallback", func(t *testing.T) {
		os.Unsetenv("TWINCORE_JWT_SECRET")

		config := &types.SystemSecurityConfig{Enabled: true}
		bridge, err := NewCaddyAuthPortalBridge(securityRepo, logger, config, mockLicenseChecker, "/tmp/test-deterministic")
		require.NoError(t, err)

		// Test deterministic fallback generation
		secret1 := bridge.generateDeterministicSecret()
		secret2 := bridge.generateDeterministicSecret()

		assert.Equal(t, secret1, secret2, "Deterministic secret should be consistent")
		assert.Len(t, secret1, 64, "Deterministic secret should be 64 characters")
		assert.Regexp(t, "^[a-f0-9]{64}$", secret1, "Deterministic secret should be lowercase hex")
	})

	t.Run("Secret Security Properties", func(t *testing.T) {
		os.Unsetenv("TWINCORE_JWT_SECRET")

		config := &types.SystemSecurityConfig{Enabled: true}
		bridge, err := NewCaddyAuthPortalBridge(securityRepo, logger, config, mockLicenseChecker, t.TempDir())
		require.NoError(t, err)

		secret := bridge.generateTokenSecret()

		// Security checks
		assert.NotContains(t, secret, "placeholder", "Should not contain placeholder text")
		assert.NotContains(t, secret, "TODO", "Should not contain TODO text")
		assert.NotContains(t, secret, "twincore-jwt-secret-key-placeholder", "Should not be the old placeholder")

		// Should be strong secret
		assert.Greater(t, len(secret), 32, "Secret should be longer than 32 characters")
		assert.Equal(t, strings.ToLower(secret), secret, "Secret should be lowercase hex format")
	})
}

func TestCaddyAuthPortalBridge_SecretPersistence(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.FatalLevel)

	db, securityRepo := setupTestDB(t)
	defer db.Close()

	mockLicenseChecker := &MockUnifiedLicenseChecker{valid: true}

	t.Run("Secret File Permissions", func(t *testing.T) {
		os.Unsetenv("TWINCORE_JWT_SECRET")

		tempDir := t.TempDir()
		config := &types.SystemSecurityConfig{Enabled: true}
		bridge, err := NewCaddyAuthPortalBridge(securityRepo, logger, config, mockLicenseChecker, tempDir)
		require.NoError(t, err)

		// Generate secret to trigger file creation
		bridge.generateTokenSecret()

		// Check file permissions
		secretFile := filepath.Join(tempDir, "jwt_secret.key")
		info, err := os.Stat(secretFile)
		require.NoError(t, err)

		// File should be readable only by owner (0600)
		mode := info.Mode()
		assert.Equal(t, os.FileMode(0600), mode.Perm(), "Secret file should have 0600 permissions")
	})

	t.Run("Directory Creation", func(t *testing.T) {
		os.Unsetenv("TWINCORE_JWT_SECRET")

		// Use nested directory that doesn't exist
		tempDir := filepath.Join(t.TempDir(), "nested", "directory")
		config := &types.SystemSecurityConfig{Enabled: true}
		bridge, err := NewCaddyAuthPortalBridge(securityRepo, logger, config, mockLicenseChecker, tempDir)
		require.NoError(t, err)

		// Generate secret should create directory structure
		secret := bridge.generateTokenSecret()
		assert.NotEmpty(t, secret)

		// Verify directory was created with correct permissions
		info, err := os.Stat(tempDir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())
		assert.Equal(t, os.FileMode(0700), info.Mode().Perm(), "Data directory should have 0700 permissions")
	})
}
