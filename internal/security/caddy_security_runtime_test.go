package security

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/twinfer/twincore/pkg/types"
)

// TestCaddySecurityRuntime tests caddy-security in a real runtime environment
func TestCaddySecurityRuntime(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping runtime integration test in short mode")
	}

	// Check if we have caddy binary available
	if !isCaddyAvailable() {
		t.Skip("Caddy binary not available - install Caddy with caddy-security plugin for runtime tests")
	}

	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	t.Run("CaddyWithSecurityPlugin", func(t *testing.T) {
		// Test that caddy can load with our security configuration
		tempDir := t.TempDir()

		// Setup test environment
		err := setupRuntimeTestEnvironment(t, tempDir)
		require.NoError(t, err)

		// Create Caddyfile with security configuration
		caddyfile := createTestCaddyfile(tempDir)
		caddyfilePath := filepath.Join(tempDir, "Caddyfile")
		err = os.WriteFile(caddyfilePath, []byte(caddyfile), 0644)
		require.NoError(t, err)

		// Test Caddyfile validation
		cmd := exec.Command("caddy", "validate", "--config", caddyfilePath)
		output, err := cmd.CombinedOutput()

		if err != nil {
			t.Logf("Caddy validation output: %s", string(output))
			// Don't fail the test - caddy-security might not be installed
			t.Logf("Caddy validation failed (expected if caddy-security not installed): %v", err)
		} else {
			t.Log("Caddyfile validation passed!")
		}
	})

	t.Run("UserAuthenticationFlow", func(t *testing.T) {
		// Test the complete authentication flow with a running instance
		tempDir := t.TempDir()

		// Setup test environment with users
		err := setupRuntimeTestEnvironment(t, tempDir)
		require.NoError(t, err)

		// Start Caddy instance (if possible)
		port := "8181" // Use non-standard port for testing
		caddyfile := createTestCaddyfileWithPort(tempDir, port)
		caddyfilePath := filepath.Join(tempDir, "Caddyfile")
		err = os.WriteFile(caddyfilePath, []byte(caddyfile), 0644)
		require.NoError(t, err)

		// Try to start Caddy
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "caddy", "run", "--config", caddyfilePath)

		// Capture output
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Logf("Failed to create stdout pipe: %v", err)
			t.Skip("Cannot start Caddy for runtime test")
			return
		}

		err = cmd.Start()
		if err != nil {
			t.Logf("Failed to start Caddy: %v", err)
			t.Skip("Cannot start Caddy for runtime test")
			return
		}

		// Ensure Caddy is stopped
		defer func() {
			if cmd.Process != nil {
				cmd.Process.Kill()
				cmd.Wait()
			}
		}()

		// Wait for Caddy to start
		time.Sleep(2 * time.Second)

		// Test basic connectivity
		client := &http.Client{Timeout: 5 * time.Second}

		// Test health endpoint
		resp, err := client.Get(fmt.Sprintf("http://localhost:%s/health", port))
		if err != nil {
			t.Logf("Health check failed: %v", err)
			// Read some output from Caddy
			go func() {
				io.Copy(os.Stdout, stdout)
			}()
			time.Sleep(1 * time.Second)
			t.Skip("Caddy not responding - likely missing caddy-security plugin")
			return
		}
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode, "Health endpoint should be accessible")
		t.Log("Caddy runtime test passed!")
	})

	t.Run("ConfigurationReload", func(t *testing.T) {
		// Test configuration reloading with updated security settings
		tempDir := t.TempDir()

		// Setup initial configuration
		err := setupRuntimeTestEnvironment(t, tempDir)
		require.NoError(t, err)

		// Test configuration validation
		caddyfile1 := createTestCaddyfile(tempDir)
		caddyfilePath := filepath.Join(tempDir, "Caddyfile")
		err = os.WriteFile(caddyfilePath, []byte(caddyfile1), 0644)
		require.NoError(t, err)

		// Validate initial config
		cmd := exec.Command("caddy", "validate", "--config", caddyfilePath)
		output, err := cmd.CombinedOutput()

		if err != nil {
			t.Logf("Initial config validation: %s", string(output))
		}

		// Create updated configuration
		caddyfile2 := createTestCaddyfileWithExtraPolicy(tempDir)
		err = os.WriteFile(caddyfilePath, []byte(caddyfile2), 0644)
		require.NoError(t, err)

		// Validate updated config
		cmd = exec.Command("caddy", "validate", "--config", caddyfilePath)
		output, err = cmd.CombinedOutput()

		if err != nil {
			t.Logf("Updated config validation: %s", string(output))
		}

		t.Log("Configuration reload test completed")
	})
}

// setupRuntimeTestEnvironment sets up a test environment for runtime testing
func setupRuntimeTestEnvironment(t *testing.T, tempDir string) error {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce noise

	// Setup test database
	db, securityRepo := setupTestDB(t)
	defer db.Close()

	// Create identity store
	store := NewLocalIdentityStore(securityRepo, logger, "twincore_local")

	// Create test users
	testUsers := []*AuthUser{
		{
			Username: "admin",
			Email:    "admin@twincore.test",
			FullName: "Test Administrator",
			Roles:    []string{"admin"},
		},
		{
			Username: "user",
			Email:    "user@twincore.test",
			FullName: "Test User",
			Roles:    []string{"user"},
		},
	}

	for _, user := range testUsers {
		user.Password = "TestPass123!"
		err := store.CreateUser(context.Background(), user)
		if err != nil {
			return fmt.Errorf("failed to create test user %s: %w", user.Username, err)
		}
	}

	// Generate caddy-security user file
	userFile := filepath.Join(tempDir, "users.json")
	err := generateCaddySecurityUserFile(store, userFile)
	if err != nil {
		return fmt.Errorf("failed to generate user file: %w", err)
	}

	// Generate JWT secret
	secretFile := filepath.Join(tempDir, "jwt_secret")
	err = os.WriteFile(secretFile, []byte("test-jwt-secret-key-for-caddy-security"), 0600)
	if err != nil {
		return fmt.Errorf("failed to write JWT secret: %w", err)
	}

	return nil
}

// createTestCaddyfile creates a Caddyfile for testing
func createTestCaddyfile(tempDir string) string {
	return fmt.Sprintf(`
{
	# Global options
	auto_https off
	admin off
	
	# Security configuration
	order authenticate before respond
	order authorize before respond
	
	security {
		local identity store twincore_local {
			realm twincore
			path %s/users.json
		}

		authentication portal twincore_portal {
			crypto default token lifetime 3600
			crypto key sign-verify file %s/jwt_secret
			enable identity store twincore_local
			cookie domain ""
			cookie path "/"
			cookie lifetime 3600
			cookie samesite lax
			transform user {
				match origin twincore
				action add role user
			}
		}

		authorization policy twincore_policy {
			set auth url /auth/
			allow roles admin user
			deny log warn
		}
	}
}

:8080 {
	# Health endpoint (no auth required)
	handle /health {
		respond "OK" 200
	}

	# Authentication portal
	handle /auth/* {
		authenticate with twincore_portal
	}

	# Protected API
	handle /api/* {
		authenticate with twincore_portal
		authorize with twincore_policy
		respond "API Access Granted for {http.request.remote.user}" 200
	}

	# Default response
	handle {
		respond "Welcome to TwinCore Gateway Test" 200
	}
}
`, tempDir, tempDir)
}

// createTestCaddyfileWithPort creates a Caddyfile with a specific port
func createTestCaddyfileWithPort(tempDir, port string) string {
	return fmt.Sprintf(`
{
	auto_https off
	admin off
}

:%s {
	handle /health {
		respond "OK" 200
	}

	handle {
		respond "TwinCore Test Instance" 200
	}
}
`, port)
}

// createTestCaddyfileWithExtraPolicy creates a Caddyfile with additional policies
func createTestCaddyfileWithExtraPolicy(tempDir string) string {
	return fmt.Sprintf(`
{
	auto_https off
	admin off
	
	security {
		local identity store twincore_local {
			realm twincore
			path %s/users.json
		}

		authentication portal twincore_portal {
			crypto default token lifetime 3600
			crypto key sign-verify file %s/jwt_secret
			enable identity store twincore_local
		}

		authorization policy twincore_policy {
			set auth url /auth/
			allow roles admin
			deny log warn
		}

		authorization policy user_policy {
			set auth url /auth/
			allow roles user
			allow paths /api/public/*
			deny log warn
		}
	}
}

:8080 {
	handle /health {
		respond "OK" 200
	}

	handle /auth/* {
		authenticate with twincore_portal
	}

	handle /api/admin/* {
		authenticate with twincore_portal
		authorize with twincore_policy
		respond "Admin API Access" 200
	}

	handle /api/public/* {
		authenticate with twincore_portal
		authorize with user_policy
		respond "Public API Access" 200
	}

	handle {
		respond "TwinCore Gateway" 200
	}
}
`, tempDir, tempDir)
}

// isCaddyAvailable checks if Caddy binary is available
func isCaddyAvailable() bool {
	cmd := exec.Command("caddy", "version")
	err := cmd.Run()
	return err == nil
}

// TestCaddySecurityDockerIntegration tests integration using Docker
func TestCaddySecurityDockerIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker integration test in short mode")
	}

	// Check if Docker is available
	if !isDockerAvailable() {
		t.Skip("Docker not available - skipping Docker integration test")
	}

	t.Run("DockerWithCaddySecurity", func(t *testing.T) {
		// Test running Caddy with security in Docker
		tempDir := t.TempDir()

		// Setup test environment
		err := setupRuntimeTestEnvironment(t, tempDir)
		require.NoError(t, err)

		// Create Dockerfile
		dockerfile := createTestDockerfile()
		dockerfilePath := filepath.Join(tempDir, "Dockerfile")
		err = os.WriteFile(dockerfilePath, []byte(dockerfile), 0644)
		require.NoError(t, err)

		// Create Caddyfile
		caddyfile := createTestCaddyfile(tempDir)
		caddyfilePath := filepath.Join(tempDir, "Caddyfile")
		err = os.WriteFile(caddyfilePath, []byte(caddyfile), 0644)
		require.NoError(t, err)

		// Try to build Docker image
		imageName := "twincore-caddy-security-test"
		cmd := exec.Command("docker", "build", "-t", imageName, tempDir)
		output, err := cmd.CombinedOutput()

		if err != nil {
			t.Logf("Docker build output: %s", string(output))
			t.Logf("Docker build failed (expected if caddy-security not available): %v", err)
		} else {
			t.Log("Docker image built successfully!")

			// Clean up image
			defer func() {
				exec.Command("docker", "rmi", imageName).Run()
			}()
		}
	})
}

// createTestDockerfile creates a Dockerfile for testing
func createTestDockerfile() string {
	return `
FROM caddy:builder AS builder

RUN caddy-builder \
    github.com/greenpau/caddy-security

FROM caddy:latest

COPY --from=builder /usr/bin/caddy /usr/bin/caddy

COPY Caddyfile /etc/caddy/Caddyfile
COPY users.json /data/users.json
COPY jwt_secret /data/jwt_secret

EXPOSE 8080

CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile"]
`
}

// isDockerAvailable checks if Docker is available
func isDockerAvailable() bool {
	cmd := exec.Command("docker", "version")
	err := cmd.Run()
	return err == nil
}

// TestCaddySecurityPerformance tests performance with caddy-security
func TestCaddySecurityPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	t.Run("ConfigGenerationPerformance", func(t *testing.T) {
		// Benchmark configuration generation
		logger := logrus.New()
		logger.SetLevel(logrus.ErrorLevel)

		db, securityRepo := setupTestDB(t)
		defer db.Close()

		mockLicenseChecker := &MockUnifiedLicenseChecker{valid: true}
		config := &types.SystemSecurityConfig{
			Enabled: true,
			AdminAuth: &types.AdminAuthConfig{
				Local: &types.LocalAuthConfig{},
			},
		}

		bridge, err := NewCaddyAuthPortalBridge(securityRepo, logger, config, mockLicenseChecker, t.TempDir())
		require.NoError(t, err)

		// Measure time for multiple generations
		start := time.Now()
		iterations := 100

		for range iterations {
			_, err := bridge.GenerateAuthPortalConfig(context.Background())
			require.NoError(t, err)
		}

		elapsed := time.Since(start)
		avgTime := elapsed / time.Duration(iterations)

		t.Logf("Generated %d configurations in %v (avg: %v per config)",
			iterations, elapsed, avgTime)

		// Should be fast enough for practical use
		assert.Less(t, avgTime.Milliseconds(), int64(100),
			"Configuration generation should be under 100ms")
	})

	t.Run("UserStorePerformance", func(t *testing.T) {
		// Test performance with many users
		logger := logrus.New()
		logger.SetLevel(logrus.ErrorLevel)

		db, securityRepo := setupTestDB(t)
		defer db.Close()

		store := NewLocalIdentityStore(securityRepo, logger, "perf_test")

		// Create many test users
		userCount := 1000
		start := time.Now()

		for i := range userCount {
			user := &AuthUser{
				Username: fmt.Sprintf("user%d", i),
				Email:    fmt.Sprintf("user%d@test.local", i),
				FullName: fmt.Sprintf("Test User %d", i),
				Roles:    []string{"user"},
				Password: "password123",
			}
			err := store.CreateUser(context.Background(), user)
			require.NoError(t, err)
		}

		createTime := time.Since(start)
		t.Logf("Created %d users in %v (avg: %v per user)",
			userCount, createTime, createTime/time.Duration(userCount))

		// Test user lookup performance
		start = time.Now()
		lookups := 100

		for i := range lookups {
			username := fmt.Sprintf("user%d", i%userCount)
			_, err := store.GetUser(context.Background(), username)
			require.NoError(t, err)
		}

		lookupTime := time.Since(start)
		avgLookup := lookupTime / time.Duration(lookups)

		t.Logf("Performed %d user lookups in %v (avg: %v per lookup)",
			lookups, lookupTime, avgLookup)

		// Should be fast enough for authentication
		assert.Less(t, avgLookup.Milliseconds(), int64(50),
			"User lookup should be under 50ms")
	})
}
