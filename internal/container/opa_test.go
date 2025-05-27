package container

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

const testRegoPolicy = `
package twinedge.authz

default allow = false

allow {
    input.license.active == true
    input.license.exp >= input.current_time_unix
    contains(input.license.features, "core")
}
`

func setupTestLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(logrus.New().Out) // Avoid actual logging during tests, or use ioutil.Discard
	logger.SetLevel(logrus.ErrorLevel) // Or any level, as it's mostly for passing to the function
	return logger
}

func TestEvaluateOPAPolicy(t *testing.T) {
	logger := setupTestLogger()

	// Create a temporary rego file for tests that need to read it
	tempDir := t.TempDir()
	policyFilePath := filepath.Join(tempDir, "test_license.rego")
	if err := os.WriteFile(policyFilePath, []byte(testRegoPolicy), 0644); err != nil {
		t.Fatalf("Failed to write temporary rego policy file: %v", err)
	}
	
	policyBytes, err := os.ReadFile(policyFilePath)
	if err != nil {
		t.Fatalf("Failed to read temporary rego policy file for setup: %v", err)
	}
	validPolicyContent := string(policyBytes)


	tests := []struct {
		name              string
		licenseClaims     map[string]interface{}
		regoPolicyContent string // Pass content directly
		wantErr           bool
		errContains       string // Substring to check in error message
	}{
		{
			name: "valid license - active, future expiry, core feature",
			licenseClaims: map[string]interface{}{
				"active":   true,
				"exp":      time.Now().Add(24 * time.Hour).Unix(),
				"features": []string{"core", "streaming"},
			},
			regoPolicyContent: validPolicyContent,
			wantErr:           false,
		},
		{
			name: "invalid license - not active",
			licenseClaims: map[string]interface{}{
				"active":   false,
				"exp":      time.Now().Add(24 * time.Hour).Unix(),
				"features": []string{"core"},
			},
			regoPolicyContent: validPolicyContent,
			wantErr:           true,
			errContains:       "license is not valid per OPA policy",
		},
		{
			name: "invalid license - expired",
			licenseClaims: map[string]interface{}{
				"active":   true,
				"exp":      time.Now().Add(-24 * time.Hour).Unix(),
				"features": []string{"core"},
			},
			regoPolicyContent: validPolicyContent,
			wantErr:           true,
			errContains:       "license is not valid per OPA policy",
		},
		{
			name: "invalid license - missing core feature",
			licenseClaims: map[string]interface{}{
				"active":   true,
				"exp":      time.Now().Add(24 * time.Hour).Unix(),
				"features": []string{"streaming"}, // "core" feature is missing
			},
			regoPolicyContent: validPolicyContent,
			wantErr:           true,
			errContains:       "license is not valid per OPA policy",
		},
		{
			name: "malformed policy content - parse error",
			licenseClaims: map[string]interface{}{
				"active": true, "exp": time.Now().Add(24 * time.Hour).Unix(), "features": []string{"core"},
			},
			regoPolicyContent: "package invalid\n\ndefault allow = wrong", // Malformed
			wantErr:           true,
			errContains:       "failed to prepare OPA query", // Error comes from rego.New(...).PrepareForEval
		},
		{
			name: "input claims missing 'active' field",
			licenseClaims: map[string]interface{}{
				// "active" is missing
				"exp":      time.Now().Add(24 * time.Hour).Unix(),
				"features": []string{"core"},
			},
			regoPolicyContent: validPolicyContent,
			wantErr:           true, // OPA policy evaluation will result in 'false' due to undefined field access
			errContains:       "license is not valid per OPA policy",
		},
		{
			name: "input claims missing 'exp' field",
			licenseClaims: map[string]interface{}{
				"active":   true,
				// "exp" is missing
				"features": []string{"core"},
			},
			regoPolicyContent: validPolicyContent,
			wantErr:           true,
			errContains:       "license is not valid per OPA policy",
		},
		{
			name: "input claims missing 'features' field",
			licenseClaims: map[string]interface{}{
				"active":   true,
				"exp":      time.Now().Add(24 * time.Hour).Unix(),
				// "features" is missing
			},
			regoPolicyContent: validPolicyContent,
			wantErr:           true,
			errContains:       "license is not valid per OPA policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := evaluateOPAPolicy(logger, tt.licenseClaims, tt.regoPolicyContent)
			if (err != nil) != tt.wantErr {
				t.Errorf("evaluateOPAPolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errContains != "" {
				if !contains(err.Error(), tt.errContains) {
					t.Errorf("evaluateOPAPolicy() error = %q, want error containing %q", err.Error(), tt.errContains)
				}
			}
		})
	}
}

// Helper to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[0:len(substr)] == substr || len(s) > len(substr) && contains(s[1:], substr)
}
