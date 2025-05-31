package security

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestPolicies(t *testing.T) string {
	tmpDir, err := os.MkdirTemp("", "opa-policies-test")
	require.NoError(t, err)

	// Write test policies
	policies := map[string]string{
		"features.rego": `package twincore.features

import future.keywords.if
import future.keywords.in

default_features := {
    "bindings": ["http", "mqtt"],
    "processors": ["json", "mapping"],
    "security": ["basic_auth"],
    "storage": [],
    "capabilities": {
        "max_things": 10,
        "max_streams": 5,
        "max_users": 2,
        "multi_tenancy": false,
        "audit_logging": false
    }
}

allowed_features := features if {
    input.jwt
    input.jwt.features
    features := input.jwt.features
} else := default_features

feature_allowed(category, feature) if {
    feature in allowed_features[category]
}`,
		"limits.rego": `package twincore.limits

import data.twincore.features.allowed_features
import future.keywords.if

within_limit(resource, count) if {
    allowed_features.capabilities[resource] >= count
}

rate_limit_for_endpoint(endpoint) := limit if {
    endpoint == "/api/things"
    limit := allowed_features.capabilities.max_things * 10 / 3600
} else := 100`,
		"security.rego": `package twincore.security

import data.twincore.features.allowed_features
import future.keywords.if
import future.keywords.in

allowed_auth_methods := methods if {
    methods := allowed_features.security
} else := ["basic_auth"]`,
	}

	for name, content := range policies {
		err := os.WriteFile(filepath.Join(tmpDir, name), []byte(content), 0644)
		require.NoError(t, err)
	}

	return tmpDir
}

func setupTestLicense(t *testing.T) string {
	license := map[string]interface{}{
		"iss": "twincore-licensing",
		"sub": "test-customer",
		"exp": 1893456000, // Far future
		"features": map[string]interface{}{
			"bindings":   []string{"http", "mqtt", "kafka"},
			"processors": []string{"json", "mapping", "parquet_encode"},
			"security":   []string{"basic_auth", "jwt", "mtls"},
			"storage":    []string{"parquet_logging", "duckdb_persistence"},
			"capabilities": map[string]interface{}{
				"max_things":    1000,
				"max_streams":   100,
				"max_users":     50,
				"multi_tenancy": true,
				"audit_logging": true,
			},
		},
	}

	tmpFile, err := os.CreateTemp("", "license-*.jwt")
	require.NoError(t, err)

	data, err := json.Marshal(license)
	require.NoError(t, err)

	err = os.WriteFile(tmpFile.Name(), data, 0644)
	require.NoError(t, err)

	return tmpFile.Name()
}

func TestLicenseCheckerOPA_NoLicense(t *testing.T) {
	policyDir := setupTestPolicies(t)
	defer os.RemoveAll(policyDir)

	logger := logrus.New()
	checker, err := NewLicenseCheckerOPA(policyDir, "", logger)
	require.NoError(t, err)

	// Should use default features
	assert.False(t, checker.HasLicense())

	// Check default features
	enabled, err := checker.IsFeatureEnabled("bindings", "http")
	assert.NoError(t, err)
	assert.True(t, enabled)

	enabled, err = checker.IsFeatureEnabled("bindings", "kafka")
	assert.NoError(t, err)
	assert.False(t, enabled)

	// Check default limits
	withinLimit, err := checker.CheckLimit("max_things", 5)
	assert.NoError(t, err)
	assert.True(t, withinLimit)

	withinLimit, err = checker.CheckLimit("max_things", 15)
	assert.NoError(t, err)
	assert.False(t, withinLimit)
}

func TestLicenseCheckerOPA_WithLicense(t *testing.T) {
	policyDir := setupTestPolicies(t)
	defer os.RemoveAll(policyDir)

	licenseFile := setupTestLicense(t)
	defer os.Remove(licenseFile)

	logger := logrus.New()
	checker, err := NewLicenseCheckerOPA(policyDir, licenseFile, logger)
	require.NoError(t, err)

	// Should have license
	assert.True(t, checker.HasLicense())

	// Check licensed features
	enabled, err := checker.IsFeatureEnabled("bindings", "kafka")
	assert.NoError(t, err)
	assert.True(t, enabled)

	enabled, err = checker.IsFeatureEnabled("processors", "parquet_encode")
	assert.NoError(t, err)
	assert.True(t, enabled)

	enabled, err = checker.IsFeatureEnabled("security", "mtls")
	assert.NoError(t, err)
	assert.True(t, enabled)

	// Check licensed limits
	withinLimit, err := checker.CheckLimit("max_things", 500)
	assert.NoError(t, err)
	assert.True(t, withinLimit)

	withinLimit, err = checker.CheckLimit("max_things", 1500)
	assert.NoError(t, err)
	assert.False(t, withinLimit)
}

func TestLicenseCheckerOPA_GetAllowedFeatures(t *testing.T) {
	policyDir := setupTestPolicies(t)
	defer os.RemoveAll(policyDir)

	licenseFile := setupTestLicense(t)
	defer os.Remove(licenseFile)

	logger := logrus.New()
	checker, err := NewLicenseCheckerOPA(policyDir, licenseFile, logger)
	require.NoError(t, err)

	features, err := checker.GetAllowedFeatures()
	require.NoError(t, err)
	require.NotNil(t, features)

	// Verify features structure
	bindings, ok := features["bindings"].([]interface{})
	assert.True(t, ok)
	assert.Contains(t, bindings, "kafka")

	capabilities, ok := features["capabilities"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, float64(1000), capabilities["max_things"])
	assert.Equal(t, true, capabilities["multi_tenancy"])
}

func TestLicenseCheckerOPA_RateLimits(t *testing.T) {
	policyDir := setupTestPolicies(t)
	defer os.RemoveAll(policyDir)

	licenseFile := setupTestLicense(t)
	defer os.Remove(licenseFile)

	logger := logrus.New()
	checker, err := NewLicenseCheckerOPA(policyDir, licenseFile, logger)
	require.NoError(t, err)

	// Check rate limit for /api/things endpoint
	limit, err := checker.GetRateLimit("/api/things")
	assert.NoError(t, err)
	// Should be max_things * 10 / 3600 = 1000 * 10 / 3600 ≈ 2.77
	assert.Equal(t, 2, limit)

	// Check default rate limit
	limit, err = checker.GetRateLimit("/unknown/endpoint")
	assert.NoError(t, err)
	assert.Equal(t, 100, limit)
}
