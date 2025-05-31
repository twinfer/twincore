//go:build !integration
// +build !integration

package security

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestOPALicenseCheckerSimple(t *testing.T) {
	// Create a temporary directory for test policies
	tmpDir := t.TempDir()

	// Write test policies
	featuresPolicy := `package twincore.features

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
}`

	limitsPolicy := `package twincore.limits

import data.twincore.features.allowed_features
import future.keywords.if

within_limit(resource, count) if {
    allowed_features.capabilities[resource] >= count
}`

	securityPolicy := `package twincore.security

import data.twincore.features.allowed_features
import future.keywords.if
import future.keywords.in

allowed_auth_methods := methods if {
    methods := allowed_features.security
} else := ["basic_auth"]`

	// Write policy files
	os.WriteFile(filepath.Join(tmpDir, "features.rego"), []byte(featuresPolicy), 0644)
	os.WriteFile(filepath.Join(tmpDir, "limits.rego"), []byte(limitsPolicy), 0644)
	os.WriteFile(filepath.Join(tmpDir, "security.rego"), []byte(securityPolicy), 0644)

	logger := logrus.New()

	t.Run("NoLicense", func(t *testing.T) {
		checker, err := NewLicenseCheckerOPA(tmpDir, "", logger)
		if err != nil {
			t.Fatalf("Failed to create checker: %v", err)
		}

		// Should not have license
		if checker.HasLicense() {
			t.Error("Expected no license")
		}

		// Check default features
		enabled, err := checker.IsFeatureEnabled("bindings", "http")
		if err != nil {
			t.Fatalf("Failed to check feature: %v", err)
		}
		if !enabled {
			t.Error("Expected http binding to be enabled by default")
		}

		// Kafka should not be enabled
		enabled, err = checker.IsFeatureEnabled("bindings", "kafka")
		if err != nil {
			t.Fatalf("Failed to check feature: %v", err)
		}
		if enabled {
			t.Error("Expected kafka binding to be disabled by default")
		}
	})

	t.Run("WithLicense", func(t *testing.T) {
		// Create test license
		license := map[string]interface{}{
			"features": map[string]interface{}{
				"bindings":   []string{"http", "mqtt", "kafka"},
				"processors": []string{"json", "mapping", "parquet_encode"},
				"security":   []string{"basic_auth", "jwt"},
				"storage":    []string{"parquet_logging"},
				"capabilities": map[string]interface{}{
					"max_things":  1000,
					"max_streams": 100,
				},
			},
		}

		licenseFile := filepath.Join(tmpDir, "license.jwt")
		data, _ := json.Marshal(license)
		os.WriteFile(licenseFile, data, 0644)

		checker, err := NewLicenseCheckerOPA(tmpDir, licenseFile, logger)
		if err != nil {
			t.Fatalf("Failed to create checker: %v", err)
		}

		// Should have license
		if !checker.HasLicense() {
			t.Error("Expected to have license")
		}

		// Check licensed feature
		enabled, err := checker.IsFeatureEnabled("bindings", "kafka")
		if err != nil {
			t.Fatalf("Failed to check feature: %v", err)
		}
		if !enabled {
			t.Error("Expected kafka binding to be enabled with license")
		}

		// Check limits
		withinLimit, err := checker.CheckLimit("max_things", 500)
		if err != nil {
			t.Fatalf("Failed to check limit: %v", err)
		}
		if !withinLimit {
			t.Error("Expected 500 to be within limit of 1000")
		}
	})
}
