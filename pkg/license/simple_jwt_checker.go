package license

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

// SimpleLicenseChecker validates JWT licenses without OPA complexity
type SimpleLicenseChecker struct {
	features   LicenseFeatures
	publicKey  *rsa.PublicKey
	logger     logrus.FieldLogger
	hasLicense bool
}

// LicenseFeatures defines what's allowed in the license
type LicenseFeatures struct {
	// Protocol bindings
	Bindings []string `json:"bindings"` // ["http", "kafka", "mqtt"]

	// Benthos processors
	Processors []string `json:"processors"` // ["json", "parquet_encode", "mapping"]

	// Security methods
	Security []string `json:"security"` // ["basic_auth", "jwt", "oauth2"]

	// Storage backends
	Storage []string `json:"storage"` // ["parquet", "postgres", "s3"]

	// Resource limits
	MaxThings  int `json:"max_things"`
	MaxStreams int `json:"max_streams"`
	MaxUsers   int `json:"max_users"`

	// Boolean capabilities
	MultiTenancy bool `json:"multi_tenancy"`
	AuditLogging bool `json:"audit_logging"`
}

// JWT Claims structure
type LicenseClaims struct {
	Features LicenseFeatures `json:"features"`
	jwt.RegisteredClaims
}

// DefaultFeatures provides basic functionality without license
func DefaultFeatures() LicenseFeatures {
	return LicenseFeatures{
		Bindings:     []string{"http", "mqtt"},
		Processors:   []string{"json", "mapping"},
		Security:     []string{"basic_auth"},
		Storage:      []string{},
		MaxThings:    10,
		MaxStreams:   5,
		MaxUsers:     2,
		MultiTenancy: false,
		AuditLogging: false,
	}
}

// NewSimpleLicenseChecker creates JWT-based license checker
func NewSimpleLicenseChecker(licenseFile string, publicKeyBytes []byte, logger logrus.FieldLogger) (*SimpleLicenseChecker, error) {
	// Parse public key from bytes
	publicKey, err := parsePublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	checker := &SimpleLicenseChecker{
		features:   DefaultFeatures(), // Start with defaults
		publicKey:  publicKey,
		logger:     logger,
		hasLicense: false,
	}

	if licenseFile == "" {
		logger.Info("No license file provided, using default features")
		return checker, nil
	}

	// Read and validate JWT
	tokenString, err := os.ReadFile(licenseFile)
	if err != nil {
		logger.WithError(err).Warn("Failed to read license file, using defaults")
		return checker, nil
	}

	// Parse JWT
	token, err := jwt.ParseWithClaims(string(tokenString), &LicenseClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		logger.WithError(err).Warn("Invalid license JWT, using defaults")
		return checker, nil
	}

	if claims, ok := token.Claims.(*LicenseClaims); ok && token.Valid {
		checker.features = claims.Features
		checker.hasLicense = true
		logger.WithFields(logrus.Fields{
			"bindings":   len(claims.Features.Bindings),
			"max_things": claims.Features.MaxThings,
			"expires":    claims.ExpiresAt,
		}).Info("License loaded successfully")
	} else {
		logger.Warn("Invalid license claims, using defaults")
	}

	return checker, nil
}

// Feature checking methods

func (l *SimpleLicenseChecker) IsFeatureEnabled(category, feature string) (bool, error) {
	switch category {
	case "bindings":
		return l.contains(l.features.Bindings, feature), nil
	case "processors":
		return l.contains(l.features.Processors, feature), nil
	case "security":
		return l.contains(l.features.Security, feature), nil
	case "storage":
		return l.contains(l.features.Storage, feature), nil
	default:
		return false, fmt.Errorf("unknown feature category: %s", category)
	}
}

// Simplified interface for binding generator
func (l *SimpleLicenseChecker) IsFeatureAvailable(feature string) bool {
	// Map feature names to categories for backward compatibility
	categoryMap := map[string]string{
		"parquet_logging":    "storage",
		"property_streaming": "bindings",
		"property_commands":  "bindings",
		"action_invocation":  "processors",
		"event_processing":   "processors",
		"http_binding":       "bindings",
		"kafka_binding":      "bindings",
		"mqtt_binding":       "bindings",
	}

	featureMap := map[string]string{
		"parquet_logging":    "parquet",
		"property_streaming": "kafka",
		"property_commands":  "http",
		"action_invocation":  "mapping",
		"event_processing":   "json",
		"http_binding":       "http",
		"kafka_binding":      "kafka",
		"mqtt_binding":       "mqtt",
	}

	category := categoryMap[feature]
	actualFeature := featureMap[feature]

	if category == "" || actualFeature == "" {
		return false // Unknown feature, deny by default
	}

	enabled, _ := l.IsFeatureEnabled(category, actualFeature)
	return enabled
}

func (l *SimpleLicenseChecker) GetFeatureConfig(feature string) map[string]interface{} {
	return map[string]interface{}{
		"enabled": l.IsFeatureAvailable(feature),
	}
}

// Resource limit checking

func (l *SimpleLicenseChecker) CheckLimit(resource string, currentCount int) (bool, error) {
	switch resource {
	case "things":
		return currentCount <= l.features.MaxThings, nil
	case "streams":
		return currentCount <= l.features.MaxStreams, nil
	case "users":
		return currentCount <= l.features.MaxUsers, nil
	default:
		return false, fmt.Errorf("unknown resource: %s", resource)
	}
}

func (l *SimpleLicenseChecker) GetLimit(resource string) int {
	switch resource {
	case "things":
		return l.features.MaxThings
	case "streams":
		return l.features.MaxStreams
	case "users":
		return l.features.MaxUsers
	default:
		return 0
	}
}

// Capability checking

func (l *SimpleLicenseChecker) IsCapabilityEnabled(capability string) bool {
	switch capability {
	case "multi_tenancy":
		return l.features.MultiTenancy
	case "audit_logging":
		return l.features.AuditLogging
	default:
		return false
	}
}

// Get all allowed features

func (l *SimpleLicenseChecker) GetAllowedFeatures() (map[string]interface{}, error) {
	return map[string]interface{}{
		"bindings":   l.features.Bindings,
		"processors": l.features.Processors,
		"security":   l.features.Security,
		"storage":    l.features.Storage,
		"capabilities": map[string]interface{}{
			"max_things":    l.features.MaxThings,
			"max_streams":   l.features.MaxStreams,
			"max_users":     l.features.MaxUsers,
			"multi_tenancy": l.features.MultiTenancy,
			"audit_logging": l.features.AuditLogging,
		},
		"has_license": l.hasLicense,
	}, nil
}

// Helper methods

func (l *SimpleLicenseChecker) contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Generate example license for testing
func GenerateExampleLicense() LicenseFeatures {
	return LicenseFeatures{
		Bindings:     []string{"http", "kafka", "mqtt"},
		Processors:   []string{"json", "parquet_encode", "mapping", "json_schema"},
		Security:     []string{"basic_auth", "jwt", "oauth2"},
		Storage:      []string{"parquet", "postgres"},
		MaxThings:    1000,
		MaxStreams:   100,
		MaxUsers:     50,
		MultiTenancy: true,
		AuditLogging: true,
	}
}

// parsePublicKey parses RSA public key from PEM bytes
func parsePublicKey(publicKeyBytes []byte) (*rsa.PublicKey, error) {
	if len(publicKeyBytes) == 0 {
		return nil, fmt.Errorf("public key bytes are empty")
	}

	// Parse PEM block
	block, _ := pem.Decode(publicKeyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing public key")
	}

	// Parse public key
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Convert to RSA public key
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA key")
	}

	return rsaPubKey, nil
}

// Ensure SimpleLicenseChecker implements LicenseChecker interface
var _ LicenseChecker = (*SimpleLicenseChecker)(nil)
