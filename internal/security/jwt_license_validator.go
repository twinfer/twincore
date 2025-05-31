package security

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/sirupsen/logrus"
)

// JWTLicenseClaims defines the structure for JWT-based licenses that work with OPA
type JWTLicenseClaims struct {
	jwt.RegisteredClaims
	Features map[string]interface{} `json:"features"`
	Customer map[string]string      `json:"customer,omitempty"`
}

// JWTLicenseValidator validates JWT licenses and integrates with OPA
type JWTLicenseValidator struct {
	publicKey      *rsa.PublicKey
	licenseChecker *LicenseCheckerOPA
	logger         logrus.FieldLogger
}

// NewJWTLicenseValidator creates a new JWT license validator
func NewJWTLicenseValidator(publicKeyPath, policyDir string, logger logrus.FieldLogger) (*JWTLicenseValidator, error) {
	// Load public key for JWT verification
	keyData, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return &JWTLicenseValidator{
		publicKey: publicKey,
		logger:    logger,
	}, nil
}

// ValidateAndLoad validates a JWT license file and loads it into OPA
func (v *JWTLicenseValidator) ValidateAndLoad(licenseFile, policyDir string) (*LicenseCheckerOPA, error) {
	// Read license file
	tokenString, err := os.ReadFile(licenseFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read license file: %w", err)
	}

	// Parse and validate JWT
	token, err := jwt.ParseWithClaims(string(tokenString), &JWTLicenseClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return v.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	claims, ok := token.Claims.(*JWTLicenseClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Check expiration
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("license expired at %v", claims.ExpiresAt)
	}

	// Convert claims to format expected by OPA
	jwtData := map[string]interface{}{
		"iss":      claims.Issuer,
		"sub":      claims.Subject,
		"exp":      claims.ExpiresAt.Unix(),
		"iat":      claims.IssuedAt.Unix(),
		"features": claims.Features,
		"customer": claims.Customer,
	}

	// Create temporary file with validated JWT data for OPA
	tmpFile, err := os.CreateTemp("", "validated-license-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	jsonData, err := json.Marshal(jwtData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWT data: %w", err)
	}

	if err := os.WriteFile(tmpFile.Name(), jsonData, 0600); err != nil {
		return nil, fmt.Errorf("failed to write temp file: %w", err)
	}

	// Create OPA license checker with validated data
	checker, err := NewLicenseCheckerOPA(policyDir, tmpFile.Name(), v.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create OPA checker: %w", err)
	}

	v.licenseChecker = checker
	v.logger.Info("JWT license validated and loaded successfully")

	return checker, nil
}

// GetLicenseInfo returns information about the current license
func (v *JWTLicenseValidator) GetLicenseInfo(licenseFile string) (map[string]interface{}, error) {
	tokenString, err := os.ReadFile(licenseFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read license file: %w", err)
	}

	token, err := jwt.ParseWithClaims(string(tokenString), &JWTLicenseClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return v.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	claims, ok := token.Claims.(*JWTLicenseClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	info := map[string]interface{}{
		"valid":      token.Valid,
		"issuer":     claims.Issuer,
		"subject":    claims.Subject,
		"expires_at": claims.ExpiresAt,
		"issued_at":  claims.IssuedAt,
		"features":   claims.Features,
		"customer":   claims.Customer,
	}

	return info, nil
}

// CreateSignedLicense creates a new signed JWT license (for testing/development)
func CreateSignedLicense(privateKeyPath string, claims *JWTLicenseClaims) (string, error) {
	keyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read private key: %w", err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	// Set standard claims if not set
	if claims.IssuedAt == nil {
		now := time.Now()
		claims.IssuedAt = jwt.NewNumericDate(now)
	}
	if claims.Issuer == "" {
		claims.Issuer = "twincore-licensing"
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}
