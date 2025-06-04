// internal/security/license.go
package security

import (
	"crypto/rsa"
	"fmt"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/twinfer/twincore/pkg/types"
	"slices"
)

// LicenseClaims defines the structure of custom claims in the JWT license.
type LicenseClaims struct {
	jwt.RegisteredClaims
	DeviceID string   `json:"did,omitempty"`
	Features []string `json:"feat,omitempty"`
	Tier     string   `json:"tier,omitempty"`
	// Add other custom claims as needed
}

// License represents the parsed and validated license.
type License struct {
	Raw      string
	Claims   *LicenseClaims
	Valid    bool
	Expiry   time.Time
	IssuedAt time.Time
	DeviceID string
	Features []string // This field will be used by IsFeatureEnabled
	Tier     string
}

// IsFeatureEnabled checks if a specific feature is enabled in the license.
// This method makes *License implement the types.License interface.
func (l *License) IsFeatureEnabled(feature string) bool {
	if l == nil || !l.Valid {
		return false
	}
	return slices.Contains(l.Features, feature)
}

// LicenseManager handles license validation and parsing.
type LicenseManager struct {
	publicKey *rsa.PublicKey
}

// NewLicenseManager creates a new LicenseManager.
func NewLicenseManager(pubKeyData []byte) (*LicenseManager, error) {
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(pubKeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
	}
	return &LicenseManager{publicKey: publicKey}, nil
}

// ParseAndValidate parses a license token string and validates it.
func (lm *LicenseManager) ParseAndValidate(tokenString string) (types.License, error) {
	claims := &LicenseClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return lm.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse or validate token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("license token is invalid")
	}

	lic := &License{
		Raw:      tokenString,
		Claims:   claims,
		Valid:    token.Valid,
		Features: claims.Features,
		Tier:     claims.Tier,
		DeviceID: claims.DeviceID,
	}
	if claims.ExpiresAt != nil {
		lic.Expiry = claims.ExpiresAt.Time
	}
	if claims.IssuedAt != nil {
		lic.IssuedAt = claims.IssuedAt.Time
	}

	if lic.Expiry.Before(time.Now()) {
		lic.Valid = false
		return lic, fmt.Errorf("license has expired on %s", lic.Expiry.Format(time.RFC3339))
	}

	return lic, nil
}

// Interface guard to ensure *LicenseManager implements types.LicenseManager
var _ types.LicenseManager = (*LicenseManager)(nil)
