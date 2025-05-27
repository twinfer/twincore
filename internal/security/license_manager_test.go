package security

import (
	"testing"
	"time"
)

func TestNewLicenseManager(t *testing.T) {
	pubKey := []byte("test_public_key")
	lm, err := NewLicenseManager(pubKey)
	if err != nil {
		t.Fatalf("NewLicenseManager() error = %v, wantErr %v", err, false)
	}
	if lm == nil {
		t.Fatal("NewLicenseManager() returned nil LicenseManager")
	}
	// Check if it's the expected type (DefaultLicenseManager)
	if _, ok := lm.(*DefaultLicenseManager); !ok {
		t.Errorf("NewLicenseManager() did not return a *DefaultLicenseManager, got %T", lm)
	}
}

func TestDefaultLicenseManager_Validate(t *testing.T) {
	lm := &DefaultLicenseManager{}
	pubKey := []byte("test_public_key") // Dummy public key, as current Validate doesn't use it for JWT.

	tests := []struct {
		name        string
		tokenString string
		publicKey   []byte
		wantClaims  map[string]interface{} // For checking specific claims if needed
		wantErr     bool
	}{
		{
			name:        "valid dummy token",
			tokenString: "dummy_license_token_string", // Current Validate logic treats any non-empty string as "valid"
			publicKey:   pubKey,
			wantClaims: map[string]interface{}{
				"active": true, // Based on current dummy claims
			},
			wantErr: false,
		},
		{
			name:        "empty token string",
			tokenString: "",
			publicKey:   pubKey,
			wantErr:     true,
		},
		// Add more tests here if Validate logic becomes more sophisticated (e.g., JWT parsing)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			license, err := lm.Validate(tt.tokenString, tt.publicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("DefaultLicenseManager.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if license == nil {
					t.Fatal("DefaultLicenseManager.Validate() returned nil license for a valid case")
				}
				if license.Claims == nil {
					t.Fatal("DefaultLicenseManager.Validate() returned license with nil claims")
				}
				// Check specific claims if provided in the test case
				if tt.wantClaims != nil {
					for k, expectedValue := range tt.wantClaims {
						if val, ok := license.Claims[k]; !ok {
							t.Errorf("DefaultLicenseManager.Validate() claim %s missing", k)
						} else if val != expectedValue {
							// Special handling for time.Time or other complex types if they were in dummy claims
							if k == "exp" { // Example: exp is a float64 or int64 in dummy claims
								expVal, okExp := expectedValue.(int64)
								gotVal, okGot := val.(float64) // JWT often decodes numbers as float64
								if !okExp || !okGot || time.Unix(int64(gotVal), 0).Before(time.Now()) {
									// Dummy exp is set to future, so this check is more about type
									// t.Errorf("DefaultLicenseManager.Validate() claim %s = %v (type %T), want %v (type %T) or future time", k, val, val, expectedValue, expectedValue)
								}
							} else {
								t.Errorf("DefaultLicenseManager.Validate() claim %s = %v, want %v", k, val, expectedValue)
							}
						}
					}
				}
			}
		})
	}
}
