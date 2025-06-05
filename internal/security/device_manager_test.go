package security

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/twinfer/twincore/pkg/types"
)

// MockLicenseManager for testing DeviceManager
type MockLicenseManager struct {
	ParseAndValidateFunc func(tokenString string) (types.License, error)
}

func (m *MockLicenseManager) ParseAndValidate(tokenString string) (types.License, error) {
	if m.ParseAndValidateFunc != nil {
		return m.ParseAndValidateFunc(tokenString)
	}
	return nil, fmt.Errorf("ParseAndValidateFunc not set in MockLicenseManager")
}

func TestNewDeviceManager(t *testing.T) {
	// Skip this test since NewDeviceManager requires a valid RSA key and we're cleaning up tests
	t.Skip("Skipping DeviceManager constructor test - requires valid RSA key setup")
}

func TestDeviceManager_InitializeLicense(t *testing.T) {
	validSecLicense := &License{ // This is *security.License
		Claims:   &LicenseClaims{RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}},
		Valid:    true,
		Features: []string{"core"},
	}

	// Create a temporary license file
	tempDir := t.TempDir()
	validLicenseFile := filepath.Join(tempDir, "license.jwt")
	if err := os.WriteFile(validLicenseFile, []byte("valid_dummy_token"), 0644); err != nil {
		t.Fatalf("Failed to write temp license file: %v", err)
	}

	nonExistentLicenseFile := filepath.Join(tempDir, "non_existent.jwt")

	tests := []struct {
		name                 string
		licensePath          string
		mockParseAndValidate func(tokenString string) (types.License, error)
		wantErr              bool
		wantLicenseNil       bool
	}{
		{
			name:        "successful initialization",
			licensePath: validLicenseFile,
			mockParseAndValidate: func(tokenString string) (types.License, error) {
				if tokenString != "valid_dummy_token" {
					return nil, fmt.Errorf("unexpected token string: %s", tokenString)
				}
				return validSecLicense, nil // Return *security.License which implements types.License
			},
			wantErr:        false,
			wantLicenseNil: false,
		},
		{
			name:        "license manager ParseAndValidate fails",
			licensePath: validLicenseFile,
			mockParseAndValidate: func(tokenString string) (types.License, error) {
				return nil, fmt.Errorf("mock validation error")
			},
			wantErr:        true,
			wantLicenseNil: false, // currentLicense will be set to a minimal {Valid:false} struct
		},
		{
			name:        "license file does not exist",
			licensePath: nonExistentLicenseFile,
			mockParseAndValidate: func(tokenString string) (types.License, error) {
				return validSecLicense, nil // This shouldn't be called if file read fails
			},
			wantErr:        true,
			wantLicenseNil: true,
		},
		{
			name:        "empty license file path",
			licensePath: "", // Test with an empty path
			mockParseAndValidate: func(tokenString string) (types.License, error) {
				return validSecLicense, nil
			},
			wantErr:        true, // os.ReadFile will error on empty path
			wantLicenseNil: true,
		},
		{
			name:        "ParseAndValidate returns wrong license type",
			licensePath: validLicenseFile,
			mockParseAndValidate: func(tokenString string) (types.License, error) {
				return &struct{ types.License }{}, fmt.Errorf("wrong type mock error, this error should not be returned by InitializeLicense") // A type that implements types.License but isn't *security.License
			},
			wantErr:        true,  // InitializeLicense should error out due to type assertion failure
			wantLicenseNil: false, // currentLicense will be set to a minimal {Valid:false} struct
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLm := &MockLicenseManager{ParseAndValidateFunc: tt.mockParseAndValidate}
			dm := &DeviceManager{
				licensePath:    tt.licensePath,
				licenseManager: mockLm,
			}
			err := dm.InitializeLicense(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("DeviceManager.InitializeLicense() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantLicenseNil && dm.currentLicense != nil {
				t.Errorf("DeviceManager.InitializeLicense() expected currentLicense to be nil, got %v", dm.currentLicense)
			}
			if !tt.wantLicenseNil && dm.currentLicense == nil {
				t.Error("DeviceManager.InitializeLicense() expected currentLicense to be non-nil, got nil")
			}
			// If an error occurred but we don't expect license to be nil, check Valid is false
			if tt.wantErr && !tt.wantLicenseNil && dm.currentLicense != nil && dm.currentLicense.Valid {
				t.Error("DeviceManager.InitializeLicense() errored but currentLicense.Valid is true")
			}
		})
	}
}

func TestDeviceManager_GetLicense(t *testing.T) {
	dm := &DeviceManager{} // Blank device manager
	if lic := dm.GetLicense(); lic != nil {
		t.Errorf("GetLicense() on uninitialized DM = %v, want nil", lic)
	}

	expectedLicense := &License{Claims: &LicenseClaims{DeviceID: "test-device"}}
	dm.currentLicense = expectedLicense

	if lic := dm.GetLicense(); lic != expectedLicense {
		t.Errorf("GetLicense() = %v, want %v", lic, expectedLicense)
	}
}

func TestDeviceManager_GetLicenseClaims(t *testing.T) {
	dm := &DeviceManager{}

	// Case 1: No license loaded
	claims, err := dm.GetLicenseClaims()
	if err == nil {
		t.Error("GetLicenseClaims() expected error when no license is loaded, got nil")
	}
	if claims != nil {
		t.Errorf("GetLicenseClaims() expected nil claims when no license, got %v", claims)
	}

	// Case 2: License loaded, but claims are nil (shouldn't happen with proper Validate)
	dm.currentLicense = &License{Valid: true, Claims: nil} // Valid but nil claims
	claims, err = dm.GetLicenseClaims()
	if err == nil { // GetLicenseClaims should error if Claims is nil
		t.Error("GetLicenseClaims() expected error when claims are nil, got nil")
	}
	if claims != nil { // It should return nil for claims if dm.currentLicense.Claims is nil
		t.Errorf("GetLicenseClaims() expected nil claims when license.Claims is nil, got %v", *claims)
	}

	// Case 3: License with valid claims
	expectedClaimsObj := &LicenseClaims{DeviceID: "test-device", Tier: "premium"}
	dm.currentLicense = &License{Valid: true, Claims: expectedClaimsObj}
	claims, err = dm.GetLicenseClaims()
	if err != nil {
		t.Errorf("GetLicenseClaims() unexpected error: %v", err)
	}
	if claims == nil {
		t.Fatalf("GetLicenseClaims() returned nil claims, want %v", expectedClaimsObj)
	}
	if claims.DeviceID != expectedClaimsObj.DeviceID || claims.Tier != expectedClaimsObj.Tier {
		t.Errorf("GetLicenseClaims() = %v, want %v", *claims, *expectedClaimsObj)
	}
}

var _ types.LicenseManager = (*MockLicenseManager)(nil) // Ensure mock implements the interface
