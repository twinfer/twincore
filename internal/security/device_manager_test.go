package security

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// MockLicenseManager for testing DeviceManager
type MockLicenseManager struct {
	ValidateFunc func(tokenString string, publicKey []byte) (*License, error)
}

func (m *MockLicenseManager) Validate(tokenString string, publicKey []byte) (*License, error) {
	if m.ValidateFunc != nil {
		return m.ValidateFunc(tokenString, publicKey)
	}
	return nil, fmt.Errorf("ValidateFunc not set in MockLicenseManager")
}

func TestNewDeviceManager(t *testing.T) {
	dm, err := NewDeviceManager("dummy_path", []byte("dummy_key"))
	if err != nil {
		t.Fatalf("NewDeviceManager() error = %v, wantErr %v", err, false)
	}
	if dm == nil {
		t.Fatal("NewDeviceManager() returned nil")
	}
	if dm.licensePath != "dummy_path" {
		t.Errorf("NewDeviceManager() licensePath = %s, want %s", dm.licensePath, "dummy_path")
	}
}

func TestDeviceManager_InitializeLicense(t *testing.T) {
	validClaims := map[string]interface{}{"active": true, "exp": time.Now().Add(time.Hour).Unix()}
	validLicense := &License{Claims: validClaims}
	dummyKey := []byte("dummy_public_key")

	// Create a temporary license file
	tempDir := t.TempDir()
	validLicenseFile := filepath.Join(tempDir, "license.jwt")
	if err := os.WriteFile(validLicenseFile, []byte("valid_dummy_token"), 0644); err != nil {
		t.Fatalf("Failed to write temp license file: %v", err)
	}

	nonExistentLicenseFile := filepath.Join(tempDir, "non_existent.jwt")

	tests := []struct {
		name           string
		licensePath    string
		mockValidate   func(tokenString string, publicKey []byte) (*License, error)
		wantErr        bool
		wantLicenseNil bool
	}{
		{
			name:        "successful initialization",
			licensePath: validLicenseFile,
			mockValidate: func(tokenString string, publicKey []byte) (*License, error) {
				if tokenString != "valid_dummy_token" {
					return nil, fmt.Errorf("unexpected token string: %s", tokenString)
				}
				return validLicense, nil
			},
			wantErr:        false,
			wantLicenseNil: false,
		},
		{
			name:        "license manager validation fails",
			licensePath: validLicenseFile,
			mockValidate: func(tokenString string, publicKey []byte) (*License, error) {
				return nil, fmt.Errorf("mock validation error")
			},
			wantErr:        true,
			wantLicenseNil: true,
		},
		{
			name:        "license file does not exist",
			licensePath: nonExistentLicenseFile,
			mockValidate: func(tokenString string, publicKey []byte) (*License, error) {
				// This shouldn't be called if file read fails
				return validLicense, nil
			},
			wantErr:        true,
			wantLicenseNil: true,
		},
		{
			name:        "empty license file path",
			licensePath: "", // Test with an empty path
			mockValidate: func(tokenString string, publicKey []byte) (*License, error) {
				return validLicense, nil
			},
			wantErr:        true, // os.ReadFile will error on empty path
			wantLicenseNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLm := &MockLicenseManager{ValidateFunc: tt.mockValidate}
			dm := &DeviceManager{
				licensePath:    tt.licensePath,
				publicKey:      dummyKey,
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
		})
	}
}

func TestDeviceManager_GetLicense(t *testing.T) {
	dm := &DeviceManager{} // Blank device manager
	if lic := dm.GetLicense(); lic != nil {
		t.Errorf("GetLicense() on uninitialized DM = %v, want nil", lic)
	}

	expectedLicense := &License{Claims: map[string]interface{}{"active": true}}
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
	dm.currentLicense = &License{Claims: nil}
	claims, err = dm.GetLicenseClaims()
	if err == nil {
		t.Error("GetLicenseClaims() expected error when claims are nil, got nil")
	}
	if claims != nil {
		t.Errorf("GetLicenseClaims() expected nil claims when license.Claims is nil, got %v", claims)
	}

	// Case 3: License with valid claims
	expectedClaims := map[string]interface{}{"feature_A": true, "user": "test"}
	dm.currentLicense = &License{Claims: expectedClaims}
	claims, err = dm.GetLicenseClaims()
	if err != nil {
		t.Errorf("GetLicenseClaims() unexpected error: %v", err)
	}
	if len(claims) != len(expectedClaims) { // Simple comparison
		t.Errorf("GetLicenseClaims() = %v, want %v", claims, expectedClaims)
	}
	for k, v := range expectedClaims {
		if claims[k] != v {
			t.Errorf("GetLicenseClaims() claim %s = %v, want %v", k, claims[k], v)
		}
	}
}
