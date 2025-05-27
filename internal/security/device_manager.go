package security

import (
	"context"
	"fmt"
	"os"
	"time"
	// Assuming types.LicenseManager is defined in a way that it's compatible.
	// The previous file `license_types.go` defined a local `LicenseManager` interface.
	// If `github.com/twinfer/twincore/pkg/types.LicenseManager` is a different interface,
	// this might need adjustment. For now, I'll assume the local `LicenseManager` is intended
	// or that `types.LicenseManager` is a general interface that `DefaultLicenseManager` satisfies.
	// For this implementation, I will use the LicenseManager defined in the same package.
)

// DeviceManager handles the device's current license.
type DeviceManager struct {
	licensePath    string
	publicKey      []byte
	currentLicense *License
	licenseManager LicenseManager // Using the LicenseManager from this package
}

// NewDeviceManager creates a new DeviceManager.
func NewDeviceManager(licensePath string, publicKey []byte) (*DeviceManager, error) {
	// Instantiate DefaultLicenseManager from this package.
	// NewLicenseManager now returns (LicenseManager, error).
	lm, err := NewLicenseManager(publicKey) // This publicKey is for Validate, not strictly for New.
	if err != nil {
		return nil, fmt.Errorf("failed to create license manager: %w", err)
	}

	return &DeviceManager{
		licensePath:    licensePath,
		publicKey:      publicKey,
		licenseManager: lm,
	}, nil
}

// InitializeLicense reads the license file, validates it, and stores it.
func (dm *DeviceManager) InitializeLicense(ctx context.Context) error {
	if dm.licenseManager == nil {
		return fmt.Errorf("device manager's licenseManager is not initialized")
	}

	licenseBytes, err := os.ReadFile(dm.licensePath)
	if err != nil {
		return fmt.Errorf("failed to read license file from %s: %w", dm.licensePath, err)
	}

	license, err := dm.licenseManager.Validate(string(licenseBytes), dm.publicKey)
	if err != nil {
		return fmt.Errorf("license validation failed: %w", err)
	}

	dm.currentLicense = license
	// Optionally log successful license load
	// fmt.Printf("License successfully loaded and validated for device. Claims: %v\n", license.Claims)
	return nil
}

// GetLicense returns the currently loaded and validated license.
// It might be nil if InitializeLicense has not been called or failed.
func (dm *DeviceManager) GetLicense() *License {
	return dm.currentLicense
}

// GetLicenseClaims returns the claims from the current license.
// Returns an error if the license or its claims are not available.
func (dm *DeviceManager) GetLicenseClaims() (map[string]interface{}, error) {
	if dm.currentLicense == nil {
		return nil, fmt.Errorf("no license loaded or license is invalid")
	}
	if dm.currentLicense.Claims == nil {
		// This case should ideally not happen if Validate ensures Claims is populated on success.
		return nil, fmt.Errorf("license is loaded but contains no claims")
	}
	return dm.currentLicense.Claims, nil
}
