package security

import (
	"context"
	"fmt"
	"os"

	"github.com/twinfer/twincore/pkg/types"
)

// DeviceManager handles the device's current license.
type DeviceManager struct {
	licensePath    string
	currentLicense *License
	licenseManager types.LicenseManager
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
		licenseManager: lm, // lm is *security.LicenseManager, which implements types.LicenseManager
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

	validatedLicense, err := dm.licenseManager.ParseAndValidate(string(licenseBytes))
	if err != nil {
		// Store minimal info on error, even if validation fails
		dm.currentLicense = &License{Valid: false, Raw: string(licenseBytes)}
		return fmt.Errorf("license validation failed: %w", err)
	}

	// Type assert to the concrete *security.License type
	secLicense, ok := validatedLicense.(*License)
	if !ok {
		// This should ideally not happen if the LicenseManager implementation (security.LicenseManager)
		// always returns *security.License which implements types.License.
		dm.currentLicense = &License{Valid: false, Raw: string(licenseBytes)} // Store raw token on type error
		return fmt.Errorf("license validation returned unexpected type: %T", validatedLicense)
	}
	dm.currentLicense = secLicense
	return nil
}

// GetLicense returns the currently loaded and validated license.
// It might be nil if InitializeLicense has not been called or failed.
func (dm *DeviceManager) GetLicense() *License {
	return dm.currentLicense
}

// GetLicenseClaims returns the claims from the current license.
// Returns an error if the license or its claims are not available.
func (dm *DeviceManager) GetLicenseClaims() (*LicenseClaims, error) {
	if dm.currentLicense == nil || !dm.currentLicense.Valid {
		return nil, fmt.Errorf("no license loaded or license is invalid")
	}
	if dm.currentLicense.Claims == nil {
		// This case should ideally not happen if Validate ensures Claims is populated on success.
		return nil, fmt.Errorf("license is loaded but contains no structured claims")
	}
	return dm.currentLicense.Claims, nil
}
