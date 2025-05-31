package security

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/open-policy-agent/opa/rego"
	"github.com/sirupsen/logrus"
)

// LicenseCheckerOPA implements license checking using OPA policies
type LicenseCheckerOPA struct {
	policyDir string
	jwtData   map[string]interface{}
	logger    logrus.FieldLogger
}

// NewLicenseCheckerOPA creates a new OPA-based license checker
func NewLicenseCheckerOPA(policyDir string, licenseFile string, logger logrus.FieldLogger) (*LicenseCheckerOPA, error) {
	lc := &LicenseCheckerOPA{
		policyDir: policyDir,
		logger:    logger,
	}

	// Verify policies exist
	policies := []string{"features.rego", "limits.rego", "security.rego"}
	for _, policyFile := range policies {
		policyPath := filepath.Join(policyDir, policyFile)
		if _, err := os.ReadFile(policyPath); err != nil {
			return nil, fmt.Errorf("failed to read policy %s: %w", policyFile, err)
		}
	}

	// Load JWT license if provided
	if licenseFile != "" {
		jwtData, err := lc.loadAndVerifyJWT(licenseFile)
		if err != nil {
			logger.WithError(err).Warn("No valid license found, using defaults")
			// Continue without license - OPA will use defaults
		} else {
			lc.jwtData = jwtData
			logger.Info("License loaded successfully")
		}
	} else {
		logger.Info("No license file provided, using default features")
	}

	return lc, nil
}

// loadAndVerifyJWT loads and verifies the JWT license file
func (lc *LicenseCheckerOPA) loadAndVerifyJWT(licenseFile string) (map[string]interface{}, error) {
	// This would integrate with the existing JWT validation logic
	// For now, we'll parse it as JSON for development
	content, err := os.ReadFile(licenseFile)
	if err != nil {
		return nil, err
	}

	var jwtData map[string]interface{}
	if err := json.Unmarshal(content, &jwtData); err != nil {
		return nil, err
	}

	// TODO: Verify JWT signature
	// validator := NewLicenseValidator(publicKey)
	// if err := validator.Verify(content); err != nil {
	//     return nil, err
	// }

	return jwtData, nil
}

// evalQuery evaluates an OPA query with the current context
func (lc *LicenseCheckerOPA) evalQuery(ctx context.Context, query string, input map[string]interface{}) (rego.ResultSet, error) {
	// Load policies
	modules := make([]func(*rego.Rego), 0)
	modules = append(modules, rego.Query(query))

	policies := []string{"features.rego", "limits.rego", "security.rego"}
	for _, policyFile := range policies {
		policyPath := filepath.Join(lc.policyDir, policyFile)
		content, err := os.ReadFile(policyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read policy %s: %w", policyFile, err)
		}
		modules = append(modules, rego.Module(policyFile, string(content)))
	}

	r := rego.New(modules...)
	prepared, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare query: %w", err)
	}

	return prepared.Eval(ctx, rego.EvalInput(input))
}

// IsFeatureEnabled checks if a specific feature is enabled
func (lc *LicenseCheckerOPA) IsFeatureEnabled(category, feature string) (bool, error) {
	ctx := context.Background()

	// Use the feature_allowed function from the policy
	query := "data.twincore.features.feature_allowed[input.category][input.feature]"

	input := map[string]interface{}{
		"jwt":      lc.jwtData,
		"category": category,
		"feature":  feature,
	}

	rs, err := lc.evalQuery(ctx, query, input)
	if err != nil {
		return false, fmt.Errorf("OPA evaluation error: %w", err)
	}

	// If we get any results, the feature is allowed
	return len(rs) > 0 && len(rs[0].Expressions) > 0, nil
}

// GetAllowedFeatures returns all allowed features based on license
func (lc *LicenseCheckerOPA) GetAllowedFeatures() (map[string]interface{}, error) {
	ctx := context.Background()

	input := map[string]interface{}{
		"jwt": lc.jwtData,
	}

	rs, err := lc.evalQuery(ctx, "data.twincore.features.allowed_features", input)
	if err != nil {
		return nil, fmt.Errorf("OPA evaluation error: %w", err)
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, fmt.Errorf("no features returned from OPA")
	}

	features, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected OPA result type")
	}

	return features, nil
}

// CheckLimit verifies if a resource count is within licensed limits
func (lc *LicenseCheckerOPA) CheckLimit(resource string, currentCount int) (bool, error) {
	ctx := context.Background()

	// Use the within_limit function from the policy
	query := "data.twincore.limits.within_limit[input.resource][input.count]"

	input := map[string]interface{}{
		"jwt":      lc.jwtData,
		"resource": resource,
		"count":    currentCount,
	}

	rs, err := lc.evalQuery(ctx, query, input)
	if err != nil {
		return false, fmt.Errorf("OPA evaluation error: %w", err)
	}

	return len(rs) > 0 && len(rs[0].Expressions) > 0, nil
}

// GetSecurityConfig generates security configuration based on license
func (lc *LicenseCheckerOPA) GetSecurityConfig(config map[string]interface{}) (map[string]interface{}, error) {
	ctx := context.Background()

	input := map[string]interface{}{
		"jwt":    lc.jwtData,
		"config": config,
	}

	rs, err := lc.evalQuery(ctx, "data.twincore.security.caddy_security_config", input)
	if err != nil {
		return nil, fmt.Errorf("OPA evaluation error: %w", err)
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, fmt.Errorf("no security config returned from OPA")
	}

	securityConfig, ok := rs[0].Expressions[0].Value.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected OPA result type")
	}

	return securityConfig, nil
}

// GetRateLimit returns the rate limit for a specific endpoint
func (lc *LicenseCheckerOPA) GetRateLimit(endpoint string) (int, error) {
	ctx := context.Background()

	query := "data.twincore.limits.rate_limit_for_endpoint[input.endpoint]"

	input := map[string]interface{}{
		"jwt":      lc.jwtData,
		"endpoint": endpoint,
	}

	rs, err := lc.evalQuery(ctx, query, input)
	if err != nil {
		return 100, fmt.Errorf("OPA evaluation error: %w", err) // Default to 100
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return 100, nil // Default rate limit
	}

	// OPA returns float64 for numbers
	if limit, ok := rs[0].Expressions[0].Value.(float64); ok {
		return int(limit), nil
	}

	return 100, nil // Default if type assertion fails
}

// HasLicense returns true if a valid license is loaded
func (lc *LicenseCheckerOPA) HasLicense() bool {
	return lc.jwtData != nil
}
