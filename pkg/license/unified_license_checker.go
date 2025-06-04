package license

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"

	"github.com/twinfer/twincore/pkg/types"
	"slices"
)

// DefaultUnifiedLicenseChecker implements the UnifiedLicenseChecker interface
type DefaultUnifiedLicenseChecker struct {
	logger         *logrus.Logger
	publicKey      []byte
	currentLicense *types.LicenseInfo
	features       *types.LicenseSecurityFeatures
	limits         *types.LicenseLimits
}

// NewDefaultUnifiedLicenseChecker creates a new unified license checker
func NewDefaultUnifiedLicenseChecker(logger *logrus.Logger, publicKey []byte) *DefaultUnifiedLicenseChecker {
	return &DefaultUnifiedLicenseChecker{
		logger:    logger,
		publicKey: publicKey,
		features:  &types.BasicTier.Features, // Start with basic tier
		limits:    &types.BasicTier.Limits,
	}
}

// License Validation

func (ulc *DefaultUnifiedLicenseChecker) ValidateLicense(ctx context.Context, licenseData string) (*types.LicenseSecurityFeatures, error) {
	ulc.logger.Debug("Validating license")

	// Parse JWT token
	token, err := jwt.Parse(licenseData, func(token *jwt.Token) (any, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return ulc.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse license token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("license token is invalid")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid license claims")
	}

	// Parse license info
	licenseInfo, err := ulc.parseLicenseInfo(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse license info: %w", err)
	}

	// Check expiry
	if time.Now().After(licenseInfo.ExpiresAt) {
		return nil, fmt.Errorf("license has expired")
	}

	// Update current license
	ulc.currentLicense = licenseInfo
	ulc.features = &licenseInfo.Features
	ulc.limits = &licenseInfo.Limits

	ulc.logger.WithFields(logrus.Fields{
		"tier":       licenseInfo.Tier,
		"expires_at": licenseInfo.ExpiresAt,
		"subject":    licenseInfo.Subject,
	}).Info("License validated successfully")

	return &licenseInfo.Features, nil
}

func (ulc *DefaultUnifiedLicenseChecker) GetLicenseFeatures(ctx context.Context) (*types.LicenseSecurityFeatures, error) {
	if ulc.features == nil {
		return &types.BasicTier.Features, nil // Return basic features if no license
	}
	return ulc.features, nil
}

func (ulc *DefaultUnifiedLicenseChecker) IsLicenseValid(ctx context.Context) bool {
	if ulc.currentLicense == nil {
		return false
	}
	return time.Now().Before(ulc.currentLicense.ExpiresAt)
}

func (ulc *DefaultUnifiedLicenseChecker) GetLicenseExpiry(ctx context.Context) (time.Time, error) {
	if ulc.currentLicense == nil {
		return time.Time{}, fmt.Errorf("no license loaded")
	}
	return ulc.currentLicense.ExpiresAt, nil
}

// Feature Checking - System Security

func (ulc *DefaultUnifiedLicenseChecker) IsSystemFeatureEnabled(ctx context.Context, feature string) bool {
	if ulc.features == nil {
		return ulc.isBasicSystemFeature(feature)
	}

	switch feature {
	// Authentication Methods
	case "local_auth":
		return ulc.features.SystemSecurity.LocalAuth
	case "ldap_auth":
		return ulc.features.SystemSecurity.LDAPAuth
	case "saml_auth":
		return ulc.features.SystemSecurity.SAMLAuth
	case "oidc_auth":
		return ulc.features.SystemSecurity.OIDCAuth
	case "mfa":
		return ulc.features.SystemSecurity.MFA
	case "sso":
		return ulc.features.SystemSecurity.SSO
	case "jwt_auth":
		return ulc.features.SystemSecurity.JWTAuth
	case "api_keys":
		return ulc.features.SystemSecurity.APIKeys

	// Session Management
	case "session_mgmt":
		return ulc.features.SystemSecurity.SessionMgmt
	case "session_timeout":
		return ulc.features.SystemSecurity.SessionTimeout
	case "concurrent_sessions":
		return ulc.features.SystemSecurity.ConcurrentSessions

	// Authorization
	case "rbac":
		return ulc.features.SystemSecurity.RBAC
	case "policy_engine":
		return ulc.features.SystemSecurity.PolicyEngine
	case "fine_grained_acl":
		return ulc.features.SystemSecurity.FineGrainedACL

	// Security Features
	case "audit_logging":
		return ulc.features.SystemSecurity.AuditLogging
	case "brute_force_protection":
		return ulc.features.SystemSecurity.BruteForceProtection
	case "password_policy":
		return ulc.features.SystemSecurity.PasswordPolicy
	case "csrf_protection":
		return ulc.features.SystemSecurity.CSRFProtection

	// API Security
	case "rate_limit":
		return ulc.features.SystemSecurity.RateLimit
	case "ip_whitelist":
		return ulc.features.SystemSecurity.IPWhitelist
	case "request_signing":
		return ulc.features.SystemSecurity.RequestSigning

	// Compliance
	case "compliance_mode":
		return ulc.features.SystemSecurity.ComplianceMode
	case "data_retention":
		return ulc.features.SystemSecurity.DataRetention

	default:
		ulc.logger.WithField("feature", feature).Warn("Unknown system security feature")
		return false
	}
}

func (ulc *DefaultUnifiedLicenseChecker) GetSystemSecurityFeatures(ctx context.Context) (*types.SystemSecurityFeatures, error) {
	if ulc.features == nil {
		return &types.BasicTier.Features.SystemSecurity, nil
	}
	return &ulc.features.SystemSecurity, nil
}

func (ulc *DefaultUnifiedLicenseChecker) ValidateSystemOperation(ctx context.Context, operation string) error {
	// Map operations to required features
	requiredFeatures := map[string]string{
		"create_user":     "local_auth",
		"ldap_login":      "ldap_auth",
		"saml_login":      "saml_auth",
		"oidc_login":      "oidc_auth",
		"mfa_verify":      "mfa",
		"create_api_key":  "api_keys",
		"create_policy":   "rbac",
		"advanced_policy": "policy_engine",
		"audit_query":     "audit_logging",
		"set_rate_limit":  "rate_limit",
	}

	if feature, exists := requiredFeatures[operation]; exists {
		if !ulc.IsSystemFeatureEnabled(ctx, feature) {
			return fmt.Errorf("operation %s requires feature %s which is not licensed", operation, feature)
		}
	}

	return nil
}

// Feature Checking - WoT Security

func (ulc *DefaultUnifiedLicenseChecker) IsWoTFeatureEnabled(ctx context.Context, feature string) bool {
	if ulc.features == nil {
		return ulc.isBasicWoTFeature(feature)
	}

	switch feature {
	// WoT Security Schemes
	case "basic_auth":
		return ulc.features.WoTSecurity.BasicAuth
	case "bearer_auth":
		return ulc.features.WoTSecurity.BearerAuth
	case "api_key_auth":
		return ulc.features.WoTSecurity.APIKeyAuth
	case "oauth2_auth":
		return ulc.features.WoTSecurity.OAuth2Auth
	case "certificate_auth":
		return ulc.features.WoTSecurity.CertificateAuth
	case "psk_auth":
		return ulc.features.WoTSecurity.PSKAuth
	case "custom_auth":
		return ulc.features.WoTSecurity.CustomAuth

	// Credential Management
	case "credential_stores":
		return ulc.features.WoTSecurity.CredentialStores
	case "vault_integration":
		return ulc.features.WoTSecurity.VaultIntegration
	case "k8s_secrets":
		return ulc.features.WoTSecurity.K8sSecrets
	case "credential_rotation":
		return ulc.features.WoTSecurity.CredentialRotation
	case "credential_encryption":
		return ulc.features.WoTSecurity.CredentialEncryption

	// Access Control
	case "thing_access_control":
		return ulc.features.WoTSecurity.ThingAccessControl
	case "property_acl":
		return ulc.features.WoTSecurity.PropertyACL
	case "action_acl":
		return ulc.features.WoTSecurity.ActionACL
	case "event_acl":
		return ulc.features.WoTSecurity.EventACL
	case "time_based_access":
		return ulc.features.WoTSecurity.TimeBasedAccess
	case "ip_based_access":
		return ulc.features.WoTSecurity.IPBasedAccess

	// Security Policies
	case "security_templates":
		return ulc.features.WoTSecurity.SecurityTemplates
	case "global_policies":
		return ulc.features.WoTSecurity.GlobalPolicies
	case "policy_inheritance":
		return ulc.features.WoTSecurity.PolicyInheritance
	case "conditional_access":
		return ulc.features.WoTSecurity.ConditionalAccess

	// Data Security
	case "data_encryption":
		return ulc.features.WoTSecurity.DataEncryption
	case "data_masking":
		return ulc.features.WoTSecurity.DataMasking
	case "data_transformation":
		return ulc.features.WoTSecurity.DataTransformation
	case "data_validation":
		return ulc.features.WoTSecurity.DataValidation

	// Protocol Security
	case "tls_required":
		return ulc.features.WoTSecurity.TLSRequired
	case "protocol_encryption":
		return ulc.features.WoTSecurity.ProtocolEncryption
	case "certificate_management":
		return ulc.features.WoTSecurity.CertificateManagement

	// Monitoring & Auditing
	case "security_audit":
		return ulc.features.WoTSecurity.SecurityAudit
	case "access_logging":
		return ulc.features.WoTSecurity.AccessLogging
	case "security_metrics":
		return ulc.features.WoTSecurity.SecurityMetrics
	case "compliance_reporting":
		return ulc.features.WoTSecurity.ComplianceReporting

	// Rate Limiting & DoS Protection
	case "wot_rate_limit":
		return ulc.features.WoTSecurity.WoTRateLimit
	case "per_thing_limits":
		return ulc.features.WoTSecurity.PerThingLimits
	case "protocol_limits":
		return ulc.features.WoTSecurity.ProtocolLimits
	case "dos_protection":
		return ulc.features.WoTSecurity.DoSProtection

	default:
		ulc.logger.WithField("feature", feature).Warn("Unknown WoT security feature")
		return false
	}
}

func (ulc *DefaultUnifiedLicenseChecker) GetWoTSecurityFeatures(ctx context.Context) (*types.WoTSecurityFeatures, error) {
	if ulc.features == nil {
		return &types.BasicTier.Features.WoTSecurity, nil
	}
	return &ulc.features.WoTSecurity, nil
}

func (ulc *DefaultUnifiedLicenseChecker) ValidateWoTOperation(ctx context.Context, operation string) error {
	// Map operations to required features
	requiredFeatures := map[string]string{
		"set_thing_credentials":    "credential_stores",
		"create_security_template": "security_templates",
		"set_global_policy":        "global_policies",
		"encrypt_data":             "data_encryption",
		"mask_data":                "data_masking",
		"validate_certificate":     "certificate_auth",
		"rotate_credentials":       "credential_rotation",
		"audit_thing_access":       "security_audit",
		"set_thing_rate_limit":     "per_thing_limits",
	}

	if feature, exists := requiredFeatures[operation]; exists {
		if !ulc.IsWoTFeatureEnabled(ctx, feature) {
			return fmt.Errorf("operation %s requires feature %s which is not licensed", operation, feature)
		}
	}

	return nil
}

func (ulc *DefaultUnifiedLicenseChecker) ValidateSecurityScheme(ctx context.Context, scheme string) error {
	switch scheme {
	case "basic":
		if !ulc.IsWoTFeatureEnabled(ctx, "basic_auth") {
			return fmt.Errorf("basic authentication scheme not licensed")
		}
	case "bearer":
		if !ulc.IsWoTFeatureEnabled(ctx, "bearer_auth") {
			return fmt.Errorf("bearer authentication scheme not licensed")
		}
	case "apikey":
		if !ulc.IsWoTFeatureEnabled(ctx, "api_key_auth") {
			return fmt.Errorf("API key authentication scheme not licensed")
		}
	case "oauth2":
		if !ulc.IsWoTFeatureEnabled(ctx, "oauth2_auth") {
			return fmt.Errorf("OAuth2 authentication scheme not licensed")
		}
	case "cert":
		if !ulc.IsWoTFeatureEnabled(ctx, "certificate_auth") {
			return fmt.Errorf("certificate authentication scheme not licensed")
		}
	case "psk":
		if !ulc.IsWoTFeatureEnabled(ctx, "psk_auth") {
			return fmt.Errorf("PSK authentication scheme not licensed")
		}
	default:
		if !ulc.IsWoTFeatureEnabled(ctx, "custom_auth") {
			return fmt.Errorf("custom authentication schemes not licensed")
		}
	}

	return nil
}

// Feature Checking - General

func (ulc *DefaultUnifiedLicenseChecker) IsGeneralFeatureEnabled(ctx context.Context, feature string) bool {
	if ulc.features == nil {
		return ulc.isBasicGeneralFeature(feature)
	}

	switch feature {
	// Transport Security
	case "tls_required":
		return ulc.features.General.TLSRequired
	case "security_headers":
		return ulc.features.General.SecurityHeaders
	case "cors_control":
		return ulc.features.General.CORSControl
	case "content_security":
		return ulc.features.General.ContentSecurity

	// Network Security
	case "ip_filtering":
		return ulc.features.General.IPFiltering
	case "geolocation_control":
		return ulc.features.General.GeolocationControl
	case "vpn_detection":
		return ulc.features.General.VPNDetection

	// Rate Limiting
	case "global_rate_limit":
		return ulc.features.General.GlobalRateLimit
	case "burst_control":
		return ulc.features.General.BurstControl

	// Monitoring & Alerting
	case "security_monitoring":
		return ulc.features.General.SecurityMonitoring
	case "alerting_system":
		return ulc.features.General.AlertingSystem
	case "incident_response":
		return ulc.features.General.IncidentResponse

	// Compliance & Standards
	case "soc2_compliance":
		return ulc.features.General.SOC2Compliance
	case "gdpr":
		return ulc.features.General.GDPR
	case "hipaa":
		return ulc.features.General.HIPAA
	case "iso_compliance":
		return ulc.features.General.ISOCompliance

	// Advanced Features
	case "zero_trust_model":
		return ulc.features.General.ZeroTrustModel
	case "micro_segmentation":
		return ulc.features.General.MicroSegmentation
	case "behavior_analysis":
		return ulc.features.General.BehaviorAnalysis
	case "threat_intelligence":
		return ulc.features.General.ThreatIntelligence

	default:
		ulc.logger.WithField("feature", feature).Warn("Unknown general security feature")
		return false
	}
}

func (ulc *DefaultUnifiedLicenseChecker) GetGeneralSecurityFeatures(ctx context.Context) (*types.GeneralSecurityFeatures, error) {
	if ulc.features == nil {
		return &types.BasicTier.Features.General, nil
	}
	return &ulc.features.General, nil
}

// Limits Checking

func (ulc *DefaultUnifiedLicenseChecker) GetLicenseLimits(ctx context.Context) (*types.LicenseLimits, error) {
	if ulc.limits == nil {
		return &types.BasicTier.Limits, nil
	}
	return ulc.limits, nil
}

func (ulc *DefaultUnifiedLicenseChecker) CheckLimit(ctx context.Context, limitType string, currentUsage int) error {
	limits, err := ulc.GetLicenseLimits(ctx)
	if err != nil {
		return err
	}

	var maxAllowed int
	switch limitType {
	case "devices":
		maxAllowed = limits.MaxDevices
	case "things":
		maxAllowed = limits.MaxThings
	case "users":
		maxAllowed = limits.MaxUsers
	case "api_requests":
		maxAllowed = limits.MaxAPIRequests
	case "data_storage":
		maxAllowed = limits.MaxDataStorage
	case "policies":
		maxAllowed = limits.MaxPolicies
	case "credential_stores":
		maxAllowed = limits.MaxCredentialStores
	case "security_templates":
		maxAllowed = limits.MaxSecurityTemplates
	default:
		return fmt.Errorf("unknown limit type: %s", limitType)
	}

	// -1 means unlimited
	if maxAllowed == -1 {
		return nil
	}

	if currentUsage > maxAllowed {
		return fmt.Errorf("%s limit exceeded: %d/%d", limitType, currentUsage, maxAllowed)
	}

	return nil
}

func (ulc *DefaultUnifiedLicenseChecker) GetUsageStats(ctx context.Context) (map[string]int, error) {
	// TODO: Implement usage statistics collection
	// This would typically involve querying the database for current counts
	return map[string]int{
		"devices":            0,
		"things":             0,
		"users":              0,
		"api_requests":       0,
		"data_storage":       0,
		"policies":           0,
		"credential_stores":  0,
		"security_templates": 0,
	}, nil
}

// License Management

func (ulc *DefaultUnifiedLicenseChecker) ReloadLicense(ctx context.Context) error {
	// TODO: Implement license reloading from configured source
	return fmt.Errorf("license reloading not implemented")
}

func (ulc *DefaultUnifiedLicenseChecker) GetLicenseInfo(ctx context.Context) (*types.LicenseInfo, error) {
	if ulc.currentLicense == nil {
		return nil, fmt.Errorf("no license loaded")
	}
	return ulc.currentLicense, nil
}

func (ulc *DefaultUnifiedLicenseChecker) ValidateLicenseForUpgrade(ctx context.Context, newLicenseData string) error {
	// Temporarily validate new license without updating current state
	tempChecker := NewDefaultUnifiedLicenseChecker(ulc.logger, ulc.publicKey)
	_, err := tempChecker.ValidateLicense(ctx, newLicenseData)
	return err
}

// Tier Management

func (ulc *DefaultUnifiedLicenseChecker) GetAvailableTiers(ctx context.Context) ([]types.LicenseTier, error) {
	return types.GetPredefinedTiers(), nil
}

func (ulc *DefaultUnifiedLicenseChecker) GetCurrentTier(ctx context.Context) (*types.LicenseTier, error) {
	if ulc.currentLicense == nil {
		return &types.BasicTier, nil
	}

	// Find tier by name
	for _, tier := range types.GetPredefinedTiers() {
		if tier.Name == ulc.currentLicense.Tier {
			return &tier, nil
		}
	}

	return &types.BasicTier, nil
}

func (ulc *DefaultUnifiedLicenseChecker) CompareTiers(ctx context.Context, currentTier, targetTier string) (*types.TierComparison, error) {
	tiers := types.GetPredefinedTiers()

	var current, target *types.LicenseTier
	for _, tier := range tiers {
		if tier.Name == currentTier {
			current = &tier
		}
		if tier.Name == targetTier {
			target = &tier
		}
	}

	if current == nil {
		return nil, fmt.Errorf("current tier %s not found", currentTier)
	}
	if target == nil {
		return nil, fmt.Errorf("target tier %s not found", targetTier)
	}

	comparison := &types.TierComparison{
		CurrentTier:     currentTier,
		TargetTier:      targetTier,
		AddedFeatures:   []string{},
		RemovedFeatures: []string{},
		LimitChanges:    make(map[string]types.LimitChange),
	}

	// Compare features (simplified - would need reflection for complete comparison)
	if target.Features.SystemSecurity.RBAC && !current.Features.SystemSecurity.RBAC {
		comparison.AddedFeatures = append(comparison.AddedFeatures, "system_rbac")
	}
	if target.Features.WoTSecurity.OAuth2Auth && !current.Features.WoTSecurity.OAuth2Auth {
		comparison.AddedFeatures = append(comparison.AddedFeatures, "wot_oauth2")
	}

	// Compare limits
	comparison.LimitChanges["max_devices"] = types.LimitChange{
		Current: current.Limits.MaxDevices,
		Target:  target.Limits.MaxDevices,
		Change:  ulc.getLimitChangeType(current.Limits.MaxDevices, target.Limits.MaxDevices),
	}

	// Generate recommendation
	if len(comparison.AddedFeatures) > 0 {
		comparison.Recommendation = "Upgrade recommended for additional security features"
	} else {
		comparison.Recommendation = "Current tier sufficient for security requirements"
	}

	return comparison, nil
}

// Helper methods

func (ulc *DefaultUnifiedLicenseChecker) parseLicenseInfo(claims jwt.MapClaims) (*types.LicenseInfo, error) {
	info := &types.LicenseInfo{
		Metadata: make(map[string]any),
	}

	// Extract standard JWT claims
	if sub, ok := claims["sub"].(string); ok {
		info.Subject = sub
	}
	if iss, ok := claims["iss"].(string); ok {
		info.Issuer = iss
	}
	if iat, ok := claims["iat"].(float64); ok {
		info.IssuedAt = time.Unix(int64(iat), 0)
	}
	if exp, ok := claims["exp"].(float64); ok {
		info.ExpiresAt = time.Unix(int64(exp), 0)
	}

	// Extract TwinCore-specific claims
	if tier, ok := claims["tier"].(string); ok {
		info.Tier = tier
	} else {
		info.Tier = "basic"
	}

	if org, ok := claims["organization"].(string); ok {
		info.Organization = org
	}

	if deviceID, ok := claims["device_id"].(string); ok {
		info.DeviceID = deviceID
	}

	// Parse features from license
	if featuresData, ok := claims["features"]; ok {
		featuresJSON, err := json.Marshal(featuresData)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal features: %w", err)
		}

		if err := json.Unmarshal(featuresJSON, &info.Features); err != nil {
			return nil, fmt.Errorf("failed to unmarshal features: %w", err)
		}
	} else {
		// Use predefined tier features
		info.Features = ulc.getFeaturesForTier(info.Tier)
	}

	// Parse limits from license
	if limitsData, ok := claims["limits"]; ok {
		limitsJSON, err := json.Marshal(limitsData)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal limits: %w", err)
		}

		if err := json.Unmarshal(limitsJSON, &info.Limits); err != nil {
			return nil, fmt.Errorf("failed to unmarshal limits: %w", err)
		}
	} else {
		// Use predefined tier limits
		info.Limits = ulc.getLimitsForTier(info.Tier)
	}

	return info, nil
}

func (ulc *DefaultUnifiedLicenseChecker) getFeaturesForTier(tier string) types.LicenseSecurityFeatures {
	for _, t := range types.GetPredefinedTiers() {
		if t.Name == tier {
			return t.Features
		}
	}
	return types.BasicTier.Features
}

func (ulc *DefaultUnifiedLicenseChecker) getLimitsForTier(tier string) types.LicenseLimits {
	for _, t := range types.GetPredefinedTiers() {
		if t.Name == tier {
			return t.Limits
		}
	}
	return types.BasicTier.Limits
}

func (ulc *DefaultUnifiedLicenseChecker) getLimitChangeType(current, target int) string {
	if target == -1 {
		return "unlimited"
	}
	if target > current {
		return "increase"
	}
	if target < current {
		return "decrease"
	}
	return "no_change"
}

// Basic feature sets for when no license is loaded

func (ulc *DefaultUnifiedLicenseChecker) isBasicSystemFeature(feature string) bool {
	basicFeatures := []string{"local_auth", "session_mgmt", "audit_logging", "rate_limit"}
	return slices.Contains(basicFeatures, feature)
}

func (ulc *DefaultUnifiedLicenseChecker) isBasicWoTFeature(feature string) bool {
	basicFeatures := []string{"basic_auth", "bearer_auth", "security_audit", "wot_rate_limit"}
	return slices.Contains(basicFeatures, feature)
}

func (ulc *DefaultUnifiedLicenseChecker) isBasicGeneralFeature(feature string) bool {
	basicFeatures := []string{"tls_required", "security_headers", "global_rate_limit"}
	return slices.Contains(basicFeatures, feature)
}

// Ensure interface compliance
var _ types.UnifiedLicenseChecker = (*DefaultUnifiedLicenseChecker)(nil)
