package security

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/twinfer/twincore/pkg/types"
	"slices"
)

// DefaultWoTSecurityManager implements WoTSecurityManager interface
type DefaultWoTSecurityManager struct {
	db               *sql.DB
	logger           *logrus.Logger
	config           *types.WoTSecurityConfig
	licenseChecker   types.UnifiedLicenseChecker
	credentialStores map[string]types.CredentialStore
}

// NewDefaultWoTSecurityManager creates a new WoT security manager
func NewDefaultWoTSecurityManager(db *sql.DB, logger *logrus.Logger, licenseChecker types.UnifiedLicenseChecker) *DefaultWoTSecurityManager {
	return &DefaultWoTSecurityManager{
		db:               db,
		logger:           logger,
		licenseChecker:   licenseChecker,
		credentialStores: make(map[string]types.CredentialStore),
		config: &types.WoTSecurityConfig{
			ThingPolicies:     make(map[string]types.ThingSecurityPolicy),
			CredentialStores:  make(map[string]types.CredentialStore),
			SecurityTemplates: make(map[string]types.SecurityTemplate),
		},
	}
}

// Thing Security Management

func (wsm *DefaultWoTSecurityManager) GetThingCredentials(ctx context.Context, thingID string, protocolType string) (*types.DeviceCredentials, error) {
	wsm.logger.WithFields(logrus.Fields{
		"thing_id": thingID,
		"protocol": protocolType,
	}).Debug("Getting Thing credentials")

	// Get Thing security policy
	policy, err := wsm.GetThingSecurityPolicy(ctx, thingID)
	if err != nil {
		return nil, fmt.Errorf("failed to get Thing security policy: %w", err)
	}

	// Find credential mapping for the protocol
	var credentialRef types.CredentialRef
	var found bool

	// Check protocol-specific credentials first
	if protocolSecurity, exists := policy.ProtocolSecurity[protocolType]; exists {
		if ref, ok := protocolSecurity.Properties["credential_ref"].(types.CredentialRef); ok {
			credentialRef = ref
			found = true
		}
	}

	// Fall back to scheme-based credentials
	if !found {
		for _, scheme := range policy.RequiredSchemes {
			if ref, exists := policy.CredentialMapping[scheme]; exists {
				credentialRef = ref
				found = true
				break
			}
		}
	}

	if !found {
		return nil, fmt.Errorf("no credentials configured for Thing %s protocol %s", thingID, protocolType)
	}

	// Retrieve credentials from store
	credentials, err := wsm.GetCredentials(ctx, credentialRef)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve credentials: %w", err)
	}

	wsm.logSecurityEvent(ctx, types.WoTSecurityEvent{
		ThingID:   thingID,
		Operation: "get_credentials",
		Protocol:  protocolType,
		Success:   true,
	})

	return credentials, nil
}

func (wsm *DefaultWoTSecurityManager) SetThingCredentials(ctx context.Context, thingID string, protocolType string, credentials *types.DeviceCredentials) error {
	// Check license for credential management
	if !wsm.licenseChecker.IsWoTFeatureEnabled(ctx, "credential_stores") {
		return fmt.Errorf("credential management not licensed")
	}

	wsm.logger.WithFields(logrus.Fields{
		"thing_id":  thingID,
		"protocol":  protocolType,
		"cred_type": credentials.Type,
	}).Debug("Setting Thing credentials")

	// Create credential reference
	credentialRef := types.CredentialRef{
		Store: "default",
		Key:   fmt.Sprintf("%s_%s_%s", thingID, protocolType, credentials.Type),
		Type:  credentials.Type,
	}

	// Store credentials
	if err := wsm.SetCredentials(ctx, credentialRef, credentials); err != nil {
		return fmt.Errorf("failed to store credentials: %w", err)
	}

	// Update Thing security policy
	policy, err := wsm.GetThingSecurityPolicy(ctx, thingID)
	if err != nil {
		// Create new policy if it doesn't exist
		policy = &types.ThingSecurityPolicy{
			ThingID:           thingID,
			RequiredSchemes:   []string{credentials.Type},
			CredentialMapping: make(map[string]types.CredentialRef),
			ProtocolSecurity:  make(map[string]types.ProtocolSecurity),
		}
	}

	// Update protocol security
	if policy.ProtocolSecurity == nil {
		policy.ProtocolSecurity = make(map[string]types.ProtocolSecurity)
	}

	protocolSec := policy.ProtocolSecurity[protocolType]
	if protocolSec.Properties == nil {
		protocolSec.Properties = make(map[string]any)
	}
	protocolSec.Properties["credential_ref"] = credentialRef
	policy.ProtocolSecurity[protocolType] = protocolSec

	// Save updated policy
	if err := wsm.SetThingSecurityPolicy(ctx, thingID, policy); err != nil {
		return fmt.Errorf("failed to update Thing security policy: %w", err)
	}

	wsm.logSecurityEvent(ctx, types.WoTSecurityEvent{
		ThingID:   thingID,
		Operation: "set_credentials",
		Protocol:  protocolType,
		Success:   true,
	})

	return nil
}

func (wsm *DefaultWoTSecurityManager) ValidateThingAccess(ctx context.Context, thingID string, operation string, accessCtx *types.WoTAccessContext) error {
	// Check if access control is enabled by license
	if !wsm.licenseChecker.IsWoTFeatureEnabled(ctx, "thing_access_control") {
		return nil // Access control not licensed, allow all
	}

	wsm.logger.WithFields(logrus.Fields{
		"thing_id":  thingID,
		"operation": operation,
		"resource":  accessCtx.Resource,
		"protocol":  accessCtx.Protocol,
		"source_ip": accessCtx.SourceIP,
	}).Debug("Validating Thing access")

	// Get Thing security policy
	policy, err := wsm.GetThingSecurityPolicy(ctx, thingID)
	if err != nil {
		// No policy means no restrictions (unless global policy says otherwise)
		if wsm.config.GlobalPolicies != nil && wsm.config.GlobalPolicies.RequireAuthentication {
			return fmt.Errorf("Thing access requires authentication but no policy found")
		}
		return nil
	}

	// Check access control rules
	if policy.AccessControl != nil {
		if err := wsm.evaluateAccessControl(ctx, policy.AccessControl, accessCtx); err != nil {
			wsm.logSecurityEvent(ctx, types.WoTSecurityEvent{
				ThingID:   thingID,
				Operation: operation,
				Resource:  accessCtx.Resource,
				Protocol:  accessCtx.Protocol,
				Success:   false,
				Error:     err.Error(),
				SourceIP:  accessCtx.SourceIP,
			})
			return err
		}
	}

	// Check global policies
	if wsm.config.GlobalPolicies != nil {
		if err := wsm.evaluateGlobalPolicies(ctx, wsm.config.GlobalPolicies, accessCtx); err != nil {
			wsm.logSecurityEvent(ctx, types.WoTSecurityEvent{
				ThingID:   thingID,
				Operation: operation,
				Resource:  accessCtx.Resource,
				Protocol:  accessCtx.Protocol,
				Success:   false,
				Error:     err.Error(),
				SourceIP:  accessCtx.SourceIP,
			})
			return err
		}
	}

	wsm.logSecurityEvent(ctx, types.WoTSecurityEvent{
		ThingID:   thingID,
		Operation: operation,
		Resource:  accessCtx.Resource,
		Protocol:  accessCtx.Protocol,
		Success:   true,
		SourceIP:  accessCtx.SourceIP,
	})

	return nil
}

func (wsm *DefaultWoTSecurityManager) GetThingSecurityPolicy(ctx context.Context, thingID string) (*types.ThingSecurityPolicy, error) {
	// Check in memory first
	if policy, exists := wsm.config.ThingPolicies[thingID]; exists {
		return &policy, nil
	}

	// Check database
	var policyJSON string
	err := wsm.db.QueryRowContext(ctx, `
		SELECT policy_data FROM thing_security_policies WHERE thing_id = ?
	`, thingID).Scan(&policyJSON)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("security policy not found for Thing %s", thingID)
	} else if err != nil {
		return nil, fmt.Errorf("failed to retrieve security policy: %w", err)
	}

	var policy types.ThingSecurityPolicy
	if err := json.Unmarshal([]byte(policyJSON), &policy); err != nil {
		return nil, fmt.Errorf("failed to parse security policy: %w", err)
	}

	// Cache in memory
	wsm.config.ThingPolicies[thingID] = policy

	return &policy, nil
}

func (wsm *DefaultWoTSecurityManager) SetThingSecurityPolicy(ctx context.Context, thingID string, policy *types.ThingSecurityPolicy) error {
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal security policy: %w", err)
	}

	// Store in database
	_, err = wsm.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO thing_security_policies (thing_id, policy_data, updated_at)
		VALUES (?, ?, ?)
	`, thingID, string(policyJSON), time.Now())

	if err != nil {
		return fmt.Errorf("failed to store security policy: %w", err)
	}

	// Update in-memory cache
	wsm.config.ThingPolicies[thingID] = *policy

	wsm.logSecurityEvent(ctx, types.WoTSecurityEvent{
		ThingID:   thingID,
		Operation: "set_security_policy",
		Success:   true,
	})

	return nil
}

// Security Scheme Processing

func (wsm *DefaultWoTSecurityManager) ProcessSecuritySchemes(ctx context.Context, thingID string, schemes []types.WoTSecurityScheme) (*types.ThingSecurityPolicy, error) {
	wsm.logger.WithFields(logrus.Fields{
		"thing_id":     thingID,
		"scheme_count": len(schemes),
	}).Debug("Processing WoT security schemes")

	policy := &types.ThingSecurityPolicy{
		ThingID:           thingID,
		RequiredSchemes:   make([]string, 0, len(schemes)),
		CredentialMapping: make(map[string]types.CredentialRef),
		ProtocolSecurity:  make(map[string]types.ProtocolSecurity),
	}

	for _, scheme := range schemes {
		// Validate scheme is licensed
		if err := wsm.ValidateSecurityScheme(ctx, scheme); err != nil {
			return nil, fmt.Errorf("security scheme %s not valid: %w", scheme.Name, err)
		}

		policy.RequiredSchemes = append(policy.RequiredSchemes, scheme.Scheme)

		// Create default credential reference
		credentialRef := types.CredentialRef{
			Store: "default",
			Key:   fmt.Sprintf("%s_%s", thingID, scheme.Scheme),
			Type:  scheme.Scheme,
		}

		policy.CredentialMapping[scheme.Scheme] = credentialRef
	}

	return policy, nil
}

func (wsm *DefaultWoTSecurityManager) GenerateProtocolAuth(ctx context.Context, schemes []types.WoTSecurityScheme, protocol string) (*types.ProtocolAuthConfig, error) {
	wsm.logger.WithFields(logrus.Fields{
		"protocol":     protocol,
		"scheme_count": len(schemes),
	}).Debug("Generating protocol authentication configuration")

	if len(schemes) == 0 {
		return &types.ProtocolAuthConfig{
			Protocol: protocol,
			Type:     "none",
			Config:   make(map[string]any),
		}, nil
	}

	// Use the first compatible scheme for the protocol
	for _, scheme := range schemes {
		if wsm.isSchemeCompatibleWithProtocol(scheme.Scheme, protocol) {
			return wsm.generateProtocolAuthForScheme(ctx, scheme, protocol)
		}
	}

	return nil, fmt.Errorf("no compatible security scheme found for protocol %s", protocol)
}

func (wsm *DefaultWoTSecurityManager) ValidateSecurityScheme(ctx context.Context, scheme types.WoTSecurityScheme) error {
	// Check if scheme is licensed
	switch scheme.Scheme {
	case "basic":
		if !wsm.licenseChecker.IsWoTFeatureEnabled(ctx, "basic_auth") {
			return fmt.Errorf("basic authentication not licensed")
		}
	case "bearer":
		if !wsm.licenseChecker.IsWoTFeatureEnabled(ctx, "bearer_auth") {
			return fmt.Errorf("bearer authentication not licensed")
		}
	case "apikey":
		if !wsm.licenseChecker.IsWoTFeatureEnabled(ctx, "api_key_auth") {
			return fmt.Errorf("API key authentication not licensed")
		}
	case "oauth2":
		if !wsm.licenseChecker.IsWoTFeatureEnabled(ctx, "oauth2_auth") {
			return fmt.Errorf("OAuth2 authentication not licensed")
		}
	case "psk":
		if !wsm.licenseChecker.IsWoTFeatureEnabled(ctx, "psk_auth") {
			return fmt.Errorf("PSK authentication not licensed")
		}
	case "cert":
		if !wsm.licenseChecker.IsWoTFeatureEnabled(ctx, "certificate_auth") {
			return fmt.Errorf("certificate authentication not licensed")
		}
	default:
		if !wsm.licenseChecker.IsWoTFeatureEnabled(ctx, "custom_auth") {
			return fmt.Errorf("custom authentication schemes not licensed")
		}
	}

	// Validate scheme configuration
	switch scheme.Scheme {
	case "apikey":
		if scheme.In == "" {
			return fmt.Errorf("apikey scheme requires 'in' field")
		}
		if scheme.Name_ == "" {
			return fmt.Errorf("apikey scheme requires 'name' field")
		}
	case "oauth2":
		if scheme.Flow == "" {
			return fmt.Errorf("oauth2 scheme requires 'flow' field")
		}
	}

	return nil
}

// Credential Store Management

func (wsm *DefaultWoTSecurityManager) RegisterCredentialStore(ctx context.Context, name string, store types.CredentialStore) error {
	// Check license for advanced credential stores
	switch store.Type {
	case "vault":
		if !wsm.licenseChecker.IsWoTFeatureEnabled(ctx, "vault_integration") {
			return fmt.Errorf("Vault integration not licensed")
		}
	case "kubernetes":
		if !wsm.licenseChecker.IsWoTFeatureEnabled(ctx, "k8s_secrets") {
			return fmt.Errorf("Kubernetes secrets not licensed")
		}
	}

	wsm.credentialStores[name] = store
	wsm.config.CredentialStores[name] = store

	wsm.logger.WithFields(logrus.Fields{
		"store_name": name,
		"store_type": store.Type,
	}).Info("Registered credential store")

	return nil
}

func (wsm *DefaultWoTSecurityManager) GetCredentialStore(ctx context.Context, name string) (*types.CredentialStore, error) {
	if store, exists := wsm.credentialStores[name]; exists {
		return &store, nil
	}
	return nil, fmt.Errorf("credential store %s not found", name)
}

func (wsm *DefaultWoTSecurityManager) ListCredentialStores(ctx context.Context) (map[string]types.CredentialStore, error) {
	return wsm.credentialStores, nil
}

func (wsm *DefaultWoTSecurityManager) GetCredentials(ctx context.Context, storeRef types.CredentialRef) (*types.DeviceCredentials, error) {
	store, err := wsm.GetCredentialStore(ctx, storeRef.Store)
	if err != nil {
		return nil, err
	}

	switch store.Type {
	case "env":
		return wsm.getCredentialsFromEnv(storeRef)
	case "db":
		return wsm.getCredentialsFromDB(ctx, storeRef)
	case "file":
		return wsm.getCredentialsFromFile(storeRef)
	default:
		return nil, fmt.Errorf("unsupported credential store type: %s", store.Type)
	}
}

func (wsm *DefaultWoTSecurityManager) SetCredentials(ctx context.Context, storeRef types.CredentialRef, credentials *types.DeviceCredentials) error {
	store, err := wsm.GetCredentialStore(ctx, storeRef.Store)
	if err != nil {
		return err
	}

	switch store.Type {
	case "db":
		return wsm.setCredentialsInDB(ctx, storeRef, credentials)
	case "file":
		return wsm.setCredentialsInFile(storeRef, credentials)
	default:
		return fmt.Errorf("credential store type %s does not support writing", store.Type)
	}
}

func (wsm *DefaultWoTSecurityManager) RotateCredentials(ctx context.Context, storeRef types.CredentialRef) error {
	if !wsm.licenseChecker.IsWoTFeatureEnabled(ctx, "credential_rotation") {
		return fmt.Errorf("credential rotation not licensed")
	}

	// TODO: Implement credential rotation logic
	return fmt.Errorf("credential rotation not implemented")
}

// Security Template Management

func (wsm *DefaultWoTSecurityManager) CreateSecurityTemplate(ctx context.Context, template types.SecurityTemplate) error {
	if !wsm.licenseChecker.IsWoTFeatureEnabled(ctx, "security_templates") {
		return fmt.Errorf("security templates not licensed")
	}

	wsm.config.SecurityTemplates[template.Name] = template

	// Store in database
	templateJSON, err := json.Marshal(template)
	if err != nil {
		return fmt.Errorf("failed to marshal template: %w", err)
	}

	_, err = wsm.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO security_templates (name, template_data, created_at)
		VALUES (?, ?, ?)
	`, template.Name, string(templateJSON), time.Now())

	return err
}

func (wsm *DefaultWoTSecurityManager) GetSecurityTemplate(ctx context.Context, name string) (*types.SecurityTemplate, error) {
	if template, exists := wsm.config.SecurityTemplates[name]; exists {
		return &template, nil
	}

	// Check database
	var templateJSON string
	err := wsm.db.QueryRowContext(ctx, `
		SELECT template_data FROM security_templates WHERE name = ?
	`, name).Scan(&templateJSON)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("security template %s not found", name)
	} else if err != nil {
		return nil, fmt.Errorf("failed to retrieve template: %w", err)
	}

	var template types.SecurityTemplate
	if err := json.Unmarshal([]byte(templateJSON), &template); err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}

	// Cache in memory
	wsm.config.SecurityTemplates[name] = template

	return &template, nil
}

func (wsm *DefaultWoTSecurityManager) ListSecurityTemplates(ctx context.Context) ([]types.SecurityTemplate, error) {
	var templates []types.SecurityTemplate

	// Add in-memory templates
	for _, template := range wsm.config.SecurityTemplates {
		templates = append(templates, template)
	}

	return templates, nil
}

func (wsm *DefaultWoTSecurityManager) ApplySecurityTemplate(ctx context.Context, thingID string, templateName string) error {
	template, err := wsm.GetSecurityTemplate(ctx, templateName)
	if err != nil {
		return fmt.Errorf("failed to get template: %w", err)
	}

	// Convert template to security policy
	policy := &types.ThingSecurityPolicy{
		ThingID:           thingID,
		RequiredSchemes:   make([]string, 0, len(template.Schemes)),
		CredentialMapping: make(map[string]types.CredentialRef),
		AccessControl:     template.Policies,
	}

	for _, scheme := range template.Schemes {
		policy.RequiredSchemes = append(policy.RequiredSchemes, scheme.Scheme)
	}

	// Copy credential mappings from template
	for scheme, credRef := range template.Credentials {
		// Customize credential reference for this Thing
		customRef := credRef
		customRef.Key = fmt.Sprintf("%s_%s", thingID, scheme)
		policy.CredentialMapping[scheme] = customRef
	}

	return wsm.SetThingSecurityPolicy(ctx, thingID, policy)
}

// Access Control

func (wsm *DefaultWoTSecurityManager) EvaluateAccess(ctx context.Context, accessCtx *types.WoTAccessContext) error {
	return wsm.ValidateThingAccess(ctx, accessCtx.ThingID, accessCtx.Operation, accessCtx)
}

func (wsm *DefaultWoTSecurityManager) LogSecurityEvent(ctx context.Context, event types.WoTSecurityEvent) error {
	wsm.logSecurityEvent(ctx, event)
	return nil
}

func (wsm *DefaultWoTSecurityManager) GetSecurityEvents(ctx context.Context, filters map[string]any) ([]types.WoTSecurityEvent, error) {
	// TODO: Implement security event retrieval from database
	return nil, fmt.Errorf("security event retrieval not implemented")
}

// Configuration Management

func (wsm *DefaultWoTSecurityManager) UpdateConfig(ctx context.Context, config types.WoTSecurityConfig) error {
	if err := wsm.ValidateConfig(ctx, config); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	wsm.config = &config

	wsm.logger.Info("WoT security configuration updated")
	return nil
}

func (wsm *DefaultWoTSecurityManager) GetConfig(ctx context.Context) (*types.WoTSecurityConfig, error) {
	return wsm.config, nil
}

func (wsm *DefaultWoTSecurityManager) ValidateConfig(ctx context.Context, config types.WoTSecurityConfig) error {
	// Validate license features for the configuration
	if config.GlobalPolicies != nil {
		if !wsm.licenseChecker.IsWoTFeatureEnabled(ctx, "global_policies") {
			return fmt.Errorf("global policies not licensed")
		}
	}

	// Validate credential stores
	for name, store := range config.CredentialStores {
		switch store.Type {
		case "vault":
			if !wsm.licenseChecker.IsWoTFeatureEnabled(ctx, "vault_integration") {
				return fmt.Errorf("Vault integration not licensed for store %s", name)
			}
		case "kubernetes":
			if !wsm.licenseChecker.IsWoTFeatureEnabled(ctx, "k8s_secrets") {
				return fmt.Errorf("Kubernetes secrets not licensed for store %s", name)
			}
		}
	}

	return nil
}

// Health and Monitoring

func (wsm *DefaultWoTSecurityManager) HealthCheck(ctx context.Context) error {
	// Check database connectivity
	if err := wsm.db.PingContext(ctx); err != nil {
		return fmt.Errorf("database connectivity failed: %w", err)
	}

	// Check license validity
	if !wsm.licenseChecker.IsLicenseValid(ctx) {
		return fmt.Errorf("license is invalid or expired")
	}

	return nil
}

func (wsm *DefaultWoTSecurityManager) GetSecurityMetrics(ctx context.Context) (map[string]any, error) {
	metrics := map[string]any{
		"thing_policies":     len(wsm.config.ThingPolicies),
		"credential_stores":  len(wsm.config.CredentialStores),
		"security_templates": len(wsm.config.SecurityTemplates),
		"license_valid":      wsm.licenseChecker.IsLicenseValid(ctx),
	}

	return metrics, nil
}

// Helper methods

func (wsm *DefaultWoTSecurityManager) evaluateAccessControl(ctx context.Context, accessControl *types.ThingAccessControl, accessCtx *types.WoTAccessContext) error {
	// Check allowed operations
	allowed := slices.Contains(accessControl.AllowedOperations, accessCtx.Operation)
	if !allowed {
		return fmt.Errorf("operation %s not allowed", accessCtx.Operation)
	}

	// Check IP whitelist
	if len(accessControl.IPWhitelist) > 0 {
		allowed = false
		clientIP := net.ParseIP(accessCtx.SourceIP)
		for _, allowedIP := range accessControl.IPWhitelist {
			if strings.Contains(allowedIP, "/") {
				// CIDR notation
				_, cidr, err := net.ParseCIDR(allowedIP)
				if err == nil && cidr.Contains(clientIP) {
					allowed = true
					break
				}
			} else {
				// Direct IP match
				if allowedIP == accessCtx.SourceIP {
					allowed = true
					break
				}
			}
		}
		if !allowed {
			return fmt.Errorf("IP address %s not in whitelist", accessCtx.SourceIP)
		}
	}

	// Check time restrictions
	if len(accessControl.TimeRestrictions) > 0 {
		if err := wsm.checkTimeRestrictions(accessControl.TimeRestrictions, accessCtx.Timestamp); err != nil {
			return err
		}
	}

	// Check rate limits
	if accessControl.RateLimit != nil {
		if err := wsm.checkRateLimit(accessCtx, accessControl.RateLimit); err != nil {
			return err
		}
	}

	return nil
}

func (wsm *DefaultWoTSecurityManager) evaluateGlobalPolicies(ctx context.Context, globalPolicies *types.GlobalWoTSecurityPolicy, accessCtx *types.WoTAccessContext) error {
	// Check blocked IPs
	if slices.Contains(globalPolicies.BlockedIPs, accessCtx.SourceIP) {
		return fmt.Errorf("IP address %s is blocked", accessCtx.SourceIP)
	}

	// Check allowed protocols
	if len(globalPolicies.AllowedProtocols) > 0 {
		allowed := slices.Contains(globalPolicies.AllowedProtocols, accessCtx.Protocol)
		if !allowed {
			return fmt.Errorf("protocol %s not allowed", accessCtx.Protocol)
		}
	}

	// Check global rate limit
	if globalPolicies.DefaultRateLimit != nil {
		if err := wsm.checkRateLimit(accessCtx, globalPolicies.DefaultRateLimit); err != nil {
			return err
		}
	}

	return nil
}

func (wsm *DefaultWoTSecurityManager) checkTimeRestrictions(restrictions []types.TimeRestriction, timestamp time.Time) error {
	// Check if current time falls within any allowed time window
	for _, restriction := range restrictions {
		if wsm.isTimeAllowed(restriction, timestamp) {
			return nil
		}
	}
	return fmt.Errorf("access not allowed at current time")
}

func (wsm *DefaultWoTSecurityManager) isTimeAllowed(restriction types.TimeRestriction, timestamp time.Time) bool {
	// Simple implementation - would need more sophisticated time handling in production
	weekday := strings.ToLower(timestamp.Weekday().String())

	// Check if current day is allowed
	for _, day := range restriction.Days {
		if day == weekday || day == "weekday" && timestamp.Weekday() >= time.Monday && timestamp.Weekday() <= time.Friday {
			// Check time range
			currentTime := timestamp.Format("15:04")
			if currentTime >= restriction.StartTime && currentTime <= restriction.EndTime {
				return true
			}
		}
	}

	return false
}

func (wsm *DefaultWoTSecurityManager) checkRateLimit(accessCtx *types.WoTAccessContext, rateLimit *types.WoTRateLimit) error {
	// TODO: Implement rate limiting logic with proper storage and counters
	wsm.logger.WithFields(logrus.Fields{
		"thing_id":   accessCtx.ThingID,
		"rate_limit": rateLimit.RequestsPerMinute,
	}).Debug("Rate limit check (not implemented)")

	return nil
}

func (wsm *DefaultWoTSecurityManager) isSchemeCompatibleWithProtocol(scheme, protocol string) bool {
	// Define compatibility matrix
	compatibility := map[string][]string{
		"http":  {"basic", "bearer", "apikey", "oauth2"},
		"https": {"basic", "bearer", "apikey", "oauth2", "cert"},
		"mqtt":  {"basic", "cert", "psk"},
		"mqtts": {"basic", "cert", "psk"},
		"kafka": {"basic", "oauth2", "cert"},
	}

	supportedSchemes, exists := compatibility[protocol]
	if !exists {
		return false
	}

	return slices.Contains(supportedSchemes, scheme)
}

func (wsm *DefaultWoTSecurityManager) generateProtocolAuthForScheme(ctx context.Context, scheme types.WoTSecurityScheme, protocol string) (*types.ProtocolAuthConfig, error) {
	switch protocol {
	case "http", "https":
		return wsm.generateHTTPAuth(scheme)
	case "mqtt", "mqtts":
		return wsm.generateMQTTAuth(scheme)
	case "kafka":
		return wsm.generateKafkaAuth(scheme)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

func (wsm *DefaultWoTSecurityManager) generateHTTPAuth(scheme types.WoTSecurityScheme) (*types.ProtocolAuthConfig, error) {
	config := &types.ProtocolAuthConfig{
		Protocol: "http",
		Type:     scheme.Scheme,
		Config:   make(map[string]any),
		Headers:  make(map[string]string),
	}

	switch scheme.Scheme {
	case "basic":
		config.Config["auth_type"] = "basic"
		config.Headers["Authorization"] = "${DEVICE_BASIC_AUTH}"
	case "bearer":
		config.Config["auth_type"] = "bearer"
		config.Headers["Authorization"] = "Bearer ${DEVICE_BEARER_TOKEN}"
	case "apikey":
		config.Config["auth_type"] = "apikey"
		if scheme.In == "header" {
			config.Headers[scheme.Name_] = "${DEVICE_API_KEY}"
		} else if scheme.In == "query" {
			config.Config["query_param"] = scheme.Name_
			config.Config["query_value"] = "${DEVICE_API_KEY}"
		}
	}

	return config, nil
}

func (wsm *DefaultWoTSecurityManager) generateMQTTAuth(scheme types.WoTSecurityScheme) (*types.ProtocolAuthConfig, error) {
	config := &types.ProtocolAuthConfig{
		Protocol:   "mqtt",
		Type:       scheme.Scheme,
		Config:     make(map[string]any),
		Properties: make(map[string]any),
	}

	switch scheme.Scheme {
	case "basic":
		config.Properties["username"] = "${DEVICE_MQTT_USERNAME}"
		config.Properties["password"] = "${DEVICE_MQTT_PASSWORD}"
	case "cert":
		config.Properties["tls"] = map[string]any{
			"cert_file": "${DEVICE_CERT_FILE}",
			"key_file":  "${DEVICE_KEY_FILE}",
			"ca_file":   "${DEVICE_CA_FILE}",
		}
	}

	return config, nil
}

func (wsm *DefaultWoTSecurityManager) generateKafkaAuth(scheme types.WoTSecurityScheme) (*types.ProtocolAuthConfig, error) {
	config := &types.ProtocolAuthConfig{
		Protocol:   "kafka",
		Type:       scheme.Scheme,
		Config:     make(map[string]any),
		Properties: make(map[string]any),
	}

	switch scheme.Scheme {
	case "basic":
		config.Properties["sasl"] = map[string]any{
			"mechanism": "PLAIN",
			"username":  "${DEVICE_KAFKA_USERNAME}",
			"password":  "${DEVICE_KAFKA_PASSWORD}",
		}
	case "oauth2":
		config.Properties["sasl"] = map[string]any{
			"mechanism":     "OAUTHBEARER",
			"client_id":     "${DEVICE_OAUTH_CLIENT_ID}",
			"client_secret": "${DEVICE_OAUTH_CLIENT_SECRET}",
			"token_url":     scheme.TokenURL,
		}
	}

	return config, nil
}

func (wsm *DefaultWoTSecurityManager) getCredentialsFromEnv(storeRef types.CredentialRef) (*types.DeviceCredentials, error) {
	// Map credential types to environment variable patterns
	envVars := map[string]map[string]string{
		"basic": {
			"username": storeRef.Key + "_USERNAME",
			"password": storeRef.Key + "_PASSWORD",
		},
		"bearer": {
			"token": storeRef.Key + "_TOKEN",
		},
		"apikey": {
			"api_key": storeRef.Key + "_API_KEY",
		},
	}

	vars, exists := envVars[storeRef.Type]
	if !exists {
		return nil, fmt.Errorf("unsupported credential type for env store: %s", storeRef.Type)
	}

	credentials := &types.DeviceCredentials{
		Type: storeRef.Type,
	}

	for field, envVar := range vars {
		value := os.Getenv(envVar)
		if value == "" {
			return nil, fmt.Errorf("environment variable %s not set", envVar)
		}

		switch field {
		case "username":
			credentials.Username = value
		case "password":
			credentials.Password = value
		case "token":
			credentials.Token = value
		case "api_key":
			credentials.APIKey = value
		}
	}

	return credentials, nil
}

func (wsm *DefaultWoTSecurityManager) getCredentialsFromDB(ctx context.Context, storeRef types.CredentialRef) (*types.DeviceCredentials, error) {
	var credentialsJSON string
	err := wsm.db.QueryRowContext(ctx, `
		SELECT credentials_data FROM device_credentials WHERE credential_key = ?
	`, storeRef.Key).Scan(&credentialsJSON)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("credentials not found for key %s", storeRef.Key)
	} else if err != nil {
		return nil, fmt.Errorf("failed to retrieve credentials: %w", err)
	}

	var credentials types.DeviceCredentials
	if err := json.Unmarshal([]byte(credentialsJSON), &credentials); err != nil {
		return nil, fmt.Errorf("failed to parse credentials: %w", err)
	}

	return &credentials, nil
}

func (wsm *DefaultWoTSecurityManager) getCredentialsFromFile(storeRef types.CredentialRef) (*types.DeviceCredentials, error) {
	// TODO: Implement file-based credential storage
	return nil, fmt.Errorf("file-based credential storage not implemented")
}

func (wsm *DefaultWoTSecurityManager) setCredentialsInDB(ctx context.Context, storeRef types.CredentialRef, credentials *types.DeviceCredentials) error {
	credentialsJSON, err := json.Marshal(credentials)
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	_, err = wsm.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO device_credentials (credential_key, credentials_data, created_at, updated_at)
		VALUES (?, ?, ?, ?)
	`, storeRef.Key, string(credentialsJSON), time.Now(), time.Now())

	return err
}

func (wsm *DefaultWoTSecurityManager) setCredentialsInFile(storeRef types.CredentialRef, credentials *types.DeviceCredentials) error {
	// TODO: Implement file-based credential storage
	return fmt.Errorf("file-based credential storage not implemented")
}

func (wsm *DefaultWoTSecurityManager) generateEventID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (wsm *DefaultWoTSecurityManager) logSecurityEvent(ctx context.Context, event types.WoTSecurityEvent) {
	event.ID = wsm.generateEventID()
	event.Timestamp = time.Now()

	// Log to structured logger
	wsm.logger.WithFields(logrus.Fields{
		"wot_security_event_id": event.ID,
		"thing_id":              event.ThingID,
		"operation":             event.Operation,
		"resource":              event.Resource,
		"protocol":              event.Protocol,
		"success":               event.Success,
		"error":                 event.Error,
		"source_ip":             event.SourceIP,
		"credentials":           event.Credentials,
	}).Info("WoT security event")

	// TODO: Store in audit log table for persistence
}

// Ensure interface compliance
var _ types.WoTSecurityManager = (*DefaultWoTSecurityManager)(nil)
