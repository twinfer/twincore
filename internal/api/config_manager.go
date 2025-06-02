package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/types"
)

// Ensure ConfigManager implements ConfigurationManager interface
var _ ConfigurationManager = (*ConfigManager)(nil)

// ConfigManager provides a unified API for managing all TwinCore configurations
// It wraps Caddy Admin API and other service configurations
type ConfigManager struct {
	caddyAdminURL string
	dbPath        string
	logger        logrus.FieldLogger

	// First-time setup tracking
	setupComplete bool
	setupMu       sync.RWMutex

	// Configuration templates
	authTemplates map[string]interface{}
}

// NewConfigManager creates a new configuration manager
func NewConfigManager(logger logrus.FieldLogger) *ConfigManager {
	return &ConfigManager{
		caddyAdminURL: "http://localhost:2019",
		logger:        logger,
		authTemplates: loadAuthTemplates(),
	}
}

// RemoveThingRoutes removes Caddy routes associated with a specific Thing.
// TODO: Implement the logic to find and remove Caddy routes.
func (cm *ConfigManager) RemoveThingRoutes(logger logrus.FieldLogger, thingID string) error {
	entryLogger := logger.WithFields(logrus.Fields{
		"service_method": "RemoveThingRoutes",
		"thing_id":       thingID,
	})
	entryLogger.Info("Attempting to remove Caddy routes for Thing")

	// TODO: Implement the logic to find and remove Caddy routes.
	// This is a complex operation and requires careful manipulation of Caddy's JSON config.
	// For now, this function is a placeholder.
	// Example steps:
	// 1. Fetch current Caddy config: currentConfig, err := cm.getCaddyConfig(logger, "/config")
	//    If err, return &ErrCaddyAdminAPIAccess{WrappedErr: err, URL: cm.caddyAdminURL + "/config", HTTPMethod: "GET"}
	// 2. Navigate to http server routes: e.g., currentConfig["apps"]["http"]["servers"]["srv0"]["routes"]
	// 3. Iterate and filter routes: remove routes matching thingID. This needs a robust way to identify these routes.
	//    If a route to be removed is not found, this might be okay or an ErrCaddyResourceNotFound.
	// 4. Update Caddy config: err = cm.updateCaddyConfig(logger, "/config", currentConfig)
	//    If err, it could be ErrCaddyAdminAPIAccess or ErrCaddyConfigLoadFailed depending on the cause.

	entryLogger.Warn("RemoveThingRoutes is not fully implemented. Placeholder success.")
	// Simulate not finding any routes for this thingID to avoid accidental success logging for an empty operation.
	// return &ErrCaddyResourceNotFound{ResourceType: "route", ResourceID: thingID, CaddyPath: "/config/apps/http/servers/srv0/routes"}
	return nil // Returning nil for now to avoid breaking existing flows.
}

// AddRoute adds a new HTTP route to the Caddy configuration
func (cm *ConfigManager) AddRoute(ctx context.Context, routeID string, route types.HTTPRoute) error {
	cm.logger.WithFields(logrus.Fields{
		"service_method": "AddRoute",
		"route_id":       routeID,
		"path":           route.Path,
	}).Info("Adding HTTP route to Caddy configuration")

	// TODO: Implement the logic to add the route to Caddy's configuration
	// This is a complex operation and requires careful manipulation of Caddy's JSON config.
	// For now, this function is a placeholder.
	// Example steps:
	// 1. Fetch current Caddy config: currentConfig, err := cm.getCaddyConfig(cm.logger, "/config")
	// 2. Navigate to http server routes: e.g., currentConfig["apps"]["http"]["servers"]["srv0"]["routes"]
	// 3. Add the new route in the appropriate format
	// 4. Update Caddy config: err = cm.updateCaddyConfig(cm.logger, "/config", currentConfig)

	cm.logger.WithFields(logrus.Fields{
		"route_id": routeID,
		"path":     route.Path,
	}).Warn("AddRoute is not fully implemented. Placeholder success.")
	
	return nil // Returning nil for now to avoid breaking existing flows.
}

// IsSetupComplete checks if initial setup has been completed
func (cm *ConfigManager) IsSetupComplete() bool {
	cm.setupMu.RLock()
	defer cm.setupMu.RUnlock()
	return cm.setupComplete
}

// CompleteSetup marks the initial setup as complete
func (cm *ConfigManager) CompleteSetup(logger logrus.FieldLogger) error {
	entryLogger := logger.WithFields(logrus.Fields{"service_method": "CompleteSetup"})
	entryLogger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	cm.setupMu.Lock()
	defer cm.setupMu.Unlock()

	// Save setup completion to database
	logger.WithFields(logrus.Fields{"dependency_name": "self", "operation": "saveSetupStatus"}).Debug("Calling dependency")
	if err := cm.saveSetupStatus(true); err != nil { // Assuming saveSetupStatus is internal and uses cm.logger or passed logger
		logger.WithError(err).Error("Failed to save setup status")
		return err
	}

	cm.setupComplete = true
	logger.Info("Initial setup marked as complete")
	return nil
}

// GetAuthProviders returns available authentication providers based on license
func (cm *ConfigManager) GetAuthProviders(license License) []AuthProviderInfo {
	providers := []AuthProviderInfo{
		{
			ID:          "local",
			Name:        "Local Users",
			Description: "Built-in user database",
			Available:   true,
		},
		{
			ID:          "jwt",
			Name:        "JWT Token",
			Description: "JSON Web Token validation",
			Available:   license.HasFeature("jwt_auth"),
		},
		{
			ID:          "saml",
			Name:        "SAML 2.0",
			Description: "Enterprise Single Sign-On",
			Available:   license.HasFeature("enterprise_auth"),
		},
		{
			ID:          "oauth2",
			Name:        "OAuth 2.0 / OIDC",
			Description: "OAuth2 and OpenID Connect",
			Available:   license.HasFeature("enterprise_auth"),
		},
		{
			ID:          "ldap",
			Name:        "LDAP / Active Directory",
			Description: "Corporate directory integration",
			Available:   license.HasFeature("enterprise_auth"),
		},
	}

	return providers
}

// ConfigureAuth configures authentication based on user selection
func (cm *ConfigManager) ConfigureAuth(logger logrus.FieldLogger, req AuthConfigRequest) error {
	entryLogger := logger.WithFields(logrus.Fields{"service_method": "ConfigureAuth", "provider": req.Provider})
	entryLogger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	// Validate provider is available
	if !cm.isProviderAvailable(req.Provider, req.License) {
		err := fmt.Errorf("authentication provider %s not available with current license", req.Provider)
		logger.WithError(err).Warn("Auth provider availability check failed")
		return err
	}
	logger.Debug("Auth provider is available")

	// Build Caddy security configuration
	logger.Debug("Building Caddy security configuration")
	securityConfig := cm.buildSecurityConfig(req) // Assuming this is a pure function or uses its own logging if needed

	// Apply to Caddy
	logger.WithFields(logrus.Fields{"dependency_name": "CaddyAdminAPI", "operation": "updateCaddyConfig", "path": "/apps/security"}).Debug("Calling dependency")
	if err := cm.updateCaddyConfig(logger, "/apps/security", securityConfig); err != nil {
		logger.WithError(err).Error("Failed to update Caddy security config")
		return fmt.Errorf("failed to update security config: %w", err)
	}
	logger.Info("Caddy security config updated")

	// Update HTTP routes to use authentication
	logger.WithFields(logrus.Fields{"dependency_name": "self", "operation": "updateHTTPRoutes"}).Debug("Calling internal method to update HTTP routes")
	if err := cm.updateHTTPRoutes(logger, req.Provider); err != nil {
		logger.WithError(err).Error("Failed to update HTTP routes for auth")
		return fmt.Errorf("failed to update HTTP routes: %w", err)
	}
	logger.Info("HTTP routes updated for new auth provider")

	return nil
}

// buildSecurityConfig builds caddy-security configuration
func (cm *ConfigManager) buildSecurityConfig(req AuthConfigRequest) map[string]interface{} {
	config := map[string]interface{}{
		"authentication": map[string]interface{}{
			"portals": []map[string]interface{}{
				{
					"name": "twincore_portal",
					"ui": map[string]interface{}{
						"theme":            "basic",
						"logo_url":         "/portal/assets/logo.png",
						"logo_description": "TwinCore Gateway",
					},
				},
			},
		},
	}

	// Configure based on provider
	switch req.Provider {
	case "local":
		config["authentication"].(map[string]interface{})["portals"].([]map[string]interface{})[0]["backends"] = []map[string]interface{}{
			{
				"method": "local",
				"name":   "local_backend",
				"file":   "/etc/twincore/users.json",
			},
		}

	case "saml":
		config["authentication"].(map[string]interface{})["portals"].([]map[string]interface{})[0]["backends"] = []map[string]interface{}{
			{
				"method":       "saml",
				"name":         "saml_backend",
				"metadata_url": req.Config["metadata_url"],
				"entity_id":    req.Config["entity_id"],
				"acs_url":      req.Config["acs_url"],
			},
		}

	case "oauth2":
		config["authentication"].(map[string]interface{})["portals"].([]map[string]interface{})[0]["backends"] = []map[string]interface{}{
			{
				"method":        "oauth2",
				"name":          "oauth2_backend",
				"provider":      req.Config["provider"], // google, github, generic
				"client_id":     req.Config["client_id"],
				"client_secret": req.Config["client_secret"],
				"redirect_url":  req.Config["redirect_url"],
			},
		}

	case "ldap":
		config["authentication"].(map[string]interface{})["portals"].([]map[string]interface{})[0]["backends"] = []map[string]interface{}{
			{
				"method":        "ldap",
				"name":          "ldap_backend",
				"server":        req.Config["server"],
				"base_dn":       req.Config["base_dn"],
				"bind_dn":       req.Config["bind_dn"],
				"bind_password": req.Config["bind_password"],
			},
		}
	}

	return config
}

// updateHTTPRoutes updates HTTP routes to use authentication
func (cm *ConfigManager) updateHTTPRoutes(logger logrus.FieldLogger, provider string) error {
	entryLogger := logger.WithFields(logrus.Fields{"service_method": "updateHTTPRoutes", "provider": provider})
	entryLogger.Debug("Service method called (internal)")
	startTime := time.Now()
	defer func() {
		entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished (internal)")
	}()

	// Get current HTTP config
	logger.WithFields(logrus.Fields{"dependency_name": "CaddyAdminAPI", "operation": "getCaddyConfig", "path": "/apps/http"}).Debug("Calling dependency")
	httpConfig, err := cm.getCaddyConfig(logger, "/apps/http")
	if err != nil {
		logger.WithError(err).Error("Failed to get current Caddy HTTP config")
		return err
	}
	logger.Debug("Successfully retrieved current Caddy HTTP config")

	// Add authentication middleware to protected routes
	routes := []map[string]interface{}{
		// Portal route (public)
		{
			"match": []map[string]interface{}{
				{"path": []string{"/portal/*"}},
			},
			"handle": []map[string]interface{}{
				{
					"handler":      "file_server",
					"root":         "{http.vars.portal_root}",
					"strip_prefix": "/portal",
				},
			},
		},
		// Setup route (public during setup)
		{
			"match": []map[string]interface{}{
				{"path": []string{"/setup/*"}},
			},
			"handle": []map[string]interface{}{
				{
					"handler": "subroute",
					"routes":  cm.buildSetupRoutes(),
				},
			},
		},
		// API routes (protected)
		{
			"match": []map[string]interface{}{
				{"path": []string{"/api/*"}},
			},
			"handle": []map[string]interface{}{
				{
					"handler":     "authenticator",
					"portal_name": "twincore_portal",
				},
				{
					"handler": "reverse_proxy",
					"upstreams": []map[string]interface{}{
						{"dial": "localhost:8090"},
					},
				},
			},
		},
		// WoT routes (configurable protection)
		{
			"match": []map[string]interface{}{
				{"path": []string{"/things/*"}},
			},
			"handle": cm.buildWoTHandlers(provider),
		},
	}

	// Update routes
	httpConfig["servers"].(map[string]interface{})["srv0"].(map[string]interface{})["routes"] = routes
	logger.Debug("Constructed new HTTP routes with auth")

	logger.WithFields(logrus.Fields{"dependency_name": "CaddyAdminAPI", "operation": "updateCaddyConfig", "path": "/apps/http"}).Debug("Calling dependency to apply updated HTTP config")
	return cm.updateCaddyConfig(logger, "/apps/http", httpConfig)
}

// Portal API endpoints

// GetConfiguration returns the current configuration
func (cm *ConfigManager) GetConfiguration(logger logrus.FieldLogger) (map[string]interface{}, error) {
	entryLogger := logger.WithFields(logrus.Fields{"service_method": "GetConfiguration"})
	entryLogger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	config := make(map[string]interface{})

	// Get Caddy config
	logger.WithFields(logrus.Fields{"dependency_name": "CaddyAdminAPI", "operation": "getCaddyConfig", "path": "/config"}).Debug("Calling dependency")
	caddyConfig, err := cm.getCaddyConfig(logger, "/config")
	if err != nil {
		logger.WithError(err).Error("Failed to get full Caddy config")
		return nil, err
	}

	// Extract relevant parts
	config["http"] = cm.extractHTTPConfig(caddyConfig)         // Assuming pure function or self-logged if complex
	config["security"] = cm.extractSecurityConfig(caddyConfig) // Assuming pure function
	config["streams"] = cm.getStreamConfig()                   // Assuming pure function or self-logged

	logger.Debug("Successfully retrieved and processed configuration")
	return config, nil
}

// UpdateConfiguration updates configuration sections
func (cm *ConfigManager) UpdateConfiguration(logger logrus.FieldLogger, section string, config map[string]interface{}) error {
	entryLogger := logger.WithFields(logrus.Fields{"service_method": "UpdateConfiguration", "section": section})
	entryLogger.Debug("Service method called")
	startTime := time.Now()
	defer func() {
		entryLogger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Service method finished")
	}()

	logger = logger.WithField("config_section", section)

	switch section {
	case "http":
		logger.Info("Updating HTTP configuration")
		return cm.updateHTTPConfig(logger, config)
	case "security":
		logger.Info("Updating security configuration")
		return cm.updateSecurityConfig(logger, config)
	case "streams":
		logger.Info("Updating streams configuration")
		return cm.updateStreamConfig(logger, config) // Assuming updateStreamConfig will be updated to use logger
	default:
		err := fmt.Errorf("unknown configuration section: %s", section)
		logger.WithError(err).Error("Attempt to update unknown configuration section")
		return err
	}
}

// Helper methods

func (cm *ConfigManager) updateCaddyConfig(logger logrus.FieldLogger, path string, config interface{}) error {
	data, err := json.Marshal(config)
	if err != nil {
		logger.WithError(err).Error("Failed to marshal Caddy config for update")
		return fmt.Errorf("failed to marshal config to JSON: %w", err) // Should not happen with valid input
	}

	req, err := http.NewRequest(http.MethodPut, cm.caddyAdminURL+path, bytes.NewReader(data))
	if err != nil {
		logger.WithError(err).Error("Failed to create new HTTP request for Caddy admin API")
		// This is an internal error, not a Caddy API access error yet.
		return fmt.Errorf("failed to create HTTP request for Caddy: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	logger.WithFields(logrus.Fields{"caddy_path": path, "http_method": "PUT"}).Debug("Sending request to Caddy admin API")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.WithError(err).Error("Caddy admin API request failed")
		return &ErrCaddyAdminAPIAccess{URL: req.URL.String(), HTTPMethod: http.MethodPut, WrappedErr: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, readErr := io.ReadAll(resp.Body)
		var bodyStr string
		if readErr == nil {
			bodyStr = string(bodyBytes)
		} else {
			bodyStr = "could not read error response body"
		}

		errWrapped := fmt.Errorf("caddy admin API error (%d): %s", resp.StatusCode, bodyStr)
		logger.WithError(errWrapped).WithField("caddy_response_body", bodyStr).Error("Caddy admin API returned error status")

		if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnprocessableEntity {
			return &ErrCaddyConfigLoadFailed{CaddyPath: path, WrappedErr: errWrapped}
		}
		return &ErrCaddyConfigOperationFailed{CaddyPath: path, StatusCode: resp.StatusCode, WrappedErr: errWrapped}
	}
	logger.WithFields(logrus.Fields{"caddy_path": path, "status_code": resp.StatusCode}).Info("Caddy config updated successfully via admin API")
	return nil
}

func (cm *ConfigManager) getCaddyConfig(logger logrus.FieldLogger, path string) (map[string]interface{}, error) {
	targetURL := cm.caddyAdminURL + path
	logger.WithFields(logrus.Fields{"caddy_path": path, "http_method": "GET", "url": targetURL}).Debug("Sending request to Caddy admin API to get config")
	resp, err := http.Get(targetURL)
	if err != nil {
		logger.WithError(err).Error("Caddy admin API request failed (GET)")
		return nil, &ErrCaddyAdminAPIAccess{URL: targetURL, HTTPMethod: http.MethodGet, WrappedErr: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, readErr := io.ReadAll(resp.Body)
		var bodyStr string
		if readErr == nil {
			bodyStr = string(bodyBytes)
		} else {
			bodyStr = "could not read error response body"
		}
		errWrapped := fmt.Errorf("caddy admin API error (%d) getting config: %s", resp.StatusCode, bodyStr)
		logger.WithError(errWrapped).WithField("caddy_response_body", bodyStr).Error("Caddy admin API returned error status (GET)")

		if resp.StatusCode == http.StatusNotFound {
			return nil, &ErrCaddyResourceNotFound{CaddyPath: path, WrappedErr: errWrapped, ResourceType: "config_path"}
		}
		return nil, &ErrCaddyConfigOperationFailed{CaddyPath: path, StatusCode: resp.StatusCode, WrappedErr: errWrapped}
	}

	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		logger.WithError(err).Error("Failed to decode Caddy config JSON response")
		return nil, fmt.Errorf("failed to decode Caddy config JSON from %s: %w", path, err)
	}
	logger.WithField("caddy_path", path).Debug("Successfully retrieved Caddy config")
	return config, nil
}

// Types

type AuthProviderInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Available   bool   `json:"available"`
	Configured  bool   `json:"configured"`
}

type AuthConfigRequest struct {
	Provider string                 `json:"provider"`
	Config   map[string]interface{} `json:"config"`
	License  License                `json:"-"` // License interface is now in interfaces.go
}

// Missing helper methods

func (cm *ConfigManager) saveSetupStatus(complete bool) error { // Assuming this is internal or uses cm.logger
	// Save to database - simplified for now
	cm.logger.WithField("status", complete).Info("Saving setup status")
	return nil
}

func (cm *ConfigManager) isProviderAvailable(provider string, license License) bool { // Pure function, no logger needed
	switch provider {
	case "local":
		return true
	case "jwt":
		return license.HasFeature("jwt_auth")
	case "saml", "oauth2", "ldap":
		return license.HasFeature("enterprise_auth")
	default:
		return false
	}
}

func (cm *ConfigManager) buildSetupRoutes() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"match": []map[string]interface{}{
				{"path": []string{"/*"}},
			},
			"handle": []map[string]interface{}{
				{
					"handler": "static_response",
					"body":    `{"message": "Setup interface - Portal UI will be embedded here"}`,
					"headers": map[string][]string{
						"Content-Type": {"application/json"},
					},
				},
			},
		},
	}
}

func (cm *ConfigManager) buildWoTHandlers(provider string) []map[string]interface{} { // Pure function
	handlers := []map[string]interface{}{
		{
			"handler": "wot_handler", // Our custom WoT handler from caddy_app
		},
	}

	// Add auth if configured
	if provider != "" && provider != "local" {
		// Prepend auth handler
		authHandler := map[string]interface{}{
			"handler":     "authenticator",
			"portal_name": "twincore_portal",
		}
		handlers = append([]map[string]interface{}{authHandler}, handlers...)
	}

	return handlers
}

func (cm *ConfigManager) extractHTTPConfig(caddyConfig map[string]interface{}) map[string]interface{} { // Pure function
	if apps, ok := caddyConfig["apps"].(map[string]interface{}); ok {
		if http, ok := apps["http"].(map[string]interface{}); ok {
			return http
		}
	}
	return map[string]interface{}{}
}

func (cm *ConfigManager) extractSecurityConfig(caddyConfig map[string]interface{}) map[string]interface{} { // Pure function
	if apps, ok := caddyConfig["apps"].(map[string]interface{}); ok {
		if security, ok := apps["security"].(map[string]interface{}); ok {
			return security
		}
	}
	return map[string]interface{}{}
}

func (cm *ConfigManager) getStreamConfig() map[string]interface{} { // Pure function for this example (would log if it did I/O)
	// Get stream configuration from database or other source
	return map[string]interface{}{
		"streams": []interface{}{},
	}
}

func (cm *ConfigManager) updateHTTPConfig(logger logrus.FieldLogger, config map[string]interface{}) error {
	logger.Info("Applying HTTP configuration to Caddy")
	return cm.updateCaddyConfig(logger, "/apps/http", config)
}

func (cm *ConfigManager) updateSecurityConfig(logger logrus.FieldLogger, config map[string]interface{}) error {
	logger.Info("Applying security configuration to Caddy")
	return cm.updateCaddyConfig(logger, "/apps/security", config)
}

func (cm *ConfigManager) updateStreamConfig(logger logrus.FieldLogger, config map[string]interface{}) error {
	// Update stream configuration in database
	logger.Info("Stream config updated (mock - no actual DB interaction here)")
	// In a real scenario:
	// logger.WithFields(logrus.Fields{"dependency_name": "Database", "operation": "SaveStreamConfig"}).Debug("Calling dependency")
	// err := cm.db.SaveStreamConfig(config)
	// if err != nil {
	//    logger.WithError(err).Error("Failed to save stream config to DB")
	//    return err
	// }
	return nil
}

// Load default auth templates
func loadAuthTemplates() map[string]interface{} {
	// These would be loaded from embedded configs
	return map[string]interface{}{
		"local": map[string]interface{}{
			"users_file": "/etc/twincore/users.json",
		},
		"saml": map[string]interface{}{
			"template": "saml_template.json",
		},
	}
}
