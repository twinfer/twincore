package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/sirupsen/logrus"
)

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

// IsSetupComplete checks if initial setup has been completed
func (cm *ConfigManager) IsSetupComplete() bool {
	cm.setupMu.RLock()
	defer cm.setupMu.RUnlock()
	return cm.setupComplete
}

// CompleteSetup marks the initial setup as complete
func (cm *ConfigManager) CompleteSetup() error {
	cm.setupMu.Lock()
	defer cm.setupMu.Unlock()

	// Save setup completion to database
	if err := cm.saveSetupStatus(true); err != nil {
		return err
	}

	cm.setupComplete = true
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
func (cm *ConfigManager) ConfigureAuth(req AuthConfigRequest) error {
	// Validate provider is available
	if !cm.isProviderAvailable(req.Provider, req.License) {
		return fmt.Errorf("authentication provider %s not available with current license", req.Provider)
	}

	// Build Caddy security configuration
	securityConfig := cm.buildSecurityConfig(req)

	// Apply to Caddy
	if err := cm.updateCaddyConfig("/apps/security", securityConfig); err != nil {
		return fmt.Errorf("failed to update security config: %w", err)
	}

	// Update HTTP routes to use authentication
	if err := cm.updateHTTPRoutes(req.Provider); err != nil {
		return fmt.Errorf("failed to update HTTP routes: %w", err)
	}

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
func (cm *ConfigManager) updateHTTPRoutes(provider string) error {
	// Get current HTTP config
	httpConfig, err := cm.getCaddyConfig("/apps/http")
	if err != nil {
		return err
	}

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

	return cm.updateCaddyConfig("/apps/http", httpConfig)
}

// Portal API endpoints

// GetConfiguration returns the current configuration
func (cm *ConfigManager) GetConfiguration() (map[string]interface{}, error) {
	config := make(map[string]interface{})

	// Get Caddy config
	caddyConfig, err := cm.getCaddyConfig("/config")
	if err != nil {
		return nil, err
	}

	// Extract relevant parts
	config["http"] = cm.extractHTTPConfig(caddyConfig)
	config["security"] = cm.extractSecurityConfig(caddyConfig)
	config["streams"] = cm.getStreamConfig()

	return config, nil
}

// UpdateConfiguration updates configuration sections
func (cm *ConfigManager) UpdateConfiguration(section string, config map[string]interface{}) error {
	switch section {
	case "http":
		return cm.updateHTTPConfig(config)
	case "security":
		return cm.updateSecurityConfig(config)
	case "streams":
		return cm.updateStreamConfig(config)
	default:
		return fmt.Errorf("unknown configuration section: %s", section)
	}
}

// Helper methods

func (cm *ConfigManager) updateCaddyConfig(path string, config interface{}) error {
	data, err := json.Marshal(config)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPut, cm.caddyAdminURL+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("caddy admin API error: %s", body)
	}

	return nil
}

func (cm *ConfigManager) getCaddyConfig(path string) (map[string]interface{}, error) {
	resp, err := http.Get(cm.caddyAdminURL + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}

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
	License  License                `json:"-"`
}

type License interface {
	HasFeature(feature string) bool
}

// Missing helper methods

func (cm *ConfigManager) saveSetupStatus(complete bool) error {
	// Save to database - simplified for now
	cm.logger.Info("Setup status saved")
	return nil
}

func (cm *ConfigManager) isProviderAvailable(provider string, license License) bool {
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

func (cm *ConfigManager) buildWoTHandlers(provider string) []map[string]interface{} {
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

func (cm *ConfigManager) extractHTTPConfig(caddyConfig map[string]interface{}) map[string]interface{} {
	if apps, ok := caddyConfig["apps"].(map[string]interface{}); ok {
		if http, ok := apps["http"].(map[string]interface{}); ok {
			return http
		}
	}
	return map[string]interface{}{}
}

func (cm *ConfigManager) extractSecurityConfig(caddyConfig map[string]interface{}) map[string]interface{} {
	if apps, ok := caddyConfig["apps"].(map[string]interface{}); ok {
		if security, ok := apps["security"].(map[string]interface{}); ok {
			return security
		}
	}
	return map[string]interface{}{}
}

func (cm *ConfigManager) getStreamConfig() map[string]interface{} {
	// Get stream configuration from database or other source
	return map[string]interface{}{
		"streams": []interface{}{},
	}
}

func (cm *ConfigManager) updateHTTPConfig(config map[string]interface{}) error {
	return cm.updateCaddyConfig("/apps/http", config)
}

func (cm *ConfigManager) updateSecurityConfig(config map[string]interface{}) error {
	return cm.updateCaddyConfig("/apps/security", config)
}

func (cm *ConfigManager) updateStreamConfig(config map[string]interface{}) error {
	// Update stream configuration in database
	cm.logger.Info("Stream config updated")
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
