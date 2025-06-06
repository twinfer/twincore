// internal/container/container.go
package container

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	"github.com/redpanda-data/benthos/v4/public/service"
	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/api"
	"github.com/twinfer/twincore/internal/config"
	"github.com/twinfer/twincore/internal/database"
	"github.com/twinfer/twincore/internal/database/repositories"
	"github.com/twinfer/twincore/internal/security"
	"github.com/twinfer/twincore/pkg/license"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
	"github.com/twinfer/twincore/pkg/wot/forms"

	svc "github.com/twinfer/twincore/service"
)

// Container holds all application dependencies
type Container struct {
	// Core components
	DatabaseFactory *database.DatabaseFactory
	Logger          *logrus.Logger

	// Security
	DeviceManager         *security.DeviceManager
	LicenseManager        types.LicenseManager // Legacy - to be removed
	UnifiedLicenseChecker types.UnifiedLicenseChecker
	SystemSecurityManager types.SystemSecurityManager
	WoTSecurityManager    types.WoTSecurityManager

	// Configuration
	ConfigManager    *config.ConfigManager
	ConfigurationMgr api.ConfigurationManager // API configuration manager
	ThingRegistry    *config.ThingRegistry

	// Services
	ServiceRegistry types.ServiceRegistry
	HTTPService     types.Service
	StreamService   types.Service
	WoTService      types.Service

	// WoT Components
	StateManager      api.StateManager
	StreamBridge      api.StreamBridge
	EventBroker       *api.EventBroker
	UnifiedWoTHandler *api.UnifiedWoTHandler

	// Stream Composition Components
	BenthosStreamManager api.BenthosStreamManager
	TDStreamComposition  api.TDStreamCompositionService
	ThingRegistrationSvc api.ThingRegistrationService

	// Benthos
	// StreamBuilder *service.StreamBuilder // Replaced by BenthosEnvironment
	BenthosEnvironment *service.Environment // Benthos v4 environment

	// WoT Binding Generation
	BindingGenerator api.BindingGenerationService

	// Initial configurations used to start services
	InitialHTTPServiceConfig   types.ServiceConfig
	InitialStreamServiceConfig types.ServiceConfig
}

// New creates a new dependency container
func New(ctx context.Context, cfg *Config) (*Container, error) {
	c := &Container{}

	// Initialize logger
	c.Logger = logrus.New()
	c.Logger.SetLevel(logrus.DebugLevel)
	c.Logger.Info("Initializing TwinEdge Gateway")

	// Initialize database
	if err := c.initDatabase(cfg.DBPath); err != nil {
		return nil, fmt.Errorf("failed to init database: %w", err)
	}

	// Initialize security components
	if err := c.initSecurity(cfg); err != nil {
		return nil, fmt.Errorf("failed to init security: %w", err)
	}

	// Initialize configuration components
	if err := c.initConfiguration(cfg); err != nil {
		return nil, fmt.Errorf("failed to init configuration: %w", err)
	}

	// Initialize WoT components
	if err := c.initWoTComponents(cfg); err != nil { // Pass cfg for ParquetLogPath
		return nil, fmt.Errorf("failed to init WoT components: %w", err)
	}

	// Initialize services
	if err := c.initServices(cfg); err != nil { // Pass cfg for consistency
		return nil, fmt.Errorf("failed to init services: %w", err)
	}

	// Wire up dependencies
	if err := c.wireDependencies(cfg); err != nil { // Pass cfg for ParquetLogPath
		return nil, fmt.Errorf("failed to wire dependencies: %w", err)
	}

	// Define initial service configurations (can be loaded from cfg or defaults)
	// This is where global security settings for HTTP would be defined.
	c.InitialHTTPServiceConfig = c.buildInitialHTTPServiceConfig(cfg)
	c.InitialStreamServiceConfig = c.buildInitialStreamServiceConfig(cfg)

	c.Logger.Info("Container initialization complete")
	return c, nil
}

func (c *Container) initDatabase(dbPath string) error {
	c.Logger.Debug("Initializing database factory")

	// Create database factory with auto-migration enabled
	config := database.DatabaseConfig{
		DBPath:      dbPath,
		AutoMigrate: true,
	}

	factory, err := database.NewDatabaseFactoryWithConfig(config, c.Logger)
	if err != nil {
		return fmt.Errorf("failed to create database factory: %w", err)
	}

	c.DatabaseFactory = factory
	c.Logger.Info("Database factory initialized with migrations")
	return nil
}

func (c *Container) initSecurity(cfg *Config) error {
	c.Logger.Debug("Initializing separated security components")

	// Initialize unified license checker
	unifiedChecker := license.NewDefaultUnifiedLicenseChecker(c.Logger, cfg.PublicKey)
	c.UnifiedLicenseChecker = unifiedChecker

	// Load and validate license if provided
	if cfg.LicensePath != "" {
		licenseData, err := os.ReadFile(cfg.LicensePath)
		if err != nil {
			c.Logger.WithError(err).Warn("Failed to read license file, using basic tier")
		} else {
			if _, err := unifiedChecker.ValidateLicense(context.Background(), string(licenseData)); err != nil {
				c.Logger.WithError(err).Warn("Failed to validate license, using basic tier")
			} else {
				c.Logger.Info("License validated successfully")
			}
		}
	}

	// Initialize system security manager for caddy-auth-portal integration
	dbManager := c.DatabaseFactory.GetManager()
	securityRepo := repositories.NewSecurityRepository(dbManager, c.Logger)
	authProviderRepo := repositories.NewAuthProviderRepository(dbManager.GetConnection(), c.Logger)

	systemSecurityMgr := security.NewSystemSecurityManager(securityRepo, authProviderRepo, c.Logger, unifiedChecker)
	c.SystemSecurityManager = systemSecurityMgr

	// Initialize WoT security manager
	wotSecurityMgr := security.NewDefaultWoTSecurityManager(securityRepo, c.Logger, unifiedChecker)
	c.WoTSecurityManager = wotSecurityMgr

	// Register default credential stores for WoT security
	envStore := types.CredentialStore{
		Type:      "env",
		Encrypted: false,
		Config:    make(map[string]any),
	}
	if err := wotSecurityMgr.RegisterCredentialStore(context.Background(), "default", envStore); err != nil {
		c.Logger.WithError(err).Warn("Failed to register default credential store")
	}

	dbStore := types.CredentialStore{
		Type:      "db",
		Encrypted: true,
		Config:    make(map[string]any),
	}
	if err := wotSecurityMgr.RegisterCredentialStore(context.Background(), "db", dbStore); err != nil {
		c.Logger.WithError(err).Warn("Failed to register database credential store")
	}

	// Legacy components for backward compatibility (to be removed in future)
	// Initialize simplified license checker for legacy components
	simpleLicenseChecker, err := license.NewSimpleLicenseChecker(cfg.LicensePath, cfg.PublicKey, c.Logger)
	if err != nil {
		c.Logger.WithError(err).Warn("Failed to create legacy license checker")
		c.LicenseManager = NewMinimalLicenseManager(nil, c.Logger)
	} else {
		c.LicenseManager = NewMinimalLicenseManager(simpleLicenseChecker, c.Logger)
	}

	// Initialize device manager (legacy)
	dm, err := security.NewDeviceManager(cfg.LicensePath, cfg.PublicKey)
	if err != nil {
		c.Logger.WithError(err).Warn("Failed to create legacy device manager")
	} else {
		c.DeviceManager = dm
		if err := c.DeviceManager.InitializeLicense(context.Background()); err != nil {
			c.Logger.WithError(err).Warn("Legacy license validation failed")
		}
	}

	c.Logger.Info("Separated security components initialized successfully")
	return nil
}

func (c *Container) initConfiguration(cfg *Config) error {
	c.Logger.Debug("Initializing configuration components")

	// Create repositories
	dbManager := c.DatabaseFactory.GetManager()
	thingRepo := repositories.NewThingRepository(dbManager, c.Logger)
	configRepo := repositories.NewConfigRepository(dbManager, c.Logger)

	// Initialize config manager (API-based, not file-based)
	cm := config.NewConfigManager(dbManager, c.Logger)
	c.ConfigManager = cm

	// Initialize API configuration manager
	c.ConfigurationMgr = api.NewConfigManager(c.Logger)

	// Initialize thing registry with repository
	tr := config.NewThingRegistry(thingRepo, c.Logger)
	c.ThingRegistry = tr

	// Create license validator adapter
	var licenseValidator config.LicenseValidator
	if simpleLicenseChecker, err := license.NewSimpleLicenseChecker(cfg.LicensePath, cfg.PublicKey, c.Logger); err == nil {
		licenseValidator = config.NewSimpleLicenseValidatorAdapter(simpleLicenseChecker, c.Logger)
	} else {
		c.Logger.WithError(err).Warn("Failed to create license validator adapter")
		licenseValidator = nil
	}

	// Initialize lifecycle manager with ConfigRepository
	lifecycleManager := config.NewLifecycleManager(
		configRepo,
		cm,
		licenseValidator,
		cfg.DBPath, // Using DBPath as data directory
		c.Logger,
	)

	// Initialize configuration lifecycle
	if err := lifecycleManager.Initialize(); err != nil {
		c.Logger.WithError(err).Error("Failed to initialize configuration lifecycle")
		// Continue with defaults even if initialization fails
	}

	c.Logger.Info("Configuration components initialized")
	return nil
}

func (c *Container) initWoTComponents(cfg *Config) error { // Added cfg parameter
	c.Logger.Debug("Initializing WoT components")

	// Initialize Benthos Environment
	c.BenthosEnvironment = service.NewEnvironment()

	// Initialize state manager
	// Create stream repository for state manager
	streamRepo := repositories.NewStreamRepository(c.DatabaseFactory.GetManager(), c.Logger)

	sm, err := api.NewBenthosStateManager(streamRepo, "", cfg.ParquetLogPath, c.Logger)
	if err != nil {
		return fmt.Errorf("failed to initialize Benthos state manager: %w", err)
	}
	c.StateManager = sm

	// Initialize event broker
	c.EventBroker = api.NewEventBroker()

	// Initialize stream bridge
	// Pass BenthosEnvironment and ParquetLogPath to NewBenthosStreamBridge
	// Note: StreamBridge might need refactoring to use DatabaseManager too
	db := c.DatabaseFactory.GetManager().GetConnection()
	sb := api.NewBenthosStreamBridge(c.BenthosEnvironment, c.StateManager, db, c.Logger, cfg.ParquetLogPath)
	c.StreamBridge = sb

	// Initialize stream composition components
	if err := c.initStreamComposition(cfg); err != nil {
		return fmt.Errorf("failed to initialize stream composition: %w", err)
	}

	// Initialize Unified WoT handler
	c.UnifiedWoTHandler = api.NewUnifiedWoTHandler(
		c.StateManager,
		c.StreamBridge,
		c.ThingRegistry,
		c.BenthosStreamManager,
		c.EventBroker,
		c.Logger,
	)

	// Initialize centralized binding generator
	if err := c.initBindingGenerator(cfg); err != nil {
		return fmt.Errorf("failed to initialize binding generator: %w", err)
	}

	c.Logger.Info("WoT components initialized")
	return nil
}

// initBindingGenerator initializes the centralized WoT binding generator
func (c *Container) initBindingGenerator(cfg *Config) error {
	c.Logger.Debug("Initializing centralized binding generator")

	// Create simplified license checker
	simpleLicenseChecker, err := license.NewSimpleLicenseChecker(cfg.LicensePath, cfg.PublicKey, c.Logger)
	if err != nil {
		return fmt.Errorf("failed to create license checker: %w", err)
	}

	// Initialize binding generator with unified system
	unifiedAdapter := forms.NewUnifiedBindingGeneratorAdapter(
		c.Logger,
		simpleLicenseChecker,
		c.BenthosStreamManager,
	)

	// Configure persistence using modern approach (Bloblang pipelines)
	persistenceConfig := forms.PersistenceConfig{
		Enabled:    cfg.ParquetLogPath != "", // Enable if path is provided
		Format:     "parquet",
		BasePath:   cfg.ParquetLogPath,
		Partitions: []string{"year", "month", "day"},
	}
	unifiedAdapter.SetPersistenceConfig(persistenceConfig)

	c.BindingGenerator = unifiedAdapter
	c.Logger.Info("Unified binding generator initialized with Bloblang pipelines")

	c.Logger.Info("Centralized binding generator initialized")
	return nil
}

func (c *Container) initStreamComposition(cfg *Config) error {
	c.Logger.Debug("Initializing stream composition components")

	// Initialize Benthos stream manager with centralized database management
	dbManager := c.DatabaseFactory.GetManager()
	streamManager, err := api.NewSimpleBenthosStreamManager(
		cfg.ParquetLogPath+"/stream_configs", // Config directory for debug files
		dbManager,
		c.Logger,
	)
	if err != nil {
		return fmt.Errorf("failed to initialize Benthos stream manager: %w", err)
	}
	c.BenthosStreamManager = streamManager

	// Initialize TD stream composition service using the binding generator
	c.TDStreamComposition = api.NewDefaultTDStreamCompositionService(
		c.BindingGenerator,
		c.BenthosStreamManager,
		c.Logger,
	)

	// Initialize Thing registration service
	// Create an adapter for ThingRegistry to match the extended interface
	thingRegistryExt := &ThingRegistryAdapter{ThingRegistry: c.ThingRegistry}

	// Initialize Thing registration service with the correct constructor
	c.ThingRegistrationSvc = api.NewDefaultThingRegistrationService(
		thingRegistryExt,
		c.TDStreamComposition,
		c.ConfigurationMgr,     // Pass ConfigurationManager
		c.BindingGenerator,     // Added
		c.BenthosStreamManager, // Added
		c.Logger,
	)

	c.Logger.Info("Stream composition components initialized")
	return nil
}

func (c *Container) initServices(cfg *Config) error { // Added cfg for consistency
	c.Logger.Debug("Initializing services")

	// Create service registry with container's logger
	c.ServiceRegistry = svc.NewServiceRegistryWithLogger(c.Logger)

	// Create services - Updated to use refactored constructors
	c.HTTPService = svc.NewHTTPService(c.ConfigurationMgr, c.Logger) // Use refactored HTTP service

	// Setup caddy-security integration
	c.setupCaddySecurityIntegration(cfg)

	// NewStreamService was refactored to delegate to BenthosStreamManager
	// Constructor: NewStreamService(streamManager api.BenthosStreamManager, logger *logrus.Logger)
	c.StreamService = svc.NewStreamService(c.BenthosStreamManager, c.Logger)
	c.WoTService = svc.NewWoTService(c.ThingRegistry, c.ConfigManager, c.Logger) // Assuming this constructor is correct

	// Register services with their configurations
	c.ServiceRegistry.RegisterServiceWithConfig("http", c.HTTPService, c.InitialHTTPServiceConfig)
	c.ServiceRegistry.RegisterServiceWithConfig("stream", c.StreamService, c.InitialStreamServiceConfig)

	// WoT service doesn't need complex config for now
	wotConfig := types.ServiceConfig{
		Name:   "wot",
		Config: make(map[string]any),
	}
	c.ServiceRegistry.RegisterServiceWithConfig("wot", c.WoTService, wotConfig)

	// Load permitted services based on license
	license := c.DeviceManager.GetLicense()
	if license == nil { // Or a more specific check if the License interface/impl allows
		c.Logger.Warnf("No valid license retrieved for loading permitted services. Proceeding with default/no restrictions or features.")
		// The LoadPermittedServices method should handle a nil license gracefully.
	}
	if err := c.ServiceRegistry.LoadPermittedServices(license); err != nil {
		return err
	}

	c.Logger.Info("Services initialized")
	return nil
}

func (c *Container) wireDependencies(cfg *Config) error { // Added cfg parameter
	c.Logger.Debug("Wiring dependencies")

	// Note: Stream integration, WoT processors and streams are now created dynamically by the centralized
	// binding generator when Thing Descriptions are registered through the API

	c.Logger.Info("Dependencies wired")
	return nil
}

// Start starts all services
func (c *Container) Start(ctx context.Context) error {
	c.Logger.Info("Starting services")

	// Start services in order
	for _, name := range []string{"http", "stream", "wot"} {
		if err := c.ServiceRegistry.StartService(ctx, name); err != nil {
			return fmt.Errorf("failed to start %s service: %w", name, err)
		}
		c.Logger.Infof("Started %s service", name)
	}

	return nil
}

// Stop stops all services
func (c *Container) Stop(ctx context.Context) error {
	c.Logger.Info("Stopping services")

	// Stop in reverse order
	for _, name := range []string{"wot", "stream", "http"} {
		if err := c.ServiceRegistry.StopService(ctx, name); err != nil {
			c.Logger.Errorf("Failed to stop %s service: %v", name, err)
		}
	}

	// Close database factory
	if c.DatabaseFactory != nil {
		c.DatabaseFactory.Close()
	}

	return nil
}

// setupCaddySecurityIntegration configures caddy-auth-portal integration with local identity store
func (c *Container) setupCaddySecurityIntegration(cfg *Config) {
	c.Logger.Debug("Setting up caddy-auth-portal integration")

	// Get system security configuration from the config manager
	systemSecurityConfig, err := c.getSystemSecurityConfig()
	if err != nil {
		c.Logger.WithError(err).Warn("Failed to get system security config, using defaults")
		systemSecurityConfig = c.getDefaultSystemSecurityConfig()
	}

	// Create caddy-auth-portal bridge
	// Reuse the SecurityRepository created earlier
	dbManager := c.DatabaseFactory.GetManager()
	securityRepo := repositories.NewSecurityRepository(dbManager, c.Logger)
	authPortalBridge, err := security.NewCaddyAuthPortalBridge(
		securityRepo,
		c.Logger,
		systemSecurityConfig,
		c.UnifiedLicenseChecker,
		cfg.ParquetLogPath, // Use ParquetLogPath as data directory
	)
	if err != nil {
		c.Logger.WithError(err).Error("Failed to create auth portal bridge")
		return
	}

	// Note: SetConfigManager is only needed for tests that call ApplyAuthConfiguration
	// Main application doesn't use this functionality

	// Set the auth portal bridge on the HTTP service
	if httpService, ok := c.HTTPService.(*svc.HTTPService); ok {
		httpService.SetSecurityBridge(authPortalBridge)
		c.Logger.Info("Caddy-auth-portal integration configured successfully")

		// Sync users to identity store (no-op for local store, but good for consistency)
		if err := authPortalBridge.SyncUsersToIdentityStore(context.Background()); err != nil {
			c.Logger.WithError(err).Warn("Failed to sync users to identity store")
		}
	} else {
		c.Logger.Error("Failed to cast HTTP service to HTTPService")
	}
}

// getSystemSecurityConfig retrieves system security configuration
func (c *Container) getSystemSecurityConfig() (*types.SystemSecurityConfig, error) {
	// TODO: This should load from the database or configuration file
	// For now, return default configuration
	return c.getDefaultSystemSecurityConfig(), nil
}

// getDefaultSystemSecurityConfig returns default system security configuration
func (c *Container) getDefaultSystemSecurityConfig() *types.SystemSecurityConfig {
	// Create default config provider with license checker and get default security config
	defaultProvider := config.NewDefaultConfigProviderWithLicense(c.UnifiedLicenseChecker)
	secConfig := defaultProvider.GetDefaultSystemSecurityConfig()

	// Enable security for caddy-security integration
	secConfig.Enabled = true

	// Configure API authentication settings for JWT tokens
	if secConfig.APIAuth == nil {
		secConfig.APIAuth = &types.APIAuthConfig{
			Methods: []string{"bearer"},
			JWTConfig: &types.JWTConfig{
				Algorithm:    "HS256",
				Issuer:       "twincore-gateway",
				Audience:     "twincore-api",
				Expiry:       time.Hour, // 1 hour
				RefreshToken: true,
			},
			Policies: []types.APIPolicy{
				{
					Principal: "role:admin",
					Resources: []string{"/api/*"},
					Actions:   []string{"read", "write", "delete"},
				},
				{
					Principal: "role:operator",
					Resources: []string{"/api/things/*", "/api/streams/*"},
					Actions:   []string{"read", "write"},
				},
				{
					Principal: "role:viewer",
					Resources: []string{"/api/things/*", "/api/streams/*"},
					Actions:   []string{"read"},
				},
			},
		}
	}

	// Configure session settings
	if secConfig.SessionConfig == nil {
		secConfig.SessionConfig = &types.SessionConfig{
			Timeout:        3600,  // 1 hour
			MaxSessions:    5,     // Max 5 concurrent sessions per user
			SecureCookies:  true,  // HTTPS only in production
			SameSite:       "lax", // CSRF protection
			CSRFProtection: true,
		}
	}

	return &secConfig
}

// buildInitialHTTPServiceConfig creates the default configuration for the HTTP service.
// This is crucial for providing baseline settings, especially security configurations,
// that are used when dynamically updating Caddy.
func (c *Container) buildInitialHTTPServiceConfig(appCfg *Config) types.ServiceConfig {
	// Security is now handled separately by SystemSecurityManager
	// HTTP configuration no longer contains security settings

	// Initialize with the new HTTPConfig
	// Security middleware will be handled by SystemSecurityManager
	httpCfg := types.HTTPConfig{
		Listen: []string{":8080"},   // Default listen address, can be from appCfg
		Routes: []types.HTTPRoute{}, // Initialize with no routes
		// Security field removed - now handled by SystemSecurityManager
	}

	// Convert HTTPConfig to map[string]interface{} for proper serialization
	// This ensures the config can be properly marshaled/unmarshaled when passed around
	// Security configurations removed - now handled by SystemSecurityManager
	httpCfgMap := map[string]any{
		"listen": httpCfg.Listen,
		"routes": httpCfg.Routes,
		// Security field removed - authentication handled by SystemSecurityManager middleware
	}

	return types.ServiceConfig{
		Name: "http",
		Type: "http_service",
		Config: map[string]any{
			// Store as map for proper serialization/deserialization
			"http": httpCfgMap,
		},
	}
}

// buildInitialStreamServiceConfig creates the default configuration for the Stream service.
func (c *Container) buildInitialStreamServiceConfig(appCfg *Config) types.ServiceConfig {
	// TODO: Define default stream configurations if any are needed at startup.
	return types.ServiceConfig{Name: "stream", Type: "stream_service", Config: map[string]any{"stream": types.StreamConfig{}}}
}

// Config holds container configuration
type Config struct {
	DBPath         string
	LicensePath    string
	PublicKey      []byte
	ParquetLogPath string // Base path for Parquet log files
}

// runMigrations runs database migrations
func runMigrations(db *sql.DB) error {
	schema := `
    -- Configuration tables
    CREATE TABLE IF NOT EXISTS configs (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        data TEXT NOT NULL,
        version INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    -- Thing registry tables
    CREATE TABLE IF NOT EXISTS things (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        td_jsonld TEXT NOT NULL,      -- Original JSON-LD
        td_parsed TEXT NOT NULL,       -- Parsed TD
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    -- Caddy config with JD patches
    CREATE TABLE IF NOT EXISTS caddy_configs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        config TEXT NOT NULL,
        patches TEXT,                  -- JD patches for rollback
        version INTEGER,
        active BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    -- Property state
    CREATE TABLE IF NOT EXISTS property_state (
        thing_id TEXT NOT NULL,
        property_name TEXT NOT NULL,
        value TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (thing_id, property_name)
    );
    
    -- Action state
    CREATE TABLE IF NOT EXISTS action_state (
        action_id TEXT PRIMARY KEY,
        thing_id TEXT NOT NULL,
        action_name TEXT NOT NULL,
        input TEXT,
        output TEXT,
        status TEXT NOT NULL,
        started_at TIMESTAMP NOT NULL,
        completed_at TIMESTAMP,
        error TEXT
    );
    
    CREATE INDEX IF NOT EXISTS idx_things_updated ON things(updated_at);
    CREATE INDEX IF NOT EXISTS idx_caddy_active ON caddy_configs(active);
    CREATE INDEX IF NOT EXISTS idx_action_status ON action_state(status);

    -- Local users for system security
    CREATE TABLE IF NOT EXISTS local_users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL, -- IMPORTANT: Store only hashed passwords
        roles TEXT,                  -- JSON array of roles
        email TEXT UNIQUE,           -- Optional, but often useful
        name TEXT,                   -- Display name, optional
        disabled BOOLEAN DEFAULT FALSE,
        last_login TIMESTAMP,        -- Track last login time
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_local_users_email ON local_users(email);
    CREATE INDEX IF NOT EXISTS idx_local_users_disabled ON local_users(disabled);
    
    -- System security sessions
    CREATE TABLE IF NOT EXISTS user_sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        username TEXT NOT NULL,
        token TEXT NOT NULL UNIQUE,
        refresh_token TEXT,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT,
        user_agent TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(token);
    CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at);
    
    -- WoT security policies
    CREATE TABLE IF NOT EXISTS thing_security_policies (
        thing_id TEXT PRIMARY KEY,
        policy_data TEXT NOT NULL,  -- JSON policy data
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    -- WoT device credentials
    CREATE TABLE IF NOT EXISTS device_credentials (
        credential_key TEXT PRIMARY KEY,
        credentials_data TEXT NOT NULL,  -- JSON credential data
        encrypted BOOLEAN DEFAULT FALSE,
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_device_credentials_expires ON device_credentials(expires_at);
    
    -- WoT security templates
    CREATE TABLE IF NOT EXISTS security_templates (
        name TEXT PRIMARY KEY,
        template_data TEXT NOT NULL,  -- JSON template data
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    
    -- System API policies
    CREATE TABLE IF NOT EXISTS api_policies (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        principal TEXT NOT NULL,     -- user, group, role
        resources TEXT NOT NULL,     -- JSON array of API endpoints
        actions TEXT NOT NULL,       -- JSON array of actions
        conditions TEXT,             -- JSON array of conditions
        enabled BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_api_policies_principal ON api_policies(principal);
    CREATE INDEX IF NOT EXISTS idx_api_policies_enabled ON api_policies(enabled);

    -- Security audit events
    CREATE TABLE IF NOT EXISTS security_audit_events (
        id TEXT PRIMARY KEY,
        event_type TEXT NOT NULL,    -- 'system' or 'wot'
        timestamp TIMESTAMP NOT NULL,
        user_id TEXT,
        thing_id TEXT,
        operation TEXT NOT NULL,
        resource TEXT,
        success BOOLEAN NOT NULL,
        error TEXT,
        ip_address TEXT,
        user_agent TEXT,
        details TEXT                 -- JSON details
    );
    CREATE INDEX IF NOT EXISTS idx_audit_events_type ON security_audit_events(event_type);
    CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON security_audit_events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_events_user ON security_audit_events(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_events_thing ON security_audit_events(thing_id);
    `

	_, err := db.Exec(schema)
	return err
}

// ThingRegistryAdapter adapts the existing ThingRegistry to implement ThingRegistryExt
type ThingRegistryAdapter struct {
	ThingRegistry *config.ThingRegistry
}

// Implement api.ThingRegistry interface methods
func (a *ThingRegistryAdapter) GetThing(thingID string) (*wot.ThingDescription, error) {
	return a.ThingRegistry.GetThing(thingID)
}

func (a *ThingRegistryAdapter) GetProperty(thingID, propertyName string) (wot.PropertyAffordance, error) {
	return a.ThingRegistry.GetProperty(thingID, propertyName)
}

func (a *ThingRegistryAdapter) GetAction(thingID, actionName string) (wot.ActionAffordance, error) {
	return a.ThingRegistry.GetAction(thingID, actionName)
}

func (a *ThingRegistryAdapter) GetEvent(thingID, eventName string) (wot.EventAffordance, error) {
	return a.ThingRegistry.GetEvent(thingID, eventName)
}

// Implement api.ThingRegistryExt interface methods (extended interface)
func (a *ThingRegistryAdapter) RegisterThing(tdJSONLD string) (*wot.ThingDescription, error) {
	return a.ThingRegistry.RegisterThing(tdJSONLD)
}

func (a *ThingRegistryAdapter) UpdateThing(thingID string, tdJSONLD string) (*wot.ThingDescription, error) {
	return a.ThingRegistry.UpdateThing(thingID, tdJSONLD)
}

func (a *ThingRegistryAdapter) DeleteThing(thingID string) error {
	return a.ThingRegistry.DeleteThing(thingID)
}

func (a *ThingRegistryAdapter) ListThings() ([]*wot.ThingDescription, error) {
	return a.ThingRegistry.ListThings()
}

// MinimalLicenseManager provides a minimal implementation of LicenseManager interface
// using the simplified JWT license checker
type MinimalLicenseManager struct {
	checker *license.SimpleLicenseChecker
	logger  *logrus.Logger
}

// NewMinimalLicenseManager creates a new minimal license manager
func NewMinimalLicenseManager(checker *license.SimpleLicenseChecker, logger *logrus.Logger) *MinimalLicenseManager {
	return &MinimalLicenseManager{
		checker: checker,
		logger:  logger,
	}
}

// ParseAndValidate implements types.LicenseManager interface
// For simplified license checking, this just returns a license wrapper
func (m *MinimalLicenseManager) ParseAndValidate(tokenString string) (types.License, error) {
	// Since our license validation is done during SimpleLicenseChecker creation,
	// we return a license wrapper that uses our checker
	return &SimpleLicenseWrapper{checker: m.checker}, nil
}

// SimpleLicenseWrapper wraps SimpleLicenseChecker to implement types.License
type SimpleLicenseWrapper struct {
	checker *license.SimpleLicenseChecker
}

// IsFeatureEnabled implements types.License interface
func (w *SimpleLicenseWrapper) IsFeatureEnabled(feature string) bool {
	return w.checker.IsFeatureAvailable(feature)
}

// Ensure ThingRegistryAdapter implements both interfaces
var _ api.ThingRegistry = (*ThingRegistryAdapter)(nil)
var _ api.ThingRegistryExt = (*ThingRegistryAdapter)(nil)

// Ensure MinimalLicenseManager implements types.LicenseManager interface
var _ types.LicenseManager = (*MinimalLicenseManager)(nil)

// Ensure SimpleLicenseWrapper implements types.License interface
var _ types.License = (*SimpleLicenseWrapper)(nil)
