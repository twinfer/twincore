// internal/container/container.go
package container

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/redpanda-data/benthos/v4/public/service"
	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/api"
	"github.com/twinfer/twincore/internal/config"
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
	DB     *sql.DB
	Logger *logrus.Logger

	// Security
	DeviceManager  *security.DeviceManager
	LicenseManager types.LicenseManager

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
	StateManager       api.StateManager
	StreamBridge       api.StreamBridge
	EventBroker        *api.EventBroker
	UnifiedWoTHandler  *api.UnifiedWoTHandler

	// Stream Composition Components
	BenthosStreamManager api.BenthosStreamManager
	TDStreamComposition  api.TDStreamCompositionService
	ThingRegistrationSvc api.ThingRegistrationService

	// Benthos
	// StreamBuilder *service.StreamBuilder // Replaced by BenthosEnvironment
	BenthosEnvironment *service.Environment // Benthos v4 environment

	// Legacy security integration (deprecated, replaced by simplified license checking)
	licenseIntegration *security.LicenseIntegration

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
	if err := c.initConfiguration(); err != nil {
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
	c.Logger.Debug("Initializing database")

	db, err := sql.Open("duckdb", dbPath)
	if err != nil {
		return err
	}

	// Run migrations
	if err := runMigrations(db); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	c.DB = db
	c.Logger.Info("Database initialized")
	return nil
}

func (c *Container) initSecurity(cfg *Config) error {
	c.Logger.Debug("Initializing security components")

	// Initialize simplified license checker (replacing OPA)
	simpleLicenseChecker, err := license.NewSimpleLicenseChecker(cfg.LicensePath, cfg.PublicKey, c.Logger)
	if err != nil {
		return fmt.Errorf("failed to create simplified license checker: %w", err)
	}

	// Validate license features
	features, err := simpleLicenseChecker.GetAllowedFeatures()
	if err != nil {
		return fmt.Errorf("failed to get license features: %w", err)
	}

	c.Logger.WithFields(logrus.Fields{
		"bindings":    len(features["bindings"].([]string)),
		"processors":  len(features["processors"].([]string)),
		"has_license": features["has_license"],
	}).Info("License validated successfully with simplified JWT checker")

	// Initialize legacy license manager for backward compatibility
	// Note: This can be removed once all components use the simplified checker
	var lm types.LicenseManager
	var specificLm *security.LicenseManager
	specificLm, err = security.NewLicenseManager(cfg.PublicKey)
	if err != nil {
		c.Logger.WithError(err).Warn("Failed to create legacy license manager, continuing with simplified checker")
		// Create a minimal implementation that satisfies the interface
		lm = NewMinimalLicenseManager(simpleLicenseChecker, c.Logger)
	} else {
		lm = specificLm
	}
	c.LicenseManager = lm

	// Initialize device manager using simplified license validation
	dm, err := security.NewDeviceManager(cfg.LicensePath, cfg.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to create device manager: %w", err)
	}
	c.DeviceManager = dm

	// Validate license using device manager (legacy path)
	if err := c.DeviceManager.InitializeLicense(context.Background()); err != nil {
		c.Logger.WithError(err).Warn("Legacy license validation failed, but simplified checker succeeded")
	}

	c.Logger.Info("Security components initialized with simplified JWT license checking")
	return nil
}

func (c *Container) initConfiguration() error {
	c.Logger.Debug("Initializing configuration components")

	// Initialize config manager (API-based, not file-based)
	cm := config.NewConfigManager(c.DB, c.Logger)
	c.ConfigManager = cm

	// Initialize API configuration manager
	c.ConfigurationMgr = api.NewConfigManager(c.Logger)

	// Initialize thing registry
	tr := config.NewThingRegistry(c.DB, c.Logger)
	c.ThingRegistry = tr

	// Load configs from DB on startup
	if err := cm.LoadFromDB(); err != nil {
		c.Logger.Warnf("Failed to load configs from DB: %v", err)
	}

	c.Logger.Info("Configuration components initialized")
	return nil
}

func (c *Container) initWoTComponents(cfg *Config) error { // Added cfg parameter
	c.Logger.Debug("Initializing WoT components")

	// Initialize Benthos Environment
	c.BenthosEnvironment = service.NewEnvironment()

	// Initialize state manager
	// NewBenthosStateManager signature: (db *sql.DB, benthosConfigDir, parquetLogPath string, logger logrus.FieldLogger)
	// Passing empty string for benthosConfigDir as it's not available in cfg here.
	// c.Logger is *logrus.Logger, which implements logrus.FieldLogger.
	sm, err := api.NewBenthosStateManager(c.DB, "", cfg.ParquetLogPath, c.Logger)
	if err != nil {
		return fmt.Errorf("failed to initialize Benthos state manager: %w", err)
	}
	c.StateManager = sm

	// Initialize event broker
	c.EventBroker = api.NewEventBroker()

	// Initialize stream bridge
	// Pass BenthosEnvironment and ParquetLogPath to NewBenthosStreamBridge
	// Signature: (env, stateMgr, db, logger, parquetLogPath)
	sb := api.NewBenthosStreamBridge(c.BenthosEnvironment, c.StateManager, c.DB, c.Logger, cfg.ParquetLogPath)
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

	// Create license adapter
	licenseAdapter := forms.NewLicenseAdapter(simpleLicenseChecker, c.Logger)

	// Create configuration structures
	parquetConfig := types.ParquetConfig{
		BasePath:        cfg.ParquetLogPath,
		BatchSize:       1000,
		BatchPeriod:     "5s",
		Compression:     "gzip",
		FileNamePattern: "%s_%s.parquet",
	}

	kafkaConfig := types.KafkaConfig{
		Brokers: []string{"${KAFKA_BROKERS:localhost:9092}"},
	}

	mqttConfig := types.MQTTConfig{
		Broker: "${MQTT_BROKER:tcp://localhost:1883}",
		QoS:    1,
	}

	// Initialize binding generator with unified system
	// Always use the new unified binding generator since legacy code has been removed
	unifiedAdapter := forms.NewUnifiedBindingGeneratorAdapter(
		c.Logger,
		licenseAdapter,
		c.BenthosStreamManager,
	)
	unifiedAdapter.ConfigureFromLegacy(parquetConfig, kafkaConfig, mqttConfig)
	c.BindingGenerator = unifiedAdapter
	c.Logger.Info("Using unified binding generator")

	c.Logger.Info("Centralized binding generator initialized")
	return nil
}

func (c *Container) initStreamComposition(cfg *Config) error {
	c.Logger.Debug("Initializing stream composition components")

	// Initialize Benthos stream manager with DuckDB persistence
	streamManager, err := api.NewSimpleBenthosStreamManager(
		cfg.ParquetLogPath+"/stream_configs", // Config directory for debug files
		c.DB,
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

	// Create service registry
	c.ServiceRegistry = svc.NewServiceRegistry()

	// Create services
	c.HTTPService = svc.NewHTTPServiceSimple(c.Logger) // Use the available constructor
	// NewStreamService was refactored to take *service.Environment.
	// Constructor: NewStreamService(env *service.Environment, logger *logrus.Logger)
	c.StreamService = svc.NewStreamService(c.BenthosEnvironment, c.Logger)
	c.WoTService = svc.NewWoTService(c.ThingRegistry, c.ConfigManager, c.Logger) // Assuming this constructor is correct

	// Register services
	c.ServiceRegistry.RegisterService("http", c.HTTPService)
	c.ServiceRegistry.RegisterService("stream", c.StreamService)
	c.ServiceRegistry.RegisterService("wot", c.WoTService)

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

	// Close database
	if c.DB != nil {
		c.DB.Close()
	}

	return nil
}

// buildInitialHTTPServiceConfig creates the default configuration for the HTTP service.
// This is crucial for providing baseline settings, especially security configurations,
// that are used when dynamically updating Caddy.
func (c *Container) buildInitialHTTPServiceConfig(appCfg *Config) types.ServiceConfig {
	// Default security configuration using the new SimpleSecurityConfig
	// This can be further customized based on appCfg if needed.
	secConfig := types.SimpleSecurityConfig{
		Enabled: true, // Default to enabled, can be configurable
		// BasicAuth, BearerAuth, JWTAuth will be nil by default.
		// They can be configured via appCfg or dynamic configuration later.
	}

	// Initialize with the new HTTPConfig (formerly HTTPConfigV2)
	// Note: types.HTTPConfig and types.HTTPRoute now refer to the
	// structs defined in pkg/types/config.go.
	httpCfg := types.HTTPConfig{
		Listen:   []string{":8080"},   // Default listen address, can be from appCfg
		Routes:   []types.HTTPRoute{}, // Initialize with no routes
		Security: secConfig,
	}

	return types.ServiceConfig{
		Name: "http",
		Type: "http_service",
		Config: map[string]interface{}{
			// The "http" key now holds the new types.HTTPConfig,
			// which includes its own security settings.
			"http": httpCfg,
			// The old top-level "security" key might be deprecated or removed
			// if all security config moves into httpCfg.Security.
			// For now, let's keep it to see if other parts rely on it,
			// but populate it from the new structure for consistency.
			// Ideally, this would be refactored away later.
			"security": map[string]interface{}{ // Reconstruct for potential legacy consumers
				"enabled": secConfig.Enabled,
				// Add other fields if necessary, e.g., from secConfig.BasicAuth etc.
				// This is a transitional step.
			},
		},
	}
}

// buildInitialStreamServiceConfig creates the default configuration for the Stream service.
func (c *Container) buildInitialStreamServiceConfig(appCfg *Config) types.ServiceConfig {
	// TODO: Define default stream configurations if any are needed at startup.
	return types.ServiceConfig{Name: "stream", Type: "stream_service", Config: map[string]interface{}{"stream": types.StreamConfig{}}}
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

    -- Local users for caddy-security/go-authcrunch
    CREATE TABLE IF NOT EXISTS local_users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL, -- IMPORTANT: Store only hashed passwords
        roles TEXT,                  -- Could be comma-separated string or JSON array
        email TEXT UNIQUE,           -- Optional, but often useful
        name TEXT,                   -- Display name, optional
        disabled BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_local_users_email ON local_users(email);
    CREATE INDEX IF NOT EXISTS idx_local_users_disabled ON local_users(disabled);
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
