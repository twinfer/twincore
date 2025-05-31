// internal/container/container.go
package container

import (
	"context"
	"database/sql"
	"fmt"
	"os"   // Added for OPA policy file reading
	"time" // Added for OPA input

	"github.com/open-policy-agent/opa/rego"
	"github.com/redpanda-data/benthos/v4/public/service"
	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/api"
	"github.com/twinfer/twincore/internal/config"
	"github.com/twinfer/twincore/internal/security" // Added for new security types
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"

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
	ConfigManager *config.ConfigManager
	ThingRegistry *config.ThingRegistry

	// Services
	ServiceRegistry types.ServiceRegistry
	HTTPService     types.Service
	StreamService   types.Service
	WoTService      types.Service

	// WoT Components
	StateManager api.StateManager
	StreamBridge api.StreamBridge
	EventBroker  *api.EventBroker
	WoTHandler   *api.WoTHandler

	// Stream Composition Components
	BenthosStreamManager api.BenthosStreamManager
	TDStreamComposer     api.TDStreamComposer
	TDStreamComposition  api.TDStreamCompositionService
	ThingRegistrationSvc api.ThingRegistrationService
	StreamConfigDefaults api.StreamConfigDefaults

	// Benthos
	// StreamBuilder *service.StreamBuilder // Replaced by BenthosEnvironment
	BenthosEnvironment *service.Environment // Benthos v4 environment

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

	// Initialize license manager using the new constructor from internal/security
	// The types.LicenseManager in Container struct should be compatible with security.LicenseManager interface
	var lm types.LicenseManager                                  // Ensure this type matches what NewLicenseManager returns or is compatible
	var specificLm *security.LicenseManager                      // Corrected type to pointer
	specificLm, err := security.NewLicenseManager(cfg.PublicKey) // Corrected assignment
	if err != nil {
		return fmt.Errorf("failed to create license manager: %w", err)
	}
	lm = specificLm // Assign if compatible, or adjust types.LicenseManager
	c.LicenseManager = lm

	// Initialize device manager using the new constructor from internal/security
	dm, err := security.NewDeviceManager(cfg.LicensePath, cfg.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to create device manager: %w", err)
	}
	c.DeviceManager = dm

	// Validate license by reading from file and using LicenseManager
	if err := c.DeviceManager.InitializeLicense(context.Background()); err != nil {
		return fmt.Errorf("license validation failed: %w", err)
	}
	c.Logger.Info("License file processed and basic validation complete.")

	// OPA-based license validation
	licenseClaims, err := c.DeviceManager.GetLicenseClaims()
	if err != nil {
		return fmt.Errorf("failed to get license claims for OPA validation: %w", err)
	}

	opaInput := map[string]interface{}{
		"license":           licenseClaims,
		"current_time_unix": time.Now().Unix(),
	}

	policyBytes, err := os.ReadFile("internal/container/license.rego")
	if err != nil {
		return fmt.Errorf("failed to read OPA policy file internal/container/license.rego: %w", err)
	}

	ctxOpa := context.Background()
	query, err := rego.New(
		rego.Query("data.twinedge.authz.allow"),
		rego.Module("license.rego", string(policyBytes)),
		rego.Input(opaInput),
	).PrepareForEval(ctxOpa)
	if err != nil {
		return fmt.Errorf("failed to prepare OPA query: %w", err)
	}

	rs, err := query.Eval(ctxOpa)
	if err != nil {
		return fmt.Errorf("OPA policy evaluation error: %w", err)
	}

	if len(rs) == 0 || !rs[0].Expressions[0].Value.(bool) {
		c.Logger.Error("License is not valid per OPA policy.")
		return fmt.Errorf("license is not valid per OPA policy")
	}

	c.Logger.Info("License successfully validated with OPA policy.")
	c.Logger.Info("Security components initialized.")
	return nil
}

func (c *Container) initConfiguration() error {
	c.Logger.Debug("Initializing configuration components")

	// Initialize config manager (API-based, not file-based)
	cm := config.NewConfigManager(c.DB, c.Logger)
	c.ConfigManager = cm

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
	// Pass ParquetLogPath to NewDuckDBStateManager (signature: db, logger, parquetLogPath)
	sm, err := api.NewDuckDBStateManager(c.DB, c.Logger, cfg.ParquetLogPath)
	if err != nil {
		return fmt.Errorf("failed to initialize DuckDB state manager: %w", err)
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

	// Initialize WoT handler
	c.WoTHandler = api.NewWoTHandler(
		c.StateManager,
		c.StreamBridge,
		c.ThingRegistry,
		c.EventBroker,
		c.Logger,
	)

	c.Logger.Info("WoT components initialized")
	return nil
}

func (c *Container) initStreamComposition(cfg *Config) error {
	c.Logger.Debug("Initializing stream composition components")

	// Initialize stream configuration defaults
	c.StreamConfigDefaults = api.GetDefaultStreamConfigDefaults()

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

	// Initialize TD stream composer
	c.TDStreamComposer = api.NewSimpleTDStreamComposer(c.Logger)

	// Initialize TD stream composition service
	c.TDStreamComposition = api.NewDefaultTDStreamCompositionService(
		c.TDStreamComposer,
		c.BenthosStreamManager,
		c.Logger,
	)

	// Create stream composition configuration with overrides from container config
	overrides := map[string]interface{}{
		"parquet_log_path": cfg.ParquetLogPath,
		"enable_metrics":   true,
	}
	compositionConfig := api.GetStreamCompositionConfigFromDefaults(c.StreamConfigDefaults, overrides)

	// Validate configuration
	validator := api.NewStreamConfigValidator(c.StreamConfigDefaults)
	if err := validator.ValidateConfig(compositionConfig); err != nil {
		return fmt.Errorf("invalid stream composition configuration: %w", err)
	}

	// Initialize Thing registration service with stream composition
	thingRegSvcBuilder := api.NewThingRegistrationServiceBuilder()

	// Create an adapter for ThingRegistry to match the extended interface
	thingRegistryExt := &ThingRegistryAdapter{ThingRegistry: c.ThingRegistry}

	thingRegSvc, err := thingRegSvcBuilder.
		WithThingRegistry(thingRegistryExt).
		WithStreamManager(c.BenthosStreamManager).
		WithLogger(c.Logger).
		WithCompositionConfig(compositionConfig).
		Build()
	if err != nil {
		return fmt.Errorf("failed to build Thing registration service: %w", err)
	}
	c.ThingRegistrationSvc = thingRegSvc

	c.Logger.Info("Stream composition components initialized")
	return nil
}

func (c *Container) initServices(cfg *Config) error { // Added cfg for consistency
	c.Logger.Debug("Initializing services")

	// Create service registry
	c.ServiceRegistry = svc.NewServiceRegistry()

	// Create services
	c.HTTPService = svc.NewHTTPService(c.Logger, c.DB) // Corrected constructor
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

	// Wire stream integration
	// Pass ParquetLogPath to NewStreamIntegration
	// Signature: (stateMgr, eventBroker, streamBridge, logger, parquetLogPath)
	integration := api.NewStreamIntegration(c.StateManager, c.EventBroker, c.StreamBridge, c.Logger, cfg.ParquetLogPath)

	// Register Benthos processors using the container's BenthosEnvironment and Logger
	// Signature: (env, integration, logger)
	if err := api.RegisterWoTProcessors(c.BenthosEnvironment, integration, c.Logger); err != nil {
		return fmt.Errorf("failed to register WoT Benthos processors: %w", err)
	}

	// Create WoT streams using the container's BenthosEnvironment
	// Signature: (env)
	if err := api.CreateWoTStreams(c.BenthosEnvironment); err != nil {
		return fmt.Errorf("failed to create WoT Benthos streams: %w", err)
	}

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
	// TODO: Load this from a static gateway configuration file or define robust defaults.
	// For now, providing a minimal structure.
	// The `security` part is essential for `main.go` when registering new Things.
	defaultSecurityConfig := types.SecurityConfig{
		Enabled: true, // Or false, depending on default posture
		// Initialize with empty slices for now to avoid compilation issues
		// These can be populated from actual configuration when needed
	}

	return types.ServiceConfig{
		Name: "http",
		Type: "http_service", // Or a more descriptive type
		Config: map[string]interface{}{
			"http":     types.HTTPConfig{Routes: []types.HTTPRoute{}}, // Initially no dynamic routes
			"security": defaultSecurityConfig,
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

// Ensure ThingRegistryAdapter implements both interfaces
var _ api.ThingRegistry = (*ThingRegistryAdapter)(nil)
var _ api.ThingRegistryExt = (*ThingRegistryAdapter)(nil)
