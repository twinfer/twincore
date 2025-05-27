// internal/container/container.go
package container

import (
	"context"
	"database/sql"
	"fmt"
	"os"   // Added for OPA policy file reading
	"time" // Added for OPA input

	"github.com/open-policy-agent/opa/rego" // Added for OPA
	"github.com/redpanda-data/benthos/v4/public/service"
	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/api"
	"github.com/twinfer/twincore/internal/config"
	"github.com/twinfer/twincore/internal/security" // Added for new security types
	"github.com/twinfer/twincore/pkg/types"
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
	var lm types.LicenseManager // Ensure this type matches what NewLicenseManager returns or is compatible
	var specificLm security.LicenseManager
	specificLm, err := security.NewLicenseManager(cfg.PublicKey)
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
	license, err := c.DeviceManager.GetLicense() // Assuming GetLicense exists and might return error
	if err != nil {
		c.Logger.Warnf("Failed to retrieve license for loading permitted services: %v. Proceeding with default/no restrictions.", err)
		// Potentially load a default "no license" or "base features" license object
	}
	if err := c.ServiceRegistry.LoadPermittedServices(license); err != nil {
		return err
	}

	c.Logger.Info("Services initialized")
	return nil
}

func (c *Container) wireDependencies(cfg *Config) error { // Added cfg parameter
	c.Logger.Debug("Wiring dependencies")

	// Wire WoT handler to HTTP service
	if httpSvc, ok := c.HTTPService.(*svc.HTTPService); ok {
		httpSvc.SetWoTHandler(c.WoTHandler)
	}

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
