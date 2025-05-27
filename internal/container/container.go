// internal/container/container.go
package container

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/redpanda-data/benthos/v4/public/service"
	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincorey/internal/api"
	"github.com/twinfer/twincorey/internal/config"
	"github.com/twinfer/twincorey/internal/security"
	svc "github.com/twinfer/twincorey/internal/service"
	"github.com/twinfer/twincorey/pkg/types"
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
	StreamBuilder *service.StreamBuilder
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
	if err := c.initWoTComponents(); err != nil {
		return nil, fmt.Errorf("failed to init WoT components: %w", err)
	}

	// Initialize services
	if err := c.initServices(); err != nil {
		return nil, fmt.Errorf("failed to init services: %w", err)
	}

	// Wire up dependencies
	if err := c.wireDependencies(); err != nil {
		return nil, fmt.Errorf("failed to wire dependencies: %w", err)
	}

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

	// Initialize license manager
	lm, err := security.NewLicenseManager(cfg.PublicKey)
	if err != nil {
		return err
	}
	c.LicenseManager = lm

	// Initialize device manager
	dm, err := security.NewDeviceManager(cfg.LicensePath, cfg.PublicKey)
	if err != nil {
		return err
	}
	c.DeviceManager = dm

	// Validate license
	if err := dm.InitializeLicense(context.Background()); err != nil {
		return fmt.Errorf("license validation failed: %w", err)
	}

	c.Logger.Info("Security components initialized")
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

func (c *Container) initWoTComponents() error {
	c.Logger.Debug("Initializing WoT components")

	// Initialize state manager
	sm, err := api.NewDuckDBStateManager(c.DB, c.Logger)
	if err != nil {
		return err
	}
	c.StateManager = sm

	// Initialize event broker
	c.EventBroker = api.NewEventBroker()

	// Initialize Benthos stream builder
	c.StreamBuilder = service.NewStreamBuilder()

	// Initialize stream bridge
	sb := api.NewBenthosStreamBridge(c.StreamBuilder, c.StateManager, c.DB, c.Logger)
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

func (c *Container) initServices() error {
	c.Logger.Debug("Initializing services")

	// Create service registry
	c.ServiceRegistry = svc.NewServiceRegistry()

	// Create services
	c.HTTPService = svc.NewHTTPService(c.ConfigManager, c.Logger)
	c.StreamService = svc.NewStreamService(c.StreamBuilder, c.Logger)
	c.WoTService = svc.NewWoTService(c.ThingRegistry, c.ConfigManager, c.Logger)

	// Register services
	c.ServiceRegistry.RegisterService("http", c.HTTPService)
	c.ServiceRegistry.RegisterService("stream", c.StreamService)
	c.ServiceRegistry.RegisterService("wot", c.WoTService)

	// Load permitted services based on license
	license := c.DeviceManager.GetLicense()
	if err := c.ServiceRegistry.LoadPermittedServices(license); err != nil {
		return err
	}

	c.Logger.Info("Services initialized")
	return nil
}

func (c *Container) wireDependencies() error {
	c.Logger.Debug("Wiring dependencies")

	// Wire WoT handler to HTTP service
	if httpSvc, ok := c.HTTPService.(*svc.HTTPService); ok {
		httpSvc.SetWoTHandler(c.WoTHandler)
	}

	// Wire stream integration
	integration := api.NewStreamIntegration(c.StateManager, c.StreamBridge, c.EventBroker)

	// Register Benthos processors
	env := service.NewEnvironment()
	if err := api.RegisterWoTProcessors(env, integration); err != nil {
		return err
	}

	// Create WoT streams
	if err := api.CreateWoTStreams(c.StreamBuilder, integration); err != nil {
		return err
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
	DBPath      string
	LicensePath string
	PublicKey   []byte
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
    `

	_, err := db.Exec(schema)
	return err
}
