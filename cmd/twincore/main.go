// Package main TwinCore Gateway
//
//	@title			TwinCore Gateway API
//	@version		1.0
//	@description	TwinCore Gateway is a Web of Things (WoT) gateway that manages IoT devices through W3C Thing Descriptions. It dynamically generates data processing pipelines using Benthos and exposes HTTP APIs for device interaction.
//	@termsOfService	http://swagger.io/terms/
//
//	@contact.name	TwinCore API Support
//	@contact.url	http://www.twinfer.com/support
//	@contact.email	support@twinfer.com
//
//	@license.name	Commercial License
//	@license.url	http://www.twinfer.com/license
//
//	@host		localhost:8080
//	@BasePath	/api
//
//	@securityDefinitions.apikey	BearerAuth
//	@in							header
//	@name						Authorization
//	@description				JWT Bearer token authentication. Format: "Bearer {token}"
//
//	@securityDefinitions.apikey	ApiKeyAuth
//	@in							header
//	@name						X-API-Key
//	@description				API key authentication for device access
//
//	@tag.name			Things
//	@tag.description	Web of Things (WoT) Thing Description management and device interactions
//
//	@tag.name			Properties
//	@tag.description	WoT Property interactions - read and write device properties
//
//	@tag.name			Actions
//	@tag.description	WoT Action invocations - execute device actions and commands
//
//	@tag.name			Events
//	@tag.description	WoT Event subscriptions - real-time event streaming via Server-Sent Events
//
//	@tag.name			Streams
//	@tag.description	Benthos stream management - data processing pipeline control
//
//	@tag.name			Processors
//	@tag.description	Benthos processor collection management
//
//	@tag.name			Bindings
//	@tag.description	Protocol binding generation from Thing Descriptions
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/caddyserver/caddy/v2"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// Standard Caddy modules
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	// Authentication module - loaded as Caddy plugin (will be optional)
	// _ "github.com/greenpau/caddy-security" // Temporarily disabled due to compilation issues

	// TwinCore custom modules
	_ "github.com/twinfer/twincore/internal/caddy_app"

	// Import our components
	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/caddy_app"
	"github.com/twinfer/twincore/internal/container"
)

// These will be populated during build process
// For now, we'll use embedded defaults

var publicKeyPEM = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890abcdefghijk
lmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmn
opqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqr
stuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuv
wxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz
ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCD
EFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGH
IJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL
MNOPQRSTUVWXYZ1234567890QIDAQAB
-----END PUBLIC KEY-----`)

var (
	// Command line flags
	licenseFile    = flag.String("license", "", "Path to license file")
	dbPath         = flag.String("db", "./twincore.db", "Path to database file")
	logLevel       = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	apiPort        = flag.String("api-port", "8090", "API server port")
	parquetLogPath = flag.String("parquet-log-path", "./twincore_data", "Path for Parquet log files")
	caddyMode      = flag.Bool("caddy-mode", false, "Run as pure Caddy (for external management)")
)

func main() {
	flag.Parse()

	// If running in caddy-mode, just start Caddy without TwinCore services
	if *caddyMode {
		caddycmd.Main()
		return
	}

	// Initialize logger
	logger := logrus.New()
	if level, err := logrus.ParseLevel(*logLevel); err == nil {
		logger.SetLevel(level)
	}

	logger.Info("Starting TwinCore Gateway...")

	// Create TwinCore container with all services
	cnt, err := container.New(context.Background(), &container.Config{
		DBPath:         *dbPath,
		LicensePath:    *licenseFile,
		PublicKey:      publicKeyPEM, // Use embedded public key
		ParquetLogPath: *parquetLogPath,
	})
	if err != nil {
		logger.WithError(err).Fatal("Failed to create container")
	}

	// Set global container for Caddy app module
	caddy_app.SetGlobalContainer(cnt)

	// Start TwinCore services
	if err := cnt.Start(context.Background()); err != nil {
		logger.WithError(err).Fatal("Failed to start TwinCore services")
	}

	// Start Caddy with minimal config - ConfigManager will handle the rest
	if err := startCaddy(logger); err != nil {
		logger.WithError(err).Fatal("Failed to start Caddy")
	}

	logger.Info("TwinCore Gateway started successfully")
	logger.Info("Portal: http://localhost:8080/portal")
	logger.Info("Admin API: http://localhost:2019")

	// Setup graceful shutdown
	setupGracefulShutdown(cnt, logger)
}

// startCaddy starts Caddy with minimal initial configuration
func startCaddy(logger *logrus.Logger) error {
	// Let Caddy start with default configuration
	// The ConfigManager will handle dynamic configuration via Admin API
	return caddy.Load(nil, false)
}

// setupGracefulShutdown handles graceful shutdown
func setupGracefulShutdown(cnt *container.Container, logger *logrus.Logger) {
	// Create channel to listen for interrupt signals
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Block until signal received
	<-c

	logger.Info("Shutting down TwinCore...")

	// Create context with timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Stop Caddy
	if err := caddy.Stop(); err != nil {
		logger.WithError(err).Error("Error stopping Caddy")
	}

	// Stop TwinCore services
	if err := cnt.Stop(ctx); err != nil {
		logger.WithError(err).Error("Error stopping TwinCore services")
	}

	logger.Info("TwinCore shutdown complete")
}
