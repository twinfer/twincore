// cmd/service/main.go
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/internal/container"
	"github.com/twinfer/twincore/pkg/types" // Import types package
	"github.com/twinfer/twincore/service"   // Import the concrete service package
)

var (
	licensePath    = flag.String("license", "/etc/twincore/license.jwt", "Path to license file")
	publicKey      = flag.String("pubkey", "/etc/twincore/public.key", "Path to public key")
	dbPath         = flag.String("db", "/var/lib/twincore/config.db", "Path to DuckDB database")
	logLevel       = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	apiPort        = flag.String("api-port", "8090", "API management port")
	parquetLogPath = flag.String("parquet-log-path", "./twincore_data", "Base path for Parquet log files")
)

func main() {
	flag.Parse()

	// Setup logger
	logger := logrus.New()
	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		logger.Fatal("Invalid log level")
	}
	logger.SetLevel(level)
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	logger.Info("twincore Gateway starting...")

	// Read public key
	pubKeyData, err := os.ReadFile(*publicKey)
	if err != nil {
		logger.Fatalf("Failed to read public key: %v", err)
	}

	// Create container config
	config := &container.Config{
		DBPath:         *dbPath,
		LicensePath:    *licensePath,
		PublicKey:      pubKeyData,
		ParquetLogPath: *parquetLogPath, // Populate from the new flag
	}

	// Initialize container
	ctx := context.Background()
	cnt, err := container.New(ctx, config)
	if err != nil {
		logger.Fatalf("Failed to initialize container: %v", err)
	}

	// Start services
	if err := cnt.Start(ctx); err != nil {
		logger.Fatalf("Failed to start services: %v", err)
	}

	// Start API management server
	apiServerErrChan := make(chan error, 1)
	apiServer := startAPIServer(cnt, *apiPort, logger, apiServerErrChan)

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1) // Ensure this is buffered enough if new senders are added.
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Health check ticker
	healthTicker := time.NewTicker(30 * time.Second)
	defer healthTicker.Stop()

	logger.Info("twincore Gateway started successfully")

	// Main loop
	for {
		select {
		case err := <-apiServerErrChan:
			logger.Errorf("API server failed: %v. Initiating shutdown...", err)
			// Trigger graceful shutdown. Sending to sigChan reuses existing shutdown logic.
			select {
			case sigChan <- syscall.SIGTERM: // Attempt to send to sigChan
			default: // If sigChan is full (e.g. already processing a signal)
				logger.Warn("sigChan is full, cannot send SIGTERM for API server error shutdown.")
				// As a fallback, directly initiate parts of shutdown or os.Exit if critical.
			}
		case <-sigChan:
			logger.Info("Shutting down twincore Gateway...")

			// Shutdown API server
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			if err := apiServer.Shutdown(shutdownCtx); err != nil {
				logger.Errorf("API server shutdown error: %v", err)
			}

			// Stop services
			if err := cnt.Stop(shutdownCtx); err != nil {
				logger.Errorf("Service shutdown error: %v", err)
			}

			logger.Info("Shutdown complete")
			os.Exit(0)

		case <-healthTicker.C:
			// Perform health checks
			if err := performHealthChecks(cnt, logger); err != nil {
				logger.Errorf("Health check failed: %v", err)
			}
		}
	}
}

// startAPIServer starts the management API server
func startAPIServer(cnt *container.Container, port string, logger *logrus.Logger, errChan chan<- error) *http.Server {
	mux := http.NewServeMux()

	// Thing management endpoints
	mux.HandleFunc("/api/things", thingHandler(cnt))
	mux.HandleFunc("/api/things/", thingItemHandler(cnt))

	// Configuration endpoints
	mux.HandleFunc("/api/config/caddy", caddyConfigHandler(cnt))
	mux.HandleFunc("/api/config/streams/", streamConfigHandler(cnt))

	// Health endpoint
	mux.HandleFunc("/health", healthHandler(cnt))

	server := &http.Server{
		Addr:    ":" + port,
		Handler: logMiddleware(mux, logger),
	}

	go func() {
		logger.Infof("API server listening on port %s", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Errorf("API server ListenAndServe error: %v", err) // Log the error
			// Send the error to the main goroutine for graceful shutdown
			select {
			case errChan <- err:
			default: // Should not happen if channel is buffered and read by select
				logger.Error("Failed to send API server error to main channel.")
			}
		}
	}()

	return server
}

// Helper function to respond with JSON
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload) // Error handling for marshal can be added if complex objects are used
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

// Helper function to respond with a JSON error
func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, map[string]string{"error": message})
}

// API Handlers

func thingHandler(cnt *container.Container) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// List things
			things, err := cnt.ThingRegistry.ListThings()
			if err != nil {
				respondWithError(w, http.StatusInternalServerError, err.Error())
				return
			}
			respondWithJSON(w, http.StatusOK, things)

		case http.MethodPost:
			// Register new thing
			body, err := io.ReadAll(r.Body)
			if err != nil {
				respondWithError(w, http.StatusBadRequest, "Failed to read request body: "+err.Error())
				return
			}

			td, err := cnt.ThingRegistry.RegisterThing(string(body))
			if err != nil {
				// Distinguish between client error (e.g., invalid TD) and server error
				if strings.Contains(err.Error(), "already exists") || strings.Contains(err.Error(), "validation failed") {
					respondWithError(w, http.StatusBadRequest, err.Error())
				} else {
					respondWithError(w, http.StatusInternalServerError, "Failed to register thing: "+err.Error())
				}
				return
			}

			// Generate and apply configs
			config, err := cnt.ThingRegistry.GenerateConfigs(td)
			if err != nil {
				// Log this, as TD registration succeeded but config generation failed.
				// Client might get a success for TD, but this is an internal issue.
				cnt.Logger.Errorf("Successfully registered TD %s, but failed to generate configs: %v", td.ID, err)
				respondWithError(w, http.StatusInternalServerError, "Failed to generate service configurations: "+err.Error())
				return
			}

			// --- Update Caddy Configuration ---
			// 1. Aggregate all HTTP routes from all registered Thing Descriptions
			allHTTPRoutes := []types.HTTPRoute{}
			allTDs, listErr := cnt.ThingRegistry.ListThings() // This includes the newly registered one
			if listErr != nil {
				cnt.Logger.Errorf("Failed to list all things for config aggregation: %v", listErr)
				respondWithError(w, http.StatusInternalServerError, "Failed to aggregate existing configurations: "+listErr.Error())
				return
			}
			for _, existingTD := range allTDs {
				tdUnifiedConfig, genErr := cnt.ThingRegistry.GenerateConfigs(existingTD)
				if genErr != nil {
					cnt.Logger.Warnf("Failed to generate config for TD %s during aggregation: %v", existingTD.ID, genErr)
					continue
				}
				if tdUnifiedConfig != nil {
					allHTTPRoutes = append(allHTTPRoutes, tdUnifiedConfig.HTTP.Routes...)
				}
			}

			cumulativeHTTPConfig := types.HTTPConfig{
				Routes: allHTTPRoutes,
			}

			// 2. Get the initial global security configuration for the HTTP service
			var initialSecurityConfig types.SecurityConfig
			initialServiceCfg := cnt.InitialHTTPServiceConfig // Use the field from the container

			if secCfg, secOk := initialServiceCfg.Config["security"].(types.SecurityConfig); secOk {
				initialSecurityConfig = secCfg
			} else {
				cnt.Logger.Warn("No initial security configuration found in InitialHTTPServiceConfig. Security features might not be active.")
				initialSecurityConfig = types.SecurityConfig{Enabled: false}
				return
			}

			// 3. Create ServiceConfig for HTTPService.generateCaddyConfig
			serviceCfgForCaddy := types.ServiceConfig{
				Config: map[string]interface{}{
					"http":     cumulativeHTTPConfig,
					"security": initialSecurityConfig,
				},
			}

			// 4. Generate the full Caddy config using HTTPService
			// Type assert cnt.HTTPService to the concrete *service.HTTPService
			httpSvc, ok := cnt.HTTPService.(*service.HTTPService)
			if !ok {
				cnt.Logger.Error("HTTPService in container is not of expected type *service.HTTPService")
				respondWithError(w, http.StatusInternalServerError, "Internal server error: HTTP service misconfiguration")
				return
			}
			fullCaddyCfg, genCaddyErr := httpSvc.GenerateCaddyConfig(serviceCfgForCaddy)
			if genCaddyErr != nil {
				cnt.Logger.Errorf("Failed to generate full Caddy config for TD %s: %v", td.ID, genCaddyErr)
				respondWithError(w, http.StatusInternalServerError, "Failed to generate Caddy service configuration: "+genCaddyErr.Error())
				return
			}

			// 5. Update Caddy config via ConfigManager
			if err := cnt.ConfigManager.UpdateCaddyConfig(fullCaddyCfg); err != nil {
				cnt.Logger.Errorf("Failed to update Caddy config after TD %s registration: %v", td.ID, err)
				respondWithError(w, http.StatusInternalServerError, "TD registered, but failed to update HTTP service configuration: "+err.Error())
				return
			}

			for _, topic := range config.Stream.Topics {
				if yaml, ok := topic.Config["yaml"].(string); ok {
					if err := cnt.ConfigManager.UpdateBenthosStream(topic.Name, yaml); err != nil {
						cnt.Logger.Errorf("Failed to update Benthos stream %s for TD %s after Caddy update: %v", topic.Name, td.ID, err)
						respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("TD registered, but failed to update stream configuration for %s: %v", topic.Name, err))
						return
					}
				}
			}
			respondWithJSON(w, http.StatusCreated, td) // Use 201 Created for new resources
		default:
			respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	}
}

func thingItemHandler(cnt *container.Container) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		thingID := strings.TrimPrefix(r.URL.Path, "/api/things/")

		switch r.Method {
		case http.MethodGet:
			// Get thing
			td, err := cnt.ThingRegistry.GetThing(thingID)
			if err != nil {
				respondWithError(w, http.StatusNotFound, err.Error())
				return
			}
			respondWithJSON(w, http.StatusOK, td)

		case http.MethodPut:
			// Update thing
			body, err := io.ReadAll(r.Body)
			if err != nil {
				respondWithError(w, http.StatusBadRequest, "Failed to read request body: "+err.Error())
				return
			}

			td, err := cnt.ThingRegistry.UpdateThing(thingID, string(body))
			if err != nil {
				respondWithError(w, http.StatusBadRequest, err.Error()) // Or InternalServerError depending on error type
				return
			}
			respondWithJSON(w, http.StatusOK, td)

		case http.MethodDelete:
			// Delete thing
			if err := cnt.ThingRegistry.DeleteThing(thingID); err != nil {
				respondWithError(w, http.StatusInternalServerError, err.Error())
				return
			}

			w.WriteHeader(http.StatusNoContent)

		default:
			respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	}
}

func caddyConfigHandler(cnt *container.Container) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			config, err := cnt.ConfigManager.GetCaddyConfig()
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(config)
		} else if r.Method == http.MethodPut {
			var config caddy.Config
			if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
				respondWithError(w, http.StatusBadRequest, "Invalid Caddy JSON config: "+err.Error())
				return
			}

			if err := cnt.ConfigManager.UpdateCaddyConfig(&config); err != nil {
				respondWithError(w, http.StatusInternalServerError, "Failed to update Caddy config: "+err.Error())
				return
			}
			w.WriteHeader(http.StatusNoContent)
		} else {
			respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	}
}

func streamConfigHandler(cnt *container.Container) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		streamName := strings.TrimPrefix(r.URL.Path, "/api/config/streams/")

		switch r.Method {
		case http.MethodGet:
			yaml, err := cnt.ConfigManager.GetBenthosConfig(streamName)
			if err != nil {
				respondWithError(w, http.StatusNotFound, err.Error())
				return
			}

			w.Header().Set("Content-Type", "text/yaml")
			w.Write([]byte(yaml))
		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				respondWithError(w, http.StatusBadRequest, "Failed to read request body: "+err.Error())
				return
			}

			if err := cnt.ConfigManager.UpdateBenthosStream(streamName, string(body)); err != nil {
				respondWithError(w, http.StatusInternalServerError, "Failed to update Benthos stream: "+err.Error())
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			respondWithError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
	}
}

func healthHandler(cnt *container.Container) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := map[string]interface{}{
			"status": "healthy",
			"time":   time.Now().UTC(),
		}

		// Check services
		if err := performHealthChecks(cnt, cnt.Logger); err != nil {
			status["status"] = "unhealthy"
			status["error"] = err.Error()
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		respondWithJSON(w, w.(*responseWriter).statusCode, status) // Use captured status code
	}
}

// Middleware

func logMiddleware(next http.Handler, logger *logrus.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Defer logging to ensure it happens after the handler has finished
		// and the status code has been potentially set by the handler.
		// However, the current setup logs after next.ServeHTTP which is correct.
		next.ServeHTTP(wrapped, r) // This will set wrapped.statusCode if WriteHeader is called

		logger.WithFields(logrus.Fields{
			"method":   r.Method,
			"path":     r.URL.Path,
			"status":   wrapped.statusCode,
			"duration": time.Since(start),
			"ip":       r.RemoteAddr,
		}).Info("API request")
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	// Only set the status code if it hasn't been set yet,
	// or to allow overriding if needed (though typically first WriteHeader wins).
	// For this simple wrapper, direct assignment is fine.
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Health checks

func performHealthChecks(cnt *container.Container, logger *logrus.Logger) error {
	// Check HTTP service
	if err := cnt.HTTPService.HealthCheck(); err != nil {
		logger.Errorf("HTTP service health check failed: %v", err)
		return err
	}

	// Check Stream service
	if err := cnt.StreamService.HealthCheck(); err != nil {
		logger.Errorf("Stream service health check failed: %v", err)
		return err
	}

	// Check WoT service
	if err := cnt.WoTService.HealthCheck(); err != nil {
		logger.Errorf("WoT service health check failed: %v", err)
		return err
	}

	// Check database
	if err := cnt.DB.Ping(); err != nil {
		logger.Errorf("Database health check failed: %v", err)
		return err
	}

	logger.Debug("All health checks passed")
	return nil
}
