// cmd/service/main.go
package main

import (
	"context"
	"encoding/json"
	"flag"
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
)

var (
	licensePath = flag.String("license", "/etc/twinedge/license.jwt", "Path to license file")
	publicKey   = flag.String("pubkey", "/etc/twinedge/public.key", "Path to public key")
	dbPath      = flag.String("db", "/var/lib/twinedge/config.db", "Path to DuckDB database")
	logLevel    = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	apiPort     = flag.String("api-port", "8090", "API management port")
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

	logger.Info("TwinEdge Gateway starting...")

	// Read public key
	pubKeyData, err := os.ReadFile(*publicKey)
	if err != nil {
		logger.Fatalf("Failed to read public key: %v", err)
	}

	// Create container config
	config := &container.Config{
		DBPath:      *dbPath,
		LicensePath: *licensePath,
		PublicKey:   pubKeyData,
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

	logger.Info("TwinEdge Gateway started successfully")

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
			logger.Info("Shutting down TwinEdge Gateway...")

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

// API Handlers

func thingHandler(cnt *container.Container) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			// List things
			things, err := cnt.ThingRegistry.ListThings()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(things)

		case http.MethodPost:
			// Register new thing
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			td, err := cnt.ThingRegistry.RegisterThing(string(body))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			// Generate and apply configs
			config, err := cnt.ThingRegistry.GenerateConfigs(td)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Update Caddy config
			if err := cnt.ConfigManager.UpdateCaddyConfig(config.HTTP); err != nil {
				cnt.Logger.Errorf("Failed to update Caddy config: %v", err)
			}

			// Update Benthos streams
			for _, topic := range config.Stream.Topics {
				if yaml, ok := topic.Config["yaml"].(string); ok {
					cnt.ConfigManager.UpdateBenthosStream(topic.Name, yaml)
				}
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(td)

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(td)

		case http.MethodPut:
			// Update thing
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			td, err := cnt.ThingRegistry.UpdateThing(thingID, string(body))
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(td)

		case http.MethodDelete:
			// Delete thing
			if err := cnt.ThingRegistry.DeleteThing(thingID); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func caddyConfigHandler(cnt *container.Container) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			config, err := cnt.ConfigManager.GetCaddyConfig()
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(config)

		case http.MethodPut:
			var config caddy.Config
			if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			if err := cnt.ConfigManager.UpdateCaddyConfig(&config); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}

			w.Header().Set("Content-Type", "text/yaml")
			w.Write([]byte(yaml))

		case http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			if err := cnt.ConfigManager.UpdateBenthosStream(streamName, string(body)); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			w.WriteHeader(http.StatusNoContent)

		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
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

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	}
}

// Middleware

func logMiddleware(next http.Handler, logger *logrus.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

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
