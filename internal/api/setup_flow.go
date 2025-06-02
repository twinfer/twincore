package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

const RequestIDHeader = "X-Request-ID" // Request ID header for tracing

// SetupHandler provides first-time setup flow
type SetupHandler struct {
	configManager ConfigurationManager // Changed to interface type
	db            *sql.DB
	logger        logrus.FieldLogger
}

// NewSetupHandler creates a new setup handler
func NewSetupHandler(configManager ConfigurationManager, db *sql.DB, logger logrus.FieldLogger) *SetupHandler { // Changed parameter to interface type
	return &SetupHandler{
		configManager: configManager,
		db:            db,
		logger:        logger,
	}
}

// SetupStatusResponse returns the current setup status
type SetupStatusResponse struct {
	Complete   bool   `json:"complete"`
	Step       int    `json:"step"`
	TotalSteps int    `json:"total_steps"`
	NextStep   string `json:"next_step,omitempty"`
}

// GetSetupStatus returns the current setup status
func (h *SetupHandler) GetSetupStatus(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get(RequestIDHeader)
	if requestID == "" {
		requestID = uuid.NewString()
	}
	logger := h.logger.WithFields(logrus.Fields{"request_id": requestID, "handler_name": "GetSetupStatus", "method": r.Method, "path": r.URL.Path})
	logger.Debug("Handler called")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Handler finished")
	}()

	logger.WithFields(logrus.Fields{"dependency_name": "ConfigManager", "operation": "IsSetupComplete"}).Debug("Calling dependency")
	isComplete := h.configManager.IsSetupComplete() // Assuming IsSetupComplete doesn't need a logger

	status := SetupStatusResponse{
		Complete:   isComplete,
		TotalSteps: 4,
	}

	if !status.Complete {
		// Assuming getCurrentStep and getNextStepDescription are simple internal logic
		status.Step = h.getCurrentStep(logger)
		status.NextStep = h.getNextStepDescription(logger, status.Step)
		logger.WithFields(logrus.Fields{"is_complete": status.Complete, "current_step": status.Step, "next_step": status.NextStep}).Info("Setup not complete, returning current status")
	} else {
		logger.Info("Setup is complete")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// SetupRequest represents a setup configuration request
type SetupRequest struct {
	Step   int                    `json:"step"`
	Config map[string]interface{} `json:"config"`
}

// ProcessSetup handles setup steps
func (h *SetupHandler) ProcessSetup(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get(RequestIDHeader)
	if requestID == "" {
		requestID = uuid.NewString()
	}
	logger := h.logger.WithFields(logrus.Fields{"request_id": requestID, "handler_name": "ProcessSetup", "method": r.Method, "path": r.URL.Path})
	logger.Debug("Handler called")
	startTime := time.Now()
	defer func() {
		logger.WithField("duration_ms", time.Since(startTime).Milliseconds()).Debug("Handler finished")
	}()

	if r.Method != http.MethodPost {
		logger.Warn("Method not allowed for setup processing")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.WithError(err).Warn("Invalid JSON in setup request")
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	logger = logger.WithField("setup_step", req.Step)
	logger.Debug("Decoded setup request")

	switch req.Step {
	case 1:
		h.processLicenseStep(logger, w, req.Config)
	case 2:
		h.processAuthStep(logger, w, req.Config)
	case 3:
		h.processAdminUserStep(logger, w, req.Config)
	case 4:
		h.processFinalizeStep(logger, w, req.Config)
	default:
		logger.WithField("invalid_step", req.Step).Warn("Invalid setup step requested")
		http.Error(w, "Invalid step", http.StatusBadRequest)
	}
}

// Step 1: License configuration
func (h *SetupHandler) processLicenseStep(logger *logrus.Entry, w http.ResponseWriter, config map[string]interface{}) {
	entryLogger := logger.WithFields(logrus.Fields{"setup_sub_step": "processLicenseStep"})
	entryLogger.Debug("Processing license step")

	licenseKey, ok := config["license_key"].(string)
	if !ok || licenseKey == "" {
		entryLogger.Info("No license key provided, using default/trial license for setup")
	} else {
		entryLogger.Debug("Validating and saving provided license key")
		if err := h.validateAndSaveLicense(logger, licenseKey); err != nil { // Pass logger
			entryLogger.WithError(err).Error("Invalid license key provided")
			http.Error(w, "Invalid license: "+err.Error(), http.StatusBadRequest)
			return
		}
		entryLogger.Info("License validated and saved")
	}

	h.sendSetupResponse(w, "License configured successfully")
}

// Step 2: Authentication provider selection
func (h *SetupHandler) processAuthStep(logger *logrus.Entry, w http.ResponseWriter, config map[string]interface{}) {
	entryLogger := logger.WithFields(logrus.Fields{"setup_sub_step": "processAuthStep"})
	entryLogger.Debug("Processing auth provider step")

	providerType, ok := config["provider"].(string)
	if !ok {
		entryLogger.Warn("Provider type missing in auth step config")
		http.Error(w, "Provider type required", http.StatusBadRequest)
		return
	}
	entryLogger = entryLogger.WithField("auth_provider", providerType)

	// Configure the selected authentication provider
	authRequest := AuthConfigRequest{
		Provider: providerType,
		Config:   config,
		// License would be needed if isProviderAvailable checked it based on current license state
	}

	entryLogger.WithFields(logrus.Fields{"dependency_name": "ConfigManager", "operation": "ConfigureAuth"}).Debug("Calling dependency")
	if err := h.configManager.ConfigureAuth(logger, authRequest); err != nil { // Pass logger
		entryLogger.WithError(err).WithFields(logrus.Fields{"dependency_name": "ConfigManager", "operation": "ConfigureAuth"}).Error("Dependency call failed")
		http.Error(w, "Failed to configure auth: "+err.Error(), http.StatusInternalServerError)
		return
	}
	entryLogger.Info("Authentication configured successfully")
	h.sendSetupResponse(w, "Authentication configured successfully")
}

// Step 3: Create initial admin user
func (h *SetupHandler) processAdminUserStep(logger *logrus.Entry, w http.ResponseWriter, config map[string]interface{}) {
	entryLogger := logger.WithFields(logrus.Fields{"setup_sub_step": "processAdminUserStep"})
	entryLogger.Debug("Processing admin user creation step")

	username, ok := config["username"].(string)
	if !ok || username == "" {
		entryLogger.Warn("Username missing for admin user creation")
		http.Error(w, "Username required", http.StatusBadRequest)
		return
	}
	entryLogger = entryLogger.WithField("admin_username", username)

	password, ok := config["password"].(string)
	if !ok || password == "" {
		entryLogger.Warn("Password missing for admin user creation")
		http.Error(w, "Password required", http.StatusBadRequest)
		return
	}

	email, _ := config["email"].(string) // Email is optional

	entryLogger.WithFields(logrus.Fields{"dependency_name": "self", "operation": "createAdminUser"}).Debug("Calling internal method")
	if err := h.createAdminUser(logger, username, password, email); err != nil { // Pass logger
		entryLogger.WithError(err).Error("Failed to create admin user")
		http.Error(w, "Failed to create admin user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	entryLogger.Info("Admin user created successfully")
	h.sendSetupResponse(w, "Admin user created successfully")
}

// Step 4: Finalize setup
func (h *SetupHandler) processFinalizeStep(logger *logrus.Entry, w http.ResponseWriter, config map[string]interface{}) {
	entryLogger := logger.WithFields(logrus.Fields{"setup_sub_step": "processFinalizeStep"})
	entryLogger.Debug("Processing finalize setup step")

	// Mark setup as complete
	entryLogger.WithFields(logrus.Fields{"dependency_name": "ConfigManager", "operation": "CompleteSetup"}).Debug("Calling dependency")
	if err := h.configManager.CompleteSetup(logger); err != nil { // Pass logger
		entryLogger.WithError(err).WithFields(logrus.Fields{"dependency_name": "ConfigManager", "operation": "CompleteSetup"}).Error("Dependency call failed")
		http.Error(w, "Failed to complete setup: "+err.Error(), http.StatusInternalServerError)
		return
	}
	entryLogger.Info("Setup marked as complete via ConfigManager")

	// Apply initial configuration
	entryLogger.WithFields(logrus.Fields{"dependency_name": "self", "operation": "applyInitialConfiguration"}).Debug("Calling internal method")
	if err := h.applyInitialConfiguration(logger); err != nil { // Pass logger
		entryLogger.WithError(err).Warn("Failed to apply some initial configurations")
		// Not returning error to client for this, as setup is technically complete.
	}

	response := map[string]interface{}{
		"message":    "Setup completed successfully",
		"portal_url": "/portal/",
		"api_url":    "/api/v1/",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Helper methods

func (h *SetupHandler) getCurrentStep(logger logrus.FieldLogger) int {
	// Check what's been configured to determine current step
	// This would check database state
	logger.Debug("Determining current setup step (simplified)")
	return 1 // Simplified for now
}

func (h *SetupHandler) getNextStepDescription(logger logrus.FieldLogger, step int) string {
	logger.WithField("current_step_for_next_desc", step).Debug("Getting next step description")
	steps := map[int]string{
		1: "Configure license",
		2: "Select authentication provider",
		3: "Create admin user",
		4: "Finalize setup",
	}
	return steps[step]
}

func (h *SetupHandler) validateAndSaveLicense(logger logrus.FieldLogger, licenseKey string) error {
	// Validate license with existing license validator
	// Save to database
	logger.WithField("license_key_present", licenseKey != "").Info("License validation/saving logic not fully implemented yet")
	return nil
}

func (h *SetupHandler) createAdminUser(logger logrus.FieldLogger, username, password, email string) error {
	logger = logger.WithFields(logrus.Fields{"admin_username": username, "email": email})
	logger.Info("Attempting to create admin user in database")
	// Hash password and create user in database
	logger.WithFields(logrus.Fields{"dependency_name": "Database", "operation": "Exec"}).Debug("Calling dependency")
	_, err := h.db.Exec(`
		INSERT INTO portal_users (id, username, email, password_hash, roles, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
	`, generateID(), username, email, hashPassword(password), `["admin"]`) // generateID and hashPassword are placeholders

	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"dependency_name": "Database", "operation": "Exec"}).Error("Dependency call failed")
	} else {
		logger.Info("Admin user DB insert successful")
	}
	return err
}

func (h *SetupHandler) applyInitialConfiguration(logger logrus.FieldLogger) error {
	// Apply default configurations
	// Start services
	logger.Info("Applying initial configuration (placeholder)")
	return nil
}

func (h *SetupHandler) sendSetupResponse(w http.ResponseWriter, message string) {
	// This is a utility, might not need its own logger context if callers log sufficiently.
	// For now, no separate logger.
	response := map[string]string{"message": message}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Utility functions (simplified)
func generateID() string {
	return "user_" + "random_id" // Use proper UUID generation
}

func hashPassword(password string) string {
	// Use proper password hashing (bcrypt)
	return "hashed_" + password // Placeholder
}
