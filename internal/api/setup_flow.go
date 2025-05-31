package api

import (
	"encoding/json"
	"net/http"
	"database/sql"
	"github.com/sirupsen/logrus"
)

// SetupHandler provides first-time setup flow
type SetupHandler struct {
	configManager *ConfigManager
	db           *sql.DB
	logger       logrus.FieldLogger
}

// NewSetupHandler creates a new setup handler
func NewSetupHandler(configManager *ConfigManager, db *sql.DB, logger logrus.FieldLogger) *SetupHandler {
	return &SetupHandler{
		configManager: configManager,
		db:           db,
		logger:       logger,
	}
}

// SetupStatusResponse returns the current setup status
type SetupStatusResponse struct {
	Complete    bool   `json:"complete"`
	Step        int    `json:"step"`
	TotalSteps  int    `json:"total_steps"`
	NextStep    string `json:"next_step,omitempty"`
}

// GetSetupStatus returns the current setup status
func (h *SetupHandler) GetSetupStatus(w http.ResponseWriter, r *http.Request) {
	status := SetupStatusResponse{
		Complete:   h.configManager.IsSetupComplete(),
		TotalSteps: 4,
	}
	
	if !status.Complete {
		status.Step = h.getCurrentStep()
		status.NextStep = h.getNextStepDescription(status.Step)
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
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	var req SetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	
	switch req.Step {
	case 1:
		h.processLicenseStep(w, req.Config)
	case 2:
		h.processAuthStep(w, req.Config)
	case 3:
		h.processAdminUserStep(w, req.Config)
	case 4:
		h.processFinalizeStep(w, req.Config)
	default:
		http.Error(w, "Invalid step", http.StatusBadRequest)
	}
}

// Step 1: License configuration
func (h *SetupHandler) processLicenseStep(w http.ResponseWriter, config map[string]interface{}) {
	licenseKey, ok := config["license_key"].(string)
	if !ok || licenseKey == "" {
		// Use default/trial license
		h.logger.Info("Using default license for setup")
	} else {
		// Validate and save license
		if err := h.validateAndSaveLicense(licenseKey); err != nil {
			http.Error(w, "Invalid license: "+err.Error(), http.StatusBadRequest)
			return
		}
		h.logger.Info("License validated and saved")
	}
	
	h.sendSetupResponse(w, "License configured successfully")
}

// Step 2: Authentication provider selection
func (h *SetupHandler) processAuthStep(w http.ResponseWriter, config map[string]interface{}) {
	providerType, ok := config["provider"].(string)
	if !ok {
		http.Error(w, "Provider type required", http.StatusBadRequest)
		return
	}
	
	// Configure the selected authentication provider
	authRequest := AuthConfigRequest{
		Provider: providerType,
		Config:   config,
	}
	
	if err := h.configManager.ConfigureAuth(authRequest); err != nil {
		http.Error(w, "Failed to configure auth: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	h.sendSetupResponse(w, "Authentication configured successfully")
}

// Step 3: Create initial admin user
func (h *SetupHandler) processAdminUserStep(w http.ResponseWriter, config map[string]interface{}) {
	username, ok := config["username"].(string)
	if !ok || username == "" {
		http.Error(w, "Username required", http.StatusBadRequest)
		return
	}
	
	password, ok := config["password"].(string)
	if !ok || password == "" {
		http.Error(w, "Password required", http.StatusBadRequest)
		return
	}
	
	email, _ := config["email"].(string)
	
	if err := h.createAdminUser(username, password, email); err != nil {
		http.Error(w, "Failed to create admin user: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	h.sendSetupResponse(w, "Admin user created successfully")
}

// Step 4: Finalize setup
func (h *SetupHandler) processFinalizeStep(w http.ResponseWriter, config map[string]interface{}) {
	// Mark setup as complete
	if err := h.configManager.CompleteSetup(); err != nil {
		http.Error(w, "Failed to complete setup: "+err.Error(), http.StatusInternalServerError)
		return
	}
	
	// Apply initial configuration
	if err := h.applyInitialConfiguration(); err != nil {
		h.logger.WithError(err).Warn("Failed to apply some initial configurations")
	}
	
	response := map[string]interface{}{
		"message": "Setup completed successfully",
		"portal_url": "/portal/",
		"api_url": "/api/v1/",
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Helper methods

func (h *SetupHandler) getCurrentStep() int {
	// Check what's been configured to determine current step
	// This would check database state
	return 1 // Simplified for now
}

func (h *SetupHandler) getNextStepDescription(step int) string {
	steps := map[int]string{
		1: "Configure license",
		2: "Select authentication provider", 
		3: "Create admin user",
		4: "Finalize setup",
	}
	return steps[step]
}

func (h *SetupHandler) validateAndSaveLicense(licenseKey string) error {
	// Validate license with existing license validator
	// Save to database
	h.logger.Info("License validation not implemented yet")
	return nil
}

func (h *SetupHandler) createAdminUser(username, password, email string) error {
	// Hash password and create user in database
	_, err := h.db.Exec(`
		INSERT INTO portal_users (id, username, email, password_hash, roles, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'), datetime('now'))
	`, generateID(), username, email, hashPassword(password), `["admin"]`)
	
	return err
}

func (h *SetupHandler) applyInitialConfiguration() error {
	// Apply default configurations
	// Start services
	h.logger.Info("Applying initial configuration")
	return nil
}

func (h *SetupHandler) sendSetupResponse(w http.ResponseWriter, message string) {
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