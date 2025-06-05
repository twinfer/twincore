package database

import (
	"context"
	"database/sql"
	"time"

	"github.com/twinfer/twincore/pkg/types"
)

// DatabaseManager defines the interface for centralized database access
type DatabaseManager interface {
	// Query operations
	Execute(ctx context.Context, queryName string, args ...any) (sql.Result, error)
	Query(ctx context.Context, queryName string, args ...any) (*sql.Rows, error)
	QueryRow(ctx context.Context, queryName string, args ...any) *sql.Row
	
	// Transaction operations
	Transaction(ctx context.Context, fn func(*sql.Tx) error) error
	
	// Query management
	GetQuery(name string) (string, error)
	ListQueries() []string
	
	// Health and monitoring
	IsHealthy() bool
	GetQueryStats() map[string]*QueryStats
	
	// Connection management
	Close() error
	GetConnection() *sql.DB
}

// TransactionExecutor defines the interface for transaction operations
type TransactionExecutor interface {
	ExecuteWithRetry(ctx context.Context, options *TxOptions, fn func(*sql.Tx) error) error
	BatchExecute(ctx context.Context, operations []BatchOperation) error
	
	// Predefined transaction patterns
	CreateThingWithStreams(ctx context.Context, thingID, title, description, tdJSONLD, tdParsed string, streamConfigs []StreamConfig) error
	UpdateThingAndCleanupStreams(ctx context.Context, thingID, title, description, tdJSONLD, tdParsed string, streamsToDelete []string) error
	CreateUserWithSession(ctx context.Context, username, passwordHash, roles, email, name string, sessionData SessionData) error
	
	// Transaction utilities
	NewQueryOperation(name, queryName string, args ...any) BatchOperation
	GetTransactionStats() *TransactionStats
}

// MigrationExecutor defines the interface for database migrations
type MigrationExecutor interface {
	RunMigrations(ctx context.Context) error
	RollbackMigration(ctx context.Context) error
	GetMigrationStatus(ctx context.Context) ([]MigrationStatus, error)
	ValidateMigrations(ctx context.Context) error
	GetCurrentVersion(ctx context.Context) (int, error)
}

// RepositoryBase defines common repository operations
type RepositoryBase interface {
	// Health check
	IsHealthy(ctx context.Context) bool
}

// ThingRepositoryInterface defines Thing Description data access operations
type ThingRepositoryInterface interface {
	RepositoryBase
	
	Create(ctx context.Context, thing *ThingEntity) error
	GetByID(ctx context.Context, id string) (*ThingEntity, error)
	GetParsedByID(ctx context.Context, id string) (string, error)
	Update(ctx context.Context, thing *ThingEntity) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, limit, offset int) ([]*ThingEntity, error)
	ListParsedOnly(ctx context.Context) ([]string, error)
	Count(ctx context.Context) (int, error)
	Exists(ctx context.Context, id string) (bool, error)
	SearchByTitle(ctx context.Context, titlePattern string) ([]*ThingEntity, error)
}

// SecurityRepositoryInterface defines security data access operations
type SecurityRepositoryInterface interface {
	RepositoryBase
	
	// User management
	CreateUser(ctx context.Context, user *types.LocalUser) error
	GetUser(ctx context.Context, username string) (*types.LocalUser, error)
	GetUserForAuth(ctx context.Context, username string) (*UserAuthData, error)
	UpdateUser(ctx context.Context, user *types.LocalUser) error
	DeleteUser(ctx context.Context, username string) error
	ListUsers(ctx context.Context) ([]*types.LocalUser, error)
	UserExists(ctx context.Context, username string) (bool, error)
	UpdateLastLogin(ctx context.Context, username string) error
	
	// Session management
	CreateSession(ctx context.Context, session *types.UserSession) error
	GetSession(ctx context.Context, sessionID string) (*types.UserSession, error)
	GetSessionByToken(ctx context.Context, token string) (*types.UserSession, error)
	UpdateSessionActivity(ctx context.Context, sessionID string) error
	DeleteSession(ctx context.Context, sessionID string) error
	DeleteExpiredSessions(ctx context.Context) error
	DeleteUserSessions(ctx context.Context, username string) error
	
	// Security policies
	CreateThingSecurityPolicy(ctx context.Context, thingID, policyData string) error
	GetThingSecurityPolicy(ctx context.Context, thingID string) (string, error)
	DeleteThingSecurityPolicy(ctx context.Context, thingID string) error
	
	// API policies
	CreateAPIPolicy(ctx context.Context, policy *types.APIPolicy) error
	GetAPIPolicy(ctx context.Context, id string) (*types.APIPolicy, error)
	ListEnabledAPIPolicies(ctx context.Context) ([]*types.APIPolicy, error)
	UpdateAPIPolicy(ctx context.Context, policy *types.APIPolicy) error
	DeleteAPIPolicy(ctx context.Context, id string) error
	
	// Audit logging
	CreateAuditEvent(ctx context.Context, event *types.AuditEvent) error
	GetAuditEvents(ctx context.Context, startTime, endTime time.Time, limit int) ([]*types.AuditEvent, error)
	GetUserAuditEvents(ctx context.Context, userID string, since time.Time, limit int) ([]*types.AuditEvent, error)
	DeleteOldAuditEvents(ctx context.Context, before time.Time) error
}

// StreamRepositoryInterface defines stream data access operations
type StreamRepositoryInterface interface {
	RepositoryBase
	
	// Stream configuration
	CreateStreamConfig(ctx context.Context, config *types.StreamInfo) error
	GetStreamConfig(ctx context.Context, streamID string) (*types.StreamInfo, error)
	UpdateStreamConfig(ctx context.Context, config *types.StreamInfo) error
	UpdateStreamStatus(ctx context.Context, streamID, status string) error
	DeleteStreamConfig(ctx context.Context, streamID string) error
	HardDeleteStreamConfig(ctx context.Context, streamID string) error
	ListActiveStreams(ctx context.Context) ([]*types.StreamInfo, error)
	ListStreamsByThing(ctx context.Context, thingID string) ([]*types.StreamInfo, error)
	ListStreamsByStatus(ctx context.Context, status string) ([]*types.StreamInfo, error)
	CountActiveStreams(ctx context.Context) (int, error)
	StreamExists(ctx context.Context, streamID string) (bool, error)
	
	// Property state
	UpsertPropertyState(ctx context.Context, thingID, propertyName, value string) error
	GetPropertyState(ctx context.Context, thingID, propertyName string) (*PropertyStateEntity, error)
	GetThingProperties(ctx context.Context, thingID string) ([]*PropertyStateEntity, error)
	GetAllPropertyStates(ctx context.Context) ([]*PropertyStateEntity, error)
	DeletePropertyState(ctx context.Context, thingID, propertyName string) error
	DeleteThingProperties(ctx context.Context, thingID string) error
	GetPropertyValue(ctx context.Context, thingID, propertyName string) (string, error)
	
	// Action state
	CreateActionState(ctx context.Context, action *ActionStateEntity) error
	GetActionState(ctx context.Context, actionID string) (*ActionStateEntity, error)
	UpdateActionState(ctx context.Context, actionID, output, status, errorMsg string) error
	ListActionsByThing(ctx context.Context, thingID string) ([]*ActionStateEntity, error)
	ListActionsByStatus(ctx context.Context, status string) ([]*ActionStateEntity, error)
	DeleteActionState(ctx context.Context, actionID string) error
	DeleteCompletedActions(ctx context.Context, before time.Time) error
	
	// Cleanup operations
	CleanupOldPropertyStates(ctx context.Context, before time.Time) error
	CleanupDeletedStreams(ctx context.Context, before time.Time) error
}

// ConfigRepositoryInterface defines configuration data access operations
type ConfigRepositoryInterface interface {
	RepositoryBase
	
	// General configuration
	UpsertConfig(ctx context.Context, id, configType, data string) error
	GetConfig(ctx context.Context, id string) (*ConfigEntity, error)
	GetConfigsByType(ctx context.Context, configType string) ([]*ConfigEntity, error)
	DeleteConfig(ctx context.Context, id string) error
	ListAllConfigs(ctx context.Context) ([]*ConfigEntity, error)
	ConfigExists(ctx context.Context, id string) (bool, error)
	
	// Caddy configuration
	CreateCaddyConfig(ctx context.Context, config, patches string, version int) error
	GetActiveCaddyConfig(ctx context.Context) (*CaddyConfigEntity, error)
	GetCaddyConfigByVersion(ctx context.Context, version int) (*CaddyConfigEntity, error)
	SetActiveCaddyConfig(ctx context.Context, version int) error
	ListCaddyConfigs(ctx context.Context) ([]*CaddyConfigEntity, error)
	DeleteOldCaddyConfigs(ctx context.Context, keepVersions int) error
	GetLatestCaddyConfigVersion(ctx context.Context) (int, error)
	CountCaddyConfigs(ctx context.Context) (int, error)
	
	// Stream configuration storage
	UpsertStreamConfig(ctx context.Context, id, data string) error
	GetStreamConfig(ctx context.Context, id string) (*ConfigEntity, error)
	DeleteStreamConfig(ctx context.Context, id string) error
	ListStreamConfigs(ctx context.Context) ([]*ConfigEntity, error)
	
	// Application settings
	UpsertAppSetting(ctx context.Context, id, data string) error
	GetAppSetting(ctx context.Context, id string) (string, error)
	ListAppSettings(ctx context.Context) ([]*ConfigEntity, error)
}

// Database-specific entity types that don't exist in pkg/types

// ThingEntity represents a Thing Description database entity
type ThingEntity struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	TDJSONLD    string    `json:"td_jsonld"`
	TDParsed    string    `json:"td_parsed"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// UserAuthData represents minimal user data for authentication
type UserAuthData struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	Roles        string `json:"roles"`
	Disabled     bool   `json:"disabled"`
}

// PropertyStateEntity represents property state data
type PropertyStateEntity struct {
	ThingID      string    `json:"thing_id"`
	PropertyName string    `json:"property_name"`
	Value        string    `json:"value"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// ActionStateEntity represents action execution state
type ActionStateEntity struct {
	ActionID    string     `json:"action_id"`
	ThingID     string     `json:"thing_id"`
	ActionName  string     `json:"action_name"`
	Input       *string    `json:"input"`
	Output      *string    `json:"output"`
	Status      string     `json:"status"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
	Error       *string    `json:"error"`
}

// ConfigEntity represents configuration data
type ConfigEntity struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Data      string    `json:"data"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CaddyConfigEntity represents Caddy configuration with versioning
type CaddyConfigEntity struct {
	ID        int        `json:"id"`
	Config    string     `json:"config"`
	Patches   *string    `json:"patches"`
	Version   int        `json:"version"`
	Active    bool       `json:"active"`
	CreatedAt time.Time  `json:"created_at"`
}