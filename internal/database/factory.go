package database

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
)

// DatabaseFactory creates and configures database components
type DatabaseFactory struct {
	manager        *Manager
	transactionMgr *TransactionManager
	migrationMgr   *MigrationManager
	logger         *logrus.Logger
}

// NewDatabaseFactory creates a new database factory
func NewDatabaseFactory(dbPath string, logger *logrus.Logger) (*DatabaseFactory, error) {
	// Create database manager with default config
	config := DefaultConfig()
	manager, err := NewManager(dbPath, logger, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create database manager: %w", err)
	}

	// Create transaction manager
	transactionMgr := NewTransactionManager(manager, logger)

	// Create migration manager
	migrationMgr := NewMigrationManager(manager, logger)

	factory := &DatabaseFactory{
		manager:        manager,
		transactionMgr: transactionMgr,
		migrationMgr:   migrationMgr,
		logger:         logger,
	}

	return factory, nil
}

// Initialize runs database migrations and performs initial setup
func (df *DatabaseFactory) Initialize(ctx context.Context) error {
	df.logger.Info("Initializing database")

	// Run migrations
	if err := df.migrationMgr.RunMigrations(ctx); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	// Validate migrations
	if err := df.migrationMgr.ValidateMigrations(ctx); err != nil {
		return fmt.Errorf("migration validation failed: %w", err)
	}

	df.logger.Info("Database initialization completed")
	return nil
}

// GetManager returns the database manager
func (df *DatabaseFactory) GetManager() DatabaseManager {
	return df.manager
}

// GetTransactionManager returns the transaction manager
func (df *DatabaseFactory) GetTransactionManager() TransactionExecutor {
	return df.transactionMgr
}

// GetMigrationManager returns the migration manager
func (df *DatabaseFactory) GetMigrationManager() MigrationExecutor {
	return df.migrationMgr
}

// Repository creation methods will be implemented in repository_factory.go
// to avoid import cycles

// Close closes the database factory and all its resources
func (df *DatabaseFactory) Close() error {
	return df.manager.Close()
}

// IsHealthy returns the overall health status of the database system
func (df *DatabaseFactory) IsHealthy() bool {
	return df.manager.IsHealthy()
}

// GetMetrics returns database performance metrics
func (df *DatabaseFactory) GetMetrics() DatabaseMetrics {
	queryStats := df.manager.GetQueryStats()

	return DatabaseMetrics{
		IsHealthy:    df.manager.IsHealthy(),
		QueryStats:   queryStats,
		QueryCount:   len(queryStats),
		TotalQueries: df.getTotalQueryCount(queryStats),
	}
}

// getTotalQueryCount calculates total query executions across all queries
func (df *DatabaseFactory) getTotalQueryCount(stats map[string]*QueryStats) int64 {
	var total int64
	for _, stat := range stats {
		total += stat.Count
	}
	return total
}

// DatabaseMetrics holds database performance and health metrics
type DatabaseMetrics struct {
	IsHealthy    bool                   `json:"is_healthy"`
	QueryStats   map[string]*QueryStats `json:"query_stats"`
	QueryCount   int                    `json:"query_count"`
	TotalQueries int64                  `json:"total_queries"`
}

// CreateDatabaseFactory is a convenience function for dependency injection
func CreateDatabaseFactory(dbPath string, logger *logrus.Logger) (*DatabaseFactory, error) {
	return NewDatabaseFactory(dbPath, logger)
}

// DatabaseConfig holds configuration for the database factory
type DatabaseConfig struct {
	DBPath              string
	MaxRetries          int
	HealthCheckInterval string
	QueryTimeout        string
	EnableQueryStats    bool
	AutoMigrate         bool
}

// NewDatabaseFactoryWithConfig creates a database factory with custom configuration
func NewDatabaseFactoryWithConfig(config DatabaseConfig, logger *logrus.Logger) (*DatabaseFactory, error) {
	// Convert config to manager config
	managerConfig := DefaultConfig()
	managerConfig.DBPath = config.DBPath

	if config.MaxRetries > 0 {
		managerConfig.MaxRetries = config.MaxRetries
	}

	managerConfig.EnableQueryStats = config.EnableQueryStats

	// Create manager with custom config
	manager, err := NewManager(config.DBPath, logger, managerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create database manager: %w", err)
	}

	// Create other managers
	transactionMgr := NewTransactionManager(manager, logger)
	migrationMgr := NewMigrationManager(manager, logger)

	factory := &DatabaseFactory{
		manager:        manager,
		transactionMgr: transactionMgr,
		migrationMgr:   migrationMgr,
		logger:         logger,
	}

	// Auto-migrate if enabled
	if config.AutoMigrate {
		ctx := context.Background()
		if err := factory.Initialize(ctx); err != nil {
			factory.Close() // Clean up on failure
			return nil, fmt.Errorf("failed to auto-migrate: %w", err)
		}
	}

	return factory, nil
}
