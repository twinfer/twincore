package database

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sirupsen/logrus"
)

//go:embed queries/*.sql
var queryFiles embed.FS

// Manager provides centralized access to SQLite with single-writer coordination
type Manager struct {
	db           *sql.DB
	logger       *logrus.Logger
	dbPath       string
	queries      map[string]string
	mu           sync.RWMutex // Coordinates access for SQLite's single-writer limitation
	connectionMu sync.Mutex   // Protects connection operations
	healthTicker *time.Ticker
	isHealthy    bool
	queryStats   map[string]*QueryStats
	statsMu      sync.RWMutex
}

// QueryStats tracks performance metrics for queries
type QueryStats struct {
	Count         int64
	TotalDuration time.Duration
	AvgDuration   time.Duration
	LastExecuted  time.Time
	ErrorCount    int64
}

// Config holds database manager configuration
type Config struct {
	DBPath              string
	MaxRetries          int
	RetryDelay          time.Duration
	HealthCheckInterval time.Duration
	QueryTimeout        time.Duration
	EnableQueryStats    bool
}

// DefaultConfig returns a sensible default configuration
func DefaultConfig() *Config {
	return &Config{
		MaxRetries:          3,
		RetryDelay:          100 * time.Millisecond,
		HealthCheckInterval: 30 * time.Second,
		QueryTimeout:        30 * time.Second,
		EnableQueryStats:    true,
	}
}

// NewManager creates a new database manager with single-writer coordination
func NewManager(dbPath string, logger *logrus.Logger, config *Config) (*Manager, error) {
	if config == nil {
		config = DefaultConfig()
	}
	config.DBPath = dbPath

	manager := &Manager{
		dbPath:     dbPath,
		logger:     logger,
		queries:    make(map[string]string),
		queryStats: make(map[string]*QueryStats),
		isHealthy:  true,
	}

	// Load SQL queries from embedded files
	if err := manager.loadQueries(); err != nil {
		return nil, fmt.Errorf("failed to load queries: %w", err)
	}

	// Establish database connection
	if err := manager.connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Start health monitoring
	if config.HealthCheckInterval > 0 {
		manager.startHealthMonitoring(config.HealthCheckInterval)
	}

	manager.logger.Info("Database manager initialized successfully")
	return manager, nil
}

// connect establishes the database connection
func (m *Manager) connect() error {
	m.connectionMu.Lock()
	defer m.connectionMu.Unlock()

	// Build connection string with SQLite pragmas
	connStr := fmt.Sprintf("%s?_foreign_keys=1&_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=5000", m.dbPath)
	db, err := sql.Open("sqlite3", connStr)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool for SQLite
	db.SetMaxOpenConns(1)    // SQLite single-writer limitation
	db.SetMaxIdleConns(1)    // Keep connection alive
	db.SetConnMaxLifetime(0) // No connection expiration

	// Enable SQLite optimizations
	if _, err := db.Exec("PRAGMA temp_store = MEMORY"); err != nil {
		db.Close()
		return fmt.Errorf("failed to set temp_store pragma: %w", err)
	}
	if _, err := db.Exec("PRAGMA mmap_size = 268435456"); err != nil {
		db.Close()
		return fmt.Errorf("failed to set mmap_size pragma: %w", err)
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return fmt.Errorf("failed to ping database: %w", err)
	}

	m.db = db
	m.logger.WithField("db_path", m.dbPath).Info("Database connection established")
	return nil
}

// loadQueries loads all SQL queries from embedded files
func (m *Manager) loadQueries() error {
	entries, err := queryFiles.ReadDir("queries")
	if err != nil {
		return fmt.Errorf("failed to read queries directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !entry.Type().IsRegular() {
			continue
		}

		filename := entry.Name()
		content, err := queryFiles.ReadFile("queries/" + filename)
		if err != nil {
			return fmt.Errorf("failed to read query file %s: %w", filename, err)
		}

		// Parse SQL file and extract named queries
		if err := m.parseQueryFile(filename, string(content)); err != nil {
			return fmt.Errorf("failed to parse query file %s: %w", filename, err)
		}
	}

	m.logger.WithField("query_count", len(m.queries)).Info("SQL queries loaded successfully")
	return nil
}

// parseQueryFile extracts named queries from SQL content
func (m *Manager) parseQueryFile(filename, content string) error {
	queries := parseNamedQueries(content)
	for name, query := range queries {
		if _, exists := m.queries[name]; exists {
			return fmt.Errorf("duplicate query name '%s' in file %s", name, filename)
		}
		m.queries[name] = query
	}
	return nil
}

// GetQuery retrieves a named query
func (m *Manager) GetQuery(name string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	query, exists := m.queries[name]
	if !exists {
		return "", fmt.Errorf("query '%s' not found", name)
	}
	return query, nil
}

// Execute runs a named query with parameters and returns the result
func (m *Manager) Execute(ctx context.Context, queryName string, args ...any) (sql.Result, error) {
	start := time.Now()
	defer func() {
		m.recordQueryStats(queryName, time.Since(start), nil)
	}()

	query, err := m.GetQuery(queryName)
	if err != nil {
		m.recordQueryStats(queryName, time.Since(start), err)
		return nil, err
	}

	// Use write lock for SQLite single-writer coordination
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isHealthy {
		return nil, fmt.Errorf("database is not healthy")
	}

	result, err := m.db.ExecContext(ctx, query, args...)
	if err != nil {
		m.recordQueryStats(queryName, time.Since(start), err)
		m.logger.WithFields(logrus.Fields{
			"query":    queryName,
			"error":    err.Error(),
			"duration": time.Since(start),
		}).Error("Query execution failed")
		return nil, err
	}

	m.logger.WithFields(logrus.Fields{
		"query":    queryName,
		"duration": time.Since(start),
	}).Debug("Query executed successfully")

	return result, nil
}

// Query runs a named query and returns rows
func (m *Manager) Query(ctx context.Context, queryName string, args ...any) (*sql.Rows, error) {
	start := time.Now()
	defer func() {
		m.recordQueryStats(queryName, time.Since(start), nil)
	}()

	query, err := m.GetQuery(queryName)
	if err != nil {
		m.recordQueryStats(queryName, time.Since(start), err)
		return nil, err
	}

	// Use read lock for queries that don't modify data
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.isHealthy {
		return nil, fmt.Errorf("database is not healthy")
	}

	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		m.recordQueryStats(queryName, time.Since(start), err)
		m.logger.WithFields(logrus.Fields{
			"query":    queryName,
			"error":    err.Error(),
			"duration": time.Since(start),
		}).Error("Query failed")
		return nil, err
	}

	m.logger.WithFields(logrus.Fields{
		"query":    queryName,
		"duration": time.Since(start),
	}).Debug("Query executed successfully")

	return rows, nil
}

// QueryRow runs a named query and returns a single row
func (m *Manager) QueryRow(ctx context.Context, queryName string, args ...any) *sql.Row {
	start := time.Now()
	defer func() {
		m.recordQueryStats(queryName, time.Since(start), nil)
	}()

	query, err := m.GetQuery(queryName)
	if err != nil {
		m.recordQueryStats(queryName, time.Since(start), err)
		// Return a Row that will return the error when scanned
		return &sql.Row{}
	}

	// Use read lock for single row queries
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.isHealthy {
		// Return a Row that will return the error when scanned
		return &sql.Row{}
	}

	row := m.db.QueryRowContext(ctx, query, args...)

	m.logger.WithFields(logrus.Fields{
		"query":    queryName,
		"duration": time.Since(start),
	}).Debug("QueryRow executed")

	return row
}

// Transaction provides a database transaction with proper cleanup
func (m *Manager) Transaction(ctx context.Context, fn func(*sql.Tx) error) error {
	// Use write lock for transactions
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isHealthy {
		return fmt.Errorf("database is not healthy")
	}

	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p) // Re-throw panic after rollback
		}
	}()

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			m.logger.WithError(rbErr).Error("Failed to rollback transaction")
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// recordQueryStats tracks query performance metrics
func (m *Manager) recordQueryStats(queryName string, duration time.Duration, err error) {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()

	stats, exists := m.queryStats[queryName]
	if !exists {
		stats = &QueryStats{}
		m.queryStats[queryName] = stats
	}

	stats.Count++
	stats.TotalDuration += duration
	stats.AvgDuration = stats.TotalDuration / time.Duration(stats.Count)
	stats.LastExecuted = time.Now()

	if err != nil {
		stats.ErrorCount++
	}
}

// GetQueryStats returns performance statistics for all queries
func (m *Manager) GetQueryStats() map[string]*QueryStats {
	m.statsMu.RLock()
	defer m.statsMu.RUnlock()

	stats := make(map[string]*QueryStats)
	for name, stat := range m.queryStats {
		// Create a copy to avoid race conditions
		stats[name] = &QueryStats{
			Count:         stat.Count,
			TotalDuration: stat.TotalDuration,
			AvgDuration:   stat.AvgDuration,
			LastExecuted:  stat.LastExecuted,
			ErrorCount:    stat.ErrorCount,
		}
	}
	return stats
}

// startHealthMonitoring begins periodic health checks
func (m *Manager) startHealthMonitoring(interval time.Duration) {
	m.healthTicker = time.NewTicker(interval)
	go func() {
		for range m.healthTicker.C {
			m.performHealthCheck()
		}
	}()
}

// performHealthCheck verifies database connectivity
func (m *Manager) performHealthCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := m.db.PingContext(ctx)
	m.isHealthy = err == nil

	if err != nil {
		m.logger.WithError(err).Error("Database health check failed")
	} else {
		m.logger.Debug("Database health check passed")
	}
}

// IsHealthy returns the current database health status
func (m *Manager) IsHealthy() bool {
	return m.isHealthy
}

// Close closes the database connection and stops health monitoring
func (m *Manager) Close() error {
	if m.healthTicker != nil {
		m.healthTicker.Stop()
	}

	m.connectionMu.Lock()
	defer m.connectionMu.Unlock()

	if m.db != nil {
		err := m.db.Close()
		m.logger.Info("Database connection closed")
		return err
	}
	return nil
}

// GetConnection returns the underlying database connection (use with caution)
func (m *Manager) GetConnection() *sql.DB {
	return m.db
}

// ListQueries returns all available query names
func (m *Manager) ListQueries() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	queries := make([]string, 0, len(m.queries))
	for name := range m.queries {
		queries = append(queries, name)
	}
	return queries
}
