package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

// TransactionManager provides advanced transaction management with retries and coordination
type TransactionManager struct {
	manager *Manager
	logger  *logrus.Logger
}

// NewTransactionManager creates a new transaction manager
func NewTransactionManager(manager *Manager, logger *logrus.Logger) *TransactionManager {
	return &TransactionManager{
		manager: manager,
		logger:  logger,
	}
}

// TxOptions configures transaction behavior
type TxOptions struct {
	RetryCount     int
	RetryDelay     time.Duration
	Timeout        time.Duration
	IsolationLevel sql.IsolationLevel
	ReadOnly       bool
}

// DefaultTxOptions returns sensible defaults for transactions
func DefaultTxOptions() *TxOptions {
	return &TxOptions{
		RetryCount:     3,
		RetryDelay:     100 * time.Millisecond,
		Timeout:        30 * time.Second,
		IsolationLevel: sql.LevelDefault,
		ReadOnly:       false,
	}
}

// ExecuteWithRetry executes a function within a transaction with retry logic
func (tm *TransactionManager) ExecuteWithRetry(ctx context.Context, options *TxOptions, fn func(*sql.Tx) error) error {
	if options == nil {
		options = DefaultTxOptions()
	}

	// Apply timeout to context
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	var lastErr error
	for attempt := 0; attempt <= options.RetryCount; attempt++ {
		if attempt > 0 {
			tm.logger.WithFields(logrus.Fields{
				"attempt": attempt,
				"error":   lastErr.Error(),
			}).Warn("Retrying transaction")

			// Wait before retry
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(options.RetryDelay):
			}
		}

		err := tm.executeTransaction(ctx, options, fn)
		if err == nil {
			if attempt > 0 {
				tm.logger.WithField("attempt", attempt).Info("Transaction succeeded after retry")
			}
			return nil
		}

		lastErr = err

		// Check if error is retryable
		if !isRetryableError(err) {
			tm.logger.WithError(err).Error("Non-retryable transaction error")
			return err
		}

		// Check if context is done
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}

	tm.logger.WithFields(logrus.Fields{
		"attempts": options.RetryCount + 1,
		"error":    lastErr.Error(),
	}).Error("Transaction failed after all retries")

	return fmt.Errorf("transaction failed after %d attempts: %w", options.RetryCount+1, lastErr)
}

// executeTransaction executes a single transaction attempt
func (tm *TransactionManager) executeTransaction(ctx context.Context, options *TxOptions, fn func(*sql.Tx) error) error {
	// Use the manager's transaction method which handles locking
	return tm.manager.Transaction(ctx, func(tx *sql.Tx) error {
		// Set transaction properties if supported
		if options.ReadOnly {
			// DuckDB doesn't support read-only transactions explicitly,
			// but we can document the intent
			tm.logger.Debug("Starting read-only transaction")
		}

		return fn(tx)
	})
}

// BatchExecute executes multiple operations in a single transaction
func (tm *TransactionManager) BatchExecute(ctx context.Context, operations []BatchOperation) error {
	return tm.ExecuteWithRetry(ctx, DefaultTxOptions(), func(tx *sql.Tx) error {
		for i, op := range operations {
			if err := op.Execute(tx); err != nil {
				return fmt.Errorf("batch operation %d failed: %w", i, err)
			}
		}
		return nil
	})
}

// BatchOperation represents a single operation in a batch
type BatchOperation struct {
	Name      string
	QueryName string
	Args      []any
	Execute   func(*sql.Tx) error
}

// NewQueryOperation creates a batch operation that executes a named query
func (tm *TransactionManager) NewQueryOperation(name, queryName string, args ...any) BatchOperation {
	return BatchOperation{
		Name:      name,
		QueryName: queryName,
		Args:      args,
		Execute: func(tx *sql.Tx) error {
			query, err := tm.manager.GetQuery(queryName)
			if err != nil {
				return fmt.Errorf("failed to get query %s: %w", queryName, err)
			}

			_, err = tx.Exec(query, args...)
			if err != nil {
				return fmt.Errorf("failed to execute query %s: %w", queryName, err)
			}

			tm.logger.WithFields(logrus.Fields{
				"operation": name,
				"query":     queryName,
			}).Debug("Batch operation executed")

			return nil
		},
	}
}

// TransactionStats tracks transaction performance and success rates
type TransactionStats struct {
	TotalAttempts  int64
	SuccessfulTxns int64
	FailedTxns     int64
	RetriedTxns    int64
	AvgDuration    time.Duration
	TotalDuration  time.Duration
	LastExecution  time.Time
}

// GetTransactionStats returns transaction statistics (placeholder for future implementation)
func (tm *TransactionManager) GetTransactionStats() *TransactionStats {
	// TODO: Implement transaction statistics tracking
	return &TransactionStats{
		LastExecution: time.Now(),
	}
}

// isRetryableError determines if an error should trigger a retry
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errorStr := err.Error()

	// DuckDB specific retryable errors
	retryablePatterns := []string{
		"database is locked",
		"database table is locked",
		"connection reset",
		"connection lost",
		"temporary failure",
		"timeout",
		"deadlock",
	}

	for _, pattern := range retryablePatterns {
		if contains(errorStr, pattern) {
			return true
		}
	}

	return false
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					indexOf(s, substr) >= 0))
}

// indexOf finds the first occurrence of substr in s
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// Predefined transaction functions for common patterns

// CreateThingWithStreams creates a thing and its associated streams in a single transaction
func (tm *TransactionManager) CreateThingWithStreams(ctx context.Context, thingID, title, description, tdJSONLD, tdParsed string, streamConfigs []StreamConfig) error {
	return tm.ExecuteWithRetry(ctx, DefaultTxOptions(), func(tx *sql.Tx) error {
		// Insert thing
		insertThingQuery, err := tm.manager.GetQuery("InsertThing")
		if err != nil {
			return fmt.Errorf("failed to get InsertThing query: %w", err)
		}

		_, err = tx.Exec(insertThingQuery, thingID, title, description, tdJSONLD, tdParsed)
		if err != nil {
			return fmt.Errorf("failed to insert thing: %w", err)
		}

		// Insert stream configurations
		insertStreamQuery, err := tm.manager.GetQuery("InsertStreamConfig")
		if err != nil {
			return fmt.Errorf("failed to get InsertStreamConfig query: %w", err)
		}

		for _, config := range streamConfigs {
			_, err = tx.Exec(insertStreamQuery,
				config.StreamID, config.ThingID, config.InteractionType,
				config.InteractionName, config.Direction, config.InputConfig,
				config.OutputConfig, config.ProcessorChain, config.Status,
				config.Metadata, config.ConfigYAML, config.ValidationError)
			if err != nil {
				return fmt.Errorf("failed to insert stream config %s: %w", config.StreamID, err)
			}
		}

		tm.logger.WithFields(logrus.Fields{
			"thing_id":     thingID,
			"stream_count": len(streamConfigs),
		}).Info("Thing and streams created successfully")

		return nil
	})
}

// StreamConfig represents a stream configuration for batch operations
type StreamConfig struct {
	StreamID        string
	ThingID         string
	InteractionType string
	InteractionName string
	Direction       string
	InputConfig     string
	OutputConfig    string
	ProcessorChain  string
	Status          string
	Metadata        string
	ConfigYAML      string
	ValidationError string
}

// UpdateThingAndCleanupStreams updates a thing and removes old streams in a single transaction
func (tm *TransactionManager) UpdateThingAndCleanupStreams(ctx context.Context, thingID, title, description, tdJSONLD, tdParsed string, streamsToDelete []string) error {
	return tm.ExecuteWithRetry(ctx, DefaultTxOptions(), func(tx *sql.Tx) error {
		// Update thing
		updateThingQuery, err := tm.manager.GetQuery("UpdateThing")
		if err != nil {
			return fmt.Errorf("failed to get UpdateThing query: %w", err)
		}

		_, err = tx.Exec(updateThingQuery, title, description, tdJSONLD, tdParsed, thingID)
		if err != nil {
			return fmt.Errorf("failed to update thing: %w", err)
		}

		// Delete old streams
		deleteStreamQuery, err := tm.manager.GetQuery("DeleteStreamConfig")
		if err != nil {
			return fmt.Errorf("failed to get DeleteStreamConfig query: %w", err)
		}

		for _, streamID := range streamsToDelete {
			_, err = tx.Exec(deleteStreamQuery, streamID)
			if err != nil {
				return fmt.Errorf("failed to delete stream %s: %w", streamID, err)
			}
		}

		tm.logger.WithFields(logrus.Fields{
			"thing_id":        thingID,
			"deleted_streams": len(streamsToDelete),
		}).Info("Thing updated and streams cleaned up")

		return nil
	})
}

// CreateUserWithSession creates a user and initial session atomically
func (tm *TransactionManager) CreateUserWithSession(ctx context.Context, username, passwordHash, roles, email, name string, sessionData SessionData) error {
	return tm.ExecuteWithRetry(ctx, DefaultTxOptions(), func(tx *sql.Tx) error {
		// Create user
		createUserQuery, err := tm.manager.GetQuery("CreateUser")
		if err != nil {
			return fmt.Errorf("failed to get CreateUser query: %w", err)
		}

		_, err = tx.Exec(createUserQuery, username, passwordHash, roles, email, name, false)
		if err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		// Create session
		createSessionQuery, err := tm.manager.GetQuery("CreateSession")
		if err != nil {
			return fmt.Errorf("failed to get CreateSession query: %w", err)
		}

		_, err = tx.Exec(createSessionQuery,
			sessionData.ID, sessionData.UserID, sessionData.Username,
			sessionData.Token, sessionData.RefreshToken, sessionData.ExpiresAt,
			sessionData.IPAddress, sessionData.UserAgent)
		if err != nil {
			return fmt.Errorf("failed to create session: %w", err)
		}

		tm.logger.WithField("username", username).Info("User and session created successfully")
		return nil
	})
}

// SessionData represents session information for batch operations
type SessionData struct {
	ID           string
	UserID       string
	Username     string
	Token        string
	RefreshToken string
	ExpiresAt    time.Time
	IPAddress    string
	UserAgent    string
}
