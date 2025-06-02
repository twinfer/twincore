package api

import (
	"fmt"
	"strings"
)

// --- ConfigurationManager Errors (Caddy) ---

// ErrCaddyAdminAPIAccess indicates an issue connecting to or communicating with the Caddy Admin API.
type ErrCaddyAdminAPIAccess struct {
	URL        string
	HTTPMethod string
	WrappedErr error
}

func (e *ErrCaddyAdminAPIAccess) Error() string {
	return fmt.Sprintf("Caddy admin API access error: method=%s, url=%s: %v", e.HTTPMethod, e.URL, e.WrappedErr)
}
func (e *ErrCaddyAdminAPIAccess) Unwrap() error { return e.WrappedErr }

// ErrCaddyConfigLoadFailed indicates Caddy rejected a configuration.
type ErrCaddyConfigLoadFailed struct {
	CaddyPath  string
	WrappedErr error
}

func (e *ErrCaddyConfigLoadFailed) Error() string {
	return fmt.Sprintf("Caddy config load failed for path '%s': %v", e.CaddyPath, e.WrappedErr)
}
func (e *ErrCaddyConfigLoadFailed) Unwrap() error { return e.WrappedErr }

// ErrCaddyConfigOperationFailed indicates a general failure in a Caddy config operation.
type ErrCaddyConfigOperationFailed struct {
	CaddyPath  string
	StatusCode int
	WrappedErr error
}

func (e *ErrCaddyConfigOperationFailed) Error() string {
	if e.WrappedErr != nil {
		return fmt.Sprintf("Caddy config operation failed for path '%s' (status %d): %v", e.CaddyPath, e.StatusCode, e.WrappedErr)
	}
	return fmt.Sprintf("Caddy config operation failed for path '%s' (status %d)", e.CaddyPath, e.StatusCode)
}
func (e *ErrCaddyConfigOperationFailed) Unwrap() error { return e.WrappedErr }

// ErrCaddyResourceNotFound indicates a specific Caddy resource was not found.
type ErrCaddyResourceNotFound struct {
	ResourceType string
	ResourceID   string
	CaddyPath    string // Optional: path where search occurred
	WrappedErr   error
}

func (e *ErrCaddyResourceNotFound) Error() string {
	msg := fmt.Sprintf("Caddy resource not found: type=%s, id=%s", e.ResourceType, e.ResourceID)
	if e.CaddyPath != "" {
		msg += fmt.Sprintf(", path=%s", e.CaddyPath)
	}
	if e.WrappedErr != nil {
		return fmt.Sprintf("%s: %v", msg, e.WrappedErr)
	}
	return msg
}
func (e *ErrCaddyResourceNotFound) Unwrap() error { return e.WrappedErr }

// --- BenthosStreamManager Errors ---

// ErrBenthosStreamConfigInvalid indicates an invalid Benthos stream configuration.
type ErrBenthosStreamConfigInvalid struct {
	StreamID   string
	Details    string
	WrappedErr error
}

func (e *ErrBenthosStreamConfigInvalid) Error() string {
	base := fmt.Sprintf("Benthos stream config invalid for stream ID '%s'", e.StreamID)
	if e.Details != "" {
		base += ": " + e.Details
	}
	if e.WrappedErr != nil {
		return fmt.Sprintf("%s: %v", base, e.WrappedErr)
	}
	return base
}
func (e *ErrBenthosStreamConfigInvalid) Unwrap() error { return e.WrappedErr }

// ErrBenthosStreamCreateFailed indicates failure during Benthos stream creation via API.
type ErrBenthosStreamCreateFailed struct {
	StreamID   string
	WrappedErr error
}

func (e *ErrBenthosStreamCreateFailed) Error() string {
	return fmt.Sprintf("Benthos stream creation failed for stream ID '%s': %v", e.StreamID, e.WrappedErr)
}
func (e *ErrBenthosStreamCreateFailed) Unwrap() error { return e.WrappedErr }

// ErrBenthosStreamStartFailed indicates a built stream failed to start.
type ErrBenthosStreamStartFailed struct {
	StreamID   string
	WrappedErr error
}

func (e *ErrBenthosStreamStartFailed) Error() string {
	return fmt.Sprintf("Benthos stream start failed for stream ID '%s': %v", e.StreamID, e.WrappedErr)
}
func (e *ErrBenthosStreamStartFailed) Unwrap() error { return e.WrappedErr }

// ErrBenthosStreamStopFailed indicates failure while stopping a Benthos stream.
type ErrBenthosStreamStopFailed struct {
	StreamID   string
	WrappedErr error
}

func (e *ErrBenthosStreamStopFailed) Error() string {
	return fmt.Sprintf("Benthos stream stop failed for stream ID '%s': %v", e.StreamID, e.WrappedErr)
}
func (e *ErrBenthosStreamStopFailed) Unwrap() error { return e.WrappedErr }

// ErrBenthosStreamDeleteFailed indicates failure during stream deletion (persistence/tracking).
type ErrBenthosStreamDeleteFailed struct {
	StreamID   string
	WrappedErr error
}

func (e *ErrBenthosStreamDeleteFailed) Error() string {
	return fmt.Sprintf("Benthos stream delete failed for stream ID '%s': %v", e.StreamID, e.WrappedErr)
}
func (e *ErrBenthosStreamDeleteFailed) Unwrap() error { return e.WrappedErr }

// ErrBenthosStreamNotFound indicates a requested stream ID does not exist.
type ErrBenthosStreamNotFound struct {
	StreamID string
}

func (e *ErrBenthosStreamNotFound) Error() string {
	return fmt.Sprintf("Benthos stream not found: id=%s", e.StreamID)
}

// ErrBenthosStreamUpdateFailed indicates failure during stream update.
type ErrBenthosStreamUpdateFailed struct {
	StreamID   string
	WrappedErr error
}

func (e *ErrBenthosStreamUpdateFailed) Error() string {
	return fmt.Sprintf("Benthos stream update failed for stream ID '%s': %v", e.StreamID, e.WrappedErr)
}
func (e *ErrBenthosStreamUpdateFailed) Unwrap() error { return e.WrappedErr }

// ErrBenthosProcessorCollectionNotFound indicates a processor collection was not found.
type ErrBenthosProcessorCollectionNotFound struct {
	CollectionID string
}

func (e *ErrBenthosProcessorCollectionNotFound) Error() string {
	return fmt.Sprintf("Benthos processor collection not found: id=%s", e.CollectionID)
}

// ErrBenthosProcessorCollectionCreateFailed indicates failure creating a processor collection.
type ErrBenthosProcessorCollectionCreateFailed struct {
	CollectionName string
	WrappedErr     error
}

func (e *ErrBenthosProcessorCollectionCreateFailed) Error() string {
	return fmt.Sprintf("Benthos processor collection creation failed for name '%s': %v", e.CollectionName, e.WrappedErr)
}
func (e *ErrBenthosProcessorCollectionCreateFailed) Unwrap() error { return e.WrappedErr }

// ErrBenthosDatabaseOperationFailed indicates a general database operation failure.
type ErrBenthosDatabaseOperationFailed struct {
	Operation  string // e.g., "load_streams", "persist_stream_config"
	WrappedErr error
}

func (e *ErrBenthosDatabaseOperationFailed) Error() string {
	return fmt.Sprintf("Benthos database operation '%s' failed: %v", e.Operation, e.WrappedErr)
}
func (e *ErrBenthosDatabaseOperationFailed) Unwrap() error { return e.WrappedErr }

// ErrComposite combines multiple errors from a sequence of operations.
type ErrComposite struct {
	Operation string
	Errors    []error
}

func (e *ErrComposite) Error() string {
	var errorMessages []string
	for _, err := range e.Errors {
		errorMessages = append(errorMessages, err.Error())
	}
	return fmt.Sprintf("%s encountered multiple errors: %s", e.Operation, strings.Join(errorMessages, "; "))
}

// Unwrap returns nil because it's a collection of errors.
// Specific errors within e.Errors can be inspected individually.
func (e *ErrComposite) Unwrap() error {
	if len(e.Errors) == 1 {
		return e.Errors[0]
	}
	// Cannot sensibly unwrap multiple errors into a single error.
	// Consumers should iterate e.Errors or use errors.As to check for specific types.
	return nil
}

// Add appends an error to the composite error list.
func (e *ErrComposite) Add(err error) {
	if err != nil {
		e.Errors = append(e.Errors, err)
	}
}

// HasErrors checks if any errors have been added.
func (e *ErrComposite) HasErrors() bool {
	return len(e.Errors) > 0
}
