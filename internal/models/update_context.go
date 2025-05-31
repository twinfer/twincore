package models

import (
	"context"
	"time"
)

// UpdateSource indicates where a property update originated
type UpdateSource string

const (
	UpdateSourceHTTP   UpdateSource = "http"
	UpdateSourceStream UpdateSource = "stream"
	UpdateSourceDevice UpdateSource = "device"
	UpdateSourceSystem UpdateSource = "system"
)

// UpdateContext carries metadata about property updates to prevent circular flows
type UpdateContext struct {
	Source    UpdateSource `json:"source"`
	RequestID string       `json:"request_id,omitempty"`
	UserAgent string       `json:"user_agent,omitempty"`
	Timestamp time.Time    `json:"timestamp"`
}

// ContextKey for storing UpdateContext in Go context
type contextKey string

const UpdateContextKey contextKey = "update_context"

// WithUpdateContext adds an UpdateContext to a Go context
func WithUpdateContext(ctx context.Context, updateCtx UpdateContext) context.Context {
	return context.WithValue(ctx, UpdateContextKey, updateCtx)
}

// GetUpdateContext retrieves UpdateContext from a Go context
func GetUpdateContext(ctx context.Context) (UpdateContext, bool) {
	updateCtx, ok := ctx.Value(UpdateContextKey).(UpdateContext)
	return updateCtx, ok
}

// NewUpdateContext creates a new UpdateContext with timestamp
func NewUpdateContext(source UpdateSource) UpdateContext {
	return UpdateContext{
		Source:    source,
		Timestamp: time.Now().UTC(),
	}
}

// PropertyUpdateWithContext extends PropertyUpdate with source context
type PropertyUpdateWithContext struct {
	PropertyUpdate
	Context UpdateContext `json:"context"`
}
