package types

import "time"

// API Response types for Swagger documentation

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Error   string `json:"error" example:"Invalid Thing Description"`
	Code    int    `json:"code" example:"400"`
	Details string `json:"details,omitempty" example:"Missing required field: title"`
}

// HealthResponse represents system health status
type HealthResponse struct {
	Status    string `json:"status" example:"healthy"`
	Timestamp string `json:"timestamp" example:"2023-12-01T10:00:00Z"`
	Version   string `json:"version" example:"1.0.0"`
	Uptime    string `json:"uptime" example:"24h30m15s"`
}

// MetricsResponse represents system metrics
type MetricsResponse struct {
	PropertyReads  uint64 `json:"property_reads" example:"1250"`
	PropertyWrites uint64 `json:"property_writes" example:"840"`
	ActionInvokes  uint64 `json:"action_invokes" example:"320"`
	EventEmissions uint64 `json:"event_emissions" example:"2100"`
	Errors         uint64 `json:"errors" example:"12"`
	Timestamp      string `json:"timestamp" example:"2023-12-01T10:00:00Z"`
}

// NewErrorResponse creates a new error response
func NewErrorResponse(code int, err error, details ...string) *ErrorResponse {
	resp := &ErrorResponse{
		Error: err.Error(),
		Code:  code,
	}
	if len(details) > 0 {
		resp.Details = details[0]
	}
	return resp
}

// NewHealthResponse creates a new health response
func NewHealthResponse(status, version string, uptime time.Duration) *HealthResponse {
	return &HealthResponse{
		Status:    status,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Version:   version,
		Uptime:    uptime.String(),
	}
}

// NewMetricsResponse creates a new metrics response
func NewMetricsResponse(propertyReads, propertyWrites, actionInvokes, eventEmissions, errors uint64) *MetricsResponse {
	return &MetricsResponse{
		PropertyReads:  propertyReads,
		PropertyWrites: propertyWrites,
		ActionInvokes:  actionInvokes,
		EventEmissions: eventEmissions,
		Errors:         errors,
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
	}
}
