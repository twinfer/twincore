package twincore.features

import future.keywords.if
import future.keywords.in

# Default features when no JWT license is present
default_features := {
    "bindings": ["http", "mqtt"],
    "processors": ["json", "mapping"],
    "security": ["basic_auth"],
    "storage": [],
    "capabilities": {
        "max_things": 10,
        "max_streams": 5,
        "max_users": 2,
        "multi_tenancy": false,
        "audit_logging": false
    }
}

# Evaluate allowed features based on JWT or defaults
allowed_features := features if {
    input.jwt
    input.jwt.features
    features := input.jwt.features
} else := default_features

# Check if a specific feature is allowed
feature_allowed(category, feature) if {
    feature in allowed_features[category]
}

# Check capability limits
within_limit(resource, count) if {
    allowed_features.capabilities[resource] >= count
}

# Check boolean capabilities
capability_enabled(capability) if {
    allowed_features.capabilities[capability] == true
}

# Validate Benthos processor usage
processor_allowed(processor_type) if {
    processor_type in allowed_features.processors
}

# Validate binding usage
binding_allowed(binding_type) if {
    binding_type in allowed_features.bindings
}

# Security feature check
security_allowed(security_type) if {
    security_type in allowed_features.security
}

# Storage feature check
storage_allowed(storage_type) if {
    storage_type in allowed_features.storage
}

# Get all features for a category
get_features(category) := features if {
    features := allowed_features[category]
} else := []

# Check if we're running with a valid license
has_license := true if {
    input.jwt
    input.jwt.features
} else := false