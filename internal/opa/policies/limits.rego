package twincore.limits

import data.twincore.features.allowed_features
import future.keywords.if
import future.keywords.in

# Enforce thing count limits
thing_limit_exceeded(current_count) if {
    current_count > allowed_features.capabilities.max_things
}

# Enforce stream count limits  
stream_limit_exceeded(current_count) if {
    current_count > allowed_features.capabilities.max_streams
}

# Enforce user count limits
user_limit_exceeded(current_count) if {
    current_count > allowed_features.capabilities.max_users
}

# Check if operation would exceed limit
would_exceed_limit(resource, current_count, additional) if {
    limit := allowed_features.capabilities[resource]
    current_count + additional > limit
}

# Get remaining capacity for a resource
remaining_capacity(resource, current_count) := remaining if {
    limit := allowed_features.capabilities[resource]
    remaining := limit - current_count
} else := 0

# Dynamic rate limiting based on license
rate_limit_for_endpoint(endpoint) := limit if {
    endpoint == "/api/things"
    limit := allowed_features.capabilities.max_things * 10 / 3600  # 10x per hour
} else := limit if {
    endpoint == "/wot/binding/streams"
    limit := allowed_features.capabilities.max_streams * 5 / 3600  # 5x per hour
} else := 100  # Default rate limit per hour

# Check if multi-tenancy is enabled
multi_tenancy_enabled if {
    allowed_features.capabilities.multi_tenancy == true
}

# Get quota for tenant (if multi-tenancy enabled)
tenant_quota(tenant_id) := quota if {
    multi_tenancy_enabled
    # In production, this would fetch from external data source
    # For now, divide limits by assumed tenant count
    quota := {
        "max_things": allowed_features.capabilities.max_things / 10,
        "max_streams": allowed_features.capabilities.max_streams / 10,
        "max_users": allowed_features.capabilities.max_users / 10
    }
} else := allowed_features.capabilities