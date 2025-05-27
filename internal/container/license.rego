package twinedge.authz

default allow = false

# Allow if the license is active, not expired, and contains the "core" feature.
# Note: 'input.current_time_unix' would be provided by the Go application when querying OPA.
allow {
    input.license.active == true
    input.license.exp > input.current_time_unix
    contains(input.license.features, "core")
}

# Example: Deny if a "revoked" field is true in the license
allow = false {
    input.license.revoked == true
}
