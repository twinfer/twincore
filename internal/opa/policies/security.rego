package twincore.security

import data.twincore.features.allowed_features
import data.twincore.features.security_allowed
import future.keywords.if
import future.keywords.in

# Determine allowed authentication methods
allowed_auth_methods := methods if {
    methods := allowed_features.security
} else := ["basic_auth"]  # Default if no license

# Validate authentication method
auth_method_allowed(method) if {
    method in allowed_auth_methods
}

# Generate Caddy security configuration
caddy_security_config := config if {
    config := {
        "authentication": {
            "providers": [provider | 
                method := allowed_auth_methods[_]
                provider := generate_provider(method)
            ]
        },
        "authorization": generate_authz_config(),
        "audit": generate_audit_config()
    }
}

# Generate provider configuration based on method
generate_provider(method) := provider if {
    method == "basic_auth"
    provider := {
        "type": "basic",
        "module": "http.authentication.providers.http_basic",
        "users_file": "/etc/twincore/users.txt"
    }
} else := provider if {
    method == "jwt"
    provider := {
        "type": "jwt",
        "module": "http.authentication.providers.jwt",
        "jwks_url": input.config.jwt_jwks_url,
        "issuer": input.config.jwt_issuer
    }
} else := provider if {
    method == "mtls"
    provider := {
        "type": "mtls",
        "module": "http.authentication.providers.mutual_tls",
        "ca_cert": "/etc/twincore/ca.crt",
        "require_and_verify_client_cert": true
    }
} else := provider if {
    method == "oauth2"
    provider := {
        "type": "oauth2",
        "module": "http.authentication.providers.oauth2",
        "provider_url": input.config.oauth2_provider_url,
        "client_id": input.config.oauth2_client_id
    }
} else := provider if {
    method == "api_key"
    provider := {
        "type": "api_key",
        "module": "http.authentication.providers.api_key",
        "header": "X-API-Key",
        "keys_file": "/etc/twincore/api_keys.txt"
    }
}

# Generate authorization configuration
generate_authz_config() := config if {
    security_allowed("opa")
    config := {
        "type": "opa",
        "module": "http.authorization.opa",
        "policy_path": "/etc/twincore/policies/authz.rego",
        "data_path": "/etc/twincore/authz_data.json"
    }
} else := config if {
    config := {
        "type": "simple",
        "module": "http.authorization.simple",
        "rules_file": "/etc/twincore/acl.yaml"
    }
}

# Generate audit configuration
generate_audit_config() := config if {
    allowed_features.capabilities.audit_logging == true
    config := {
        "enabled": true,
        "type": "parquet",
        "path": "/var/log/twincore/audit/",
        "rotation": "daily",
        "retention_days": 90
    }
} else := config if {
    config := {
        "enabled": false
    }
}

# Check if specific security feature combination is valid
valid_security_config(auth_methods, authz_type) if {
    count([m | m := auth_methods[_]; auth_method_allowed(m)]) == count(auth_methods)
    authz_type == "opa" -> security_allowed("opa")
}

# Get security level (for UI/reporting)
security_level := level if {
    security_allowed("mtls")
    security_allowed("opa")
    allowed_features.capabilities.audit_logging == true
    level := "enterprise"
} else := level if {
    security_allowed("jwt")
    level := "standard"
} else := "basic"