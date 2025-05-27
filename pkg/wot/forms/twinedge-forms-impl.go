// pkg/wot/forms/kafka.go
package forms

import (
    _ "embed"
    "bytes"
    "text/template"
    "fmt"     // Retained for potential logging, or remove if not used
    "strings" // Added for SCRAM mechanism
    
    "github.com/twinfer/twincore/pkg/wot"
)

//go:embed templates/kafka_input.yaml
var kafkaInputTemplate string

//go:embed templates/kafka_output.yaml
var kafkaOutputTemplate string

// KafkaForm implements Form interface for Kafka/Redpanda
type KafkaForm struct {
    Href        string   `json:"href"`
    ContentType string   `json:"contentType"`
    Op          []string `json:"op"`
    Topic       string   `json:"kafka:topic,omitempty"`
    Partition   int      `json:"kafka:partition,omitempty"`
}

func (f *KafkaForm) GetProtocol() string {
    return "kafka"
}

func (f *KafkaForm) GetHref() string {
    return f.Href
}

func (f *KafkaForm) GetContentType() string {
    if f.ContentType == "" {
        return "application/json"
    }
    return f.ContentType
}

func (f *KafkaForm) GetOp() []string {
    return f.Op
}

func (f *KafkaForm) GenerateConfig(securityDefs map[string]wot.SecurityScheme) (map[string]interface{}, error) {
    // Determine if this is input or output based on operations
    isInput := false
    for _, op := range f.Op {
        if op == "readproperty" || op == "subscribeevent" {
            isInput = true
            break
        }
    }

    // Select template
    tmplStr := kafkaOutputTemplate
    if isInput {
        tmplStr = kafkaInputTemplate
    }

    // Parse template
    tmpl, err := template.New("kafka").Parse(tmplStr)
    if err != nil {
        return nil, err
    }

    // Build config data
    config := map[string]interface{}{
        "addresses": []string{f.Href},
        "topic":     f.Topic,
        "partition": f.Partition,
    }

    // Add security config
    if auth := f.extractAuthConfig(securityDefs); auth != nil {
        config["auth"] = auth
    }

    // Execute template
    var buf bytes.Buffer
    if err := tmpl.Execute(&buf, config); err != nil {
        return nil, err
    }

    return map[string]interface{}{
        "yaml": buf.String(),
        "type": f.GetProtocol(),
    }, nil
}

func (f *KafkaForm) extractAuthConfig(securityDefs map[string]wot.SecurityScheme) map[string]interface{} {
    for _, schemeInterface := range securityDefs {
        // Attempt to treat schemeInterface as map[string]interface{}
        schemeData, ok := schemeInterface.(map[string]interface{})
        if !ok {
            // Potentially log or handle cases where schemeInterface is not a map
            // For this subtask, we'll skip if it's not in the expected map format
            continue
        }

        schemeTypeStr, ok := schemeData["scheme"].(string)
        if !ok {
            continue // Scheme type is mandatory
        }

        switch strings.ToLower(schemeTypeStr) {
        case "basic", "plain": // SASL PLAIN
            username := "${TWINEDGE_KAFKA_USER}" // Default placeholder
            password := "${TWINEDGE_KAFKA_PASS}" // Default placeholder

            if userVal, ok := schemeData["user"].(string); ok && userVal != "" {
                username = userVal
            } else if userVal, ok := schemeData["username"].(string); ok && userVal != "" {
                username = userVal
            }

            if passVal, ok := schemeData["password"].(string); ok && passVal != "" {
                password = passVal
            }
            return map[string]interface{}{
                "mechanism": "PLAIN",
                "username":  username,
                "password":  password,
            }

        case "scram-sha-256", "scram-sha-512":
            username := "${TWINEDGE_KAFKA_USER}"
            password := "${TWINEDGE_KAFKA_PASS}"
            mechanism := strings.ToUpper(schemeTypeStr) // SCRAM-SHA-256 or SCRAM-SHA-512

            if userVal, ok := schemeData["user"].(string); ok && userVal != "" {
                username = userVal
            } else if userVal, ok := schemeData["username"].(string); ok && userVal != "" {
                username = userVal
            }
            if passVal, ok := schemeData["password"].(string); ok && passVal != "" {
                password = passVal
            }
            return map[string]interface{}{
                "mechanism": mechanism,
                "username":  username,
                "password":  password,
            }

        case "oauth2":
            // SASL OAUTHBEARER. Benthos expects the token to be provided.
            // The actual token must be sourced externally (e.g., env var).
            tokenPlaceholder := "${TWINEDGE_KAFKA_OAUTH_TOKEN}"
             if tokenVal, ok := schemeData["token"].(string); ok && tokenVal != "" { // If TD provides a direct token string
                tokenPlaceholder = tokenVal
            }
            // The current Kafka template (kafka_input.yaml/kafka_output.yaml) needs to be updated
            // to actually use this token. It currently only has username/password fields for SASL.
            return map[string]interface{}{
                "mechanism": "OAUTHBEARER",
                "token": tokenPlaceholder, // Custom field for template to use
            }

        case "nosec":
            return nil // No auth config needed
        }
    }
    return nil // No suitable and configured security scheme found
}

// pkg/wot/forms/http.go
package forms

import (
    _ "embed"
    "bytes"
    "text/template"
    
    "github.com/twinfer/twincore/pkg/wot"
)

//go:embed templates/http_client.yaml
var httpClientTemplate string

//go:embed templates/http_server.yaml
var httpServerTemplate string

// HTTPForm implements Form interface for HTTP
type HTTPForm struct {
    Href        string              `json:"href"`
    ContentType string              `json:"contentType"`
    Op          []string            `json:"op"`
    Method      string              `json:"htv:methodName,omitempty"`
    Headers     map[string]string   `json:"htv:headers,omitempty"`
}

func (f *HTTPForm) GetProtocol() string {
    return "http"
}

func (f *HTTPForm) GetHref() string {
    return f.Href
}

func (f *HTTPForm) GetContentType() string {
    if f.ContentType == "" {
        return "application/json"
    }
    return f.ContentType
}

func (f *HTTPForm) GetOp() []string {
    return f.Op
}

func (f *HTTPForm) GenerateConfig(securityDefs map[string]wot.SecurityScheme) (map[string]interface{}, error) {
    // Determine if this is client or server based on operations
    isServer := false
    for _, op := range f.Op {
        if op == "invokeaction" {
            isServer = true
            break
        }
    }

    // Select template
    tmplStr := httpClientTemplate
    if isServer {
        tmplStr = httpServerTemplate
    }

    // Parse template
    tmpl, err := template.New("http").Parse(tmplStr)
    if err != nil {
        return nil, err
    }

    // Build config data
    config := map[string]interface{}{
        "url":         f.Href,
        "method":      f.Method,
        "headers":     f.Headers,
        "contentType": f.GetContentType(),
    }

    // Add auth headers based on security definitions
    if authHeaders := f.extractAuthHeaders(securityDefs); len(authHeaders) > 0 {
        if config["headers"] == nil {
            config["headers"] = make(map[string]string)
        }
        headers := config["headers"].(map[string]string)
        for k, v := range authHeaders {
            headers[k] = v
        }
    }

    // Execute template
    var buf bytes.Buffer
    if err := tmpl.Execute(&buf, config); err != nil {
        return nil, err
    }

    return map[string]interface{}{
        "yaml": buf.String(),
        "type": f.GetProtocol(),
    }, nil
}

// Removed the misplaced import block that was here.

func (f *HTTPForm) extractAuthHeaders(securityDefs map[string]wot.SecurityScheme) map[string]string {
    headers := make(map[string]string)

    for _, schemeInterface := range securityDefs {
        // Treat schemeInterface as map[string]interface{} to access fields
        // The input is map[string]wot.SecurityScheme.
        // So `schemeInterface` inside the loop IS of type wot.SecurityScheme.
        // We will use type assertion to map[string]interface{} on `schemeInterface`.
        
        tempSchemeMap, ok := schemeInterface.(map[string]interface{})
        if !ok {
            // If it's not a map, we cannot proceed with dynamic key access.
            // Log or skip. For this task, we skip.
            // fmt.Printf("Warning: SecurityScheme is not a map[string]interface{}, skipping: %T\n", schemeInterface)
            continue
        }

        schemeTypeStr := ""
        if st, okSt := tempSchemeMap["scheme"].(string); okSt {
            schemeTypeStr = st
        } else {
            // If "scheme" key is not present or not a string, we can't determine the type.
            // fmt.Printf("Warning: SecurityScheme does not have a valid 'scheme' field, skipping.\n")
            continue 
        }

        switch schemeTypeStr {
        case "basic":
            // W3C: name (optional), user (optional), password (optional)
            // Benthos http_client basic_auth needs: username, password.
            // We'll construct a placeholder if specific user/pass not in TD.
            authUsername := "${TWINEDGE_BASIC_USER}" // Default placeholder
            authPassword := "${TWINEDGE_BASIC_PASS}" // Default placeholder

            if userVal, okUser := tempSchemeMap["user"].(string); okUser && userVal != "" {
                authUsername = userVal
            }
            if passVal, okPass := tempSchemeMap["password"].(string); okPass && passVal != "" {
                authPassword = passVal
            }
            authVal := base64.StdEncoding.EncodeToString([]byte(authUsername + ":" + authPassword))
            headers["Authorization"] = "Basic " + authVal
        case "bearer":
            // W3C: token (optional string for direct token - not common), format (e.g. "jwt"), alg, authorization (URL)
            // Benthos http_client oauth2.token or a direct bearer token.
            // For now, we'll assume a placeholder that should be externally resolved.
            bearerToken := "${TWINEDGE_BEARER_TOKEN}"
            if tokenVal, okToken := tempSchemeMap["token"].(string); okToken && tokenVal != "" { // If TD provides a direct token string
                bearerToken = tokenVal
            }
            headers["Authorization"] = "Bearer " + bearerToken
        case "apikey":
            // W3C: in ("header", "query", "cookie"), name (header/query/cookie name)
            // We only handle "header" for Benthos http_client headers.
            // A field for the actual key value is needed, e.g. "keyValue" or "token"
            inVal, _ := tempSchemeMap["in"].(string)
            nameVal, _ := tempSchemeMap["name"].(string)

            if inVal == "header" && nameVal != "" {
                apiKey := fmt.Sprintf("${TWINEDGE_APIKEY_%s}", nameVal) // Placeholder by default
                if keyVal, okKey := tempSchemeMap["token"].(string); okKey && keyVal != "" { // Assuming "token" field holds the key
                    apiKey = keyVal
                } else if keyValAlt, okKeyAlt := tempSchemeMap["keyValue"].(string); okKeyAlt && keyValAlt != "" {
                     apiKey = keyValAlt
                }
                headers[nameVal] = apiKey
            }
        case "oauth2":
            // W3C: authorization (URL), token (URL), refresh (URL), scopes, flow
            // Benthos http_client has oauth2 block for client_credentials, password_owner, etc.
            // This is complex. For forms, we'll just indicate intent with a placeholder.
            // The actual token must be fetched by an external process and made available.
            headers["Authorization"] = "Bearer ${TWINEDGE_OAUTH2_TOKEN}"
            // Optionally, could pass through flow, authorization, token URLs if Benthos template can use them
            // For instance, as comments or for a more advanced Benthos processor.
        }
    }
    return headers
}

// pkg/wot/forms/templates/kafka_input.yaml
input:
  kafka:
    addresses:
    {{- range .addresses }}
    - "{{ . }}"
    {{- end }}
    topics:
    - "{{ .topic }}"
    consumer_group: "twinedge-{{ .topic }}"
    {{- if .partition }}
    partition: {{ .partition }}
    {{- end }}
    {{- if .auth }}
    tls:
      enabled: true
    sasl:
      mechanism: "{{ .auth.mechanism }}"
      username: "{{ .auth.username }}"
      password: "{{ .auth.password }}"
    {{- end }}

// pkg/wot/forms/templates/kafka_output.yaml
output:
  kafka:
    addresses:
    {{- range .addresses }}
    - "{{ . }}"
    {{- end }}
    topic: "{{ .topic }}"
    {{- if .partition }}
    partition: {{ .partition }}
    {{- end }}
    {{- if .auth }}
    tls:
      enabled: true
    sasl:
      mechanism: "{{ .auth.mechanism }}"
      username: "{{ .auth.username }}"
      password: "{{ .auth.password }}"
    {{- end }}

// pkg/wot/forms/templates/http_client.yaml
output:
  http_client:
    url: "{{ .url }}"
    verb: "{{ .method }}"
    headers:
      Content-Type: "{{ .contentType }}"
      {{- range $key, $value := .headers }}
      {{ $key }}: "{{ $value }}"
      {{- end }}
    rate_limit: "10s"
    timeout: "30s"

// pkg/wot/forms/templates/http_server.yaml
input:
  http_server:
    address: "0.0.0.0:8081"
    path: "{{ .url }}"
    allowed_verbs:
    - "{{ .method }}"
    sync_response:
      status: 200