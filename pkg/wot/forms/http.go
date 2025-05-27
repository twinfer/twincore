// pkg/wot/forms/http.go
package forms

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"fmt"
	"text/template"

	"github.com/twinfer/twincore/pkg/wot"
)

//go:embed templates/http_client.yaml
var httpClientTemplate string

//go:embed templates/http_server.yaml
var httpServerTemplate string

// HTTPForm implements Form interface for HTTP
type HTTPForm struct {
	Href        string            `json:"href"`
	ContentType string            `json:"contentType"`
	Op          []string          `json:"op"`
	Method      string            `json:"htv:methodName,omitempty"`
	Headers     map[string]string `json:"htv:headers,omitempty"`
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
				apiKey := fmt.Sprintf("${TWINEDGE_APIKEY_%s}", nameVal)                      // Placeholder by default
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
