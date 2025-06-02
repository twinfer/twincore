package forms

import (
	_ "embed"
	"encoding/base64"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/twinfer/twincore/pkg/types"
	"github.com/twinfer/twincore/pkg/wot"
)

//go:embed templates/http_client.yaml
var httpClientTemplate string

//go:embed templates/http_server.yaml
var httpServerTemplate string

// HTTPForm implements Form interface for HTTP with enhanced capabilities
type HTTPForm struct {
	Href        string            `json:"href"`
	ContentType string            `json:"contentType"`
	Method      string            `json:"htv:methodName,omitempty"` // W3C WoT compliant
	Op          []string          `json:"op"`
	Headers     map[string]string `json:"htv:headers,omitempty"` // W3C WoT compliant
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

func (f *HTTPForm) GetStreamProtocol() types.StreamProtocol {
	return types.ProtocolHTTP
}

func (f *HTTPForm) GetStreamDirection(op []string) types.StreamDirection {
	return GetStreamDirection(op) // Assumes GetStreamDirection is in the same package
}

func (f *HTTPForm) GenerateStreamEndpoint() (map[string]interface{}, error) {
	return f.GenerateConfig(logrus.NewEntry(logrus.StandardLogger()), nil) // Pass default logger if called directly
}

func (f *HTTPForm) GenerateConfig(logger logrus.FieldLogger, securityDefs map[string]wot.SecurityScheme) (map[string]interface{}, error) {
	logger.WithFields(logrus.Fields{"form_href": f.Href, "protocol": f.GetProtocol()}).Debug("Generating config for HTTP form")
	// Determine if this is client or server based on operations
	isServer := false
	for _, op := range f.Op {
		if op == "writeproperty" || op == "invokeaction" {
			isServer = true
			break
		}
	}

	// Select template
	var tmplStr string
	var templateName string
	if isServer {
		tmplStr = httpServerTemplate
		templateName = "httpServerTemplate"
		logger.WithField("template_name", templateName).Debug("Selected HTTP server template")
	} else {
		tmplStr = httpClientTemplate
		templateName = "httpClientTemplate"
		logger.WithField("template_name", templateName).Debug("Selected HTTP client template")
	}

	// Determine HTTP method
	method := f.Method
	if method == "" {
		method = f.inferHTTPMethod()
	}

	// Build config data
	config := map[string]interface{}{
		"url":     f.Href,
		"method":  method,
		"headers": f.Headers,
	}

	// Add security config
	if auth := f.extractAuthHeaders(logger, securityDefs); auth != nil { // Pass logger here
		if config["headers"] == nil {
			config["headers"] = make(map[string]string)
		}
		headers := config["headers"].(map[string]string)
		for k, v := range auth {
			headers[k] = v
		}
	}

	// Execute template
	yamlOutput, err := executeTemplate("http", tmplStr, config)
	if err != nil {
		logger.WithError(err).WithFields(logrus.Fields{"form_href": f.Href, "template_name": templateName}).Error("Failed to execute HTTP form template")
		return nil, fmt.Errorf("failed to execute http template: %w", err)
	}

	return map[string]interface{}{
		"yaml":   yamlOutput,
		"type":   f.GetProtocol(),
		"config": config,
	}, nil
}

func (f *HTTPForm) inferHTTPMethod() string {
	for _, op := range f.Op {
		switch op {
		case "readproperty", "observeproperty", "subscribeevent":
			return "GET"
		case "writeproperty":
			return "PUT"
		case "invokeaction":
			return "POST"
		}
	}
	return "GET" // Default
}

func (f *HTTPForm) extractAuthHeaders(logger logrus.FieldLogger, securityDefs map[string]wot.SecurityScheme) map[string]string {
	headers := make(map[string]string)

	for _, schemeDef := range securityDefs {
		if schemeDef.Scheme == "" {
			continue
		}

		switch schemeDef.Scheme {
		case "basic":
			// W3C WoT: name (optional), user (optional), password (optional)
			// Use environment variable placeholders for actual credentials
			authUsername := "${TWINEDGE_BASIC_USER}" // Default placeholder
			authPassword := "${TWINEDGE_BASIC_PASS}" // Default placeholder

			// Encode credentials for HTTP Basic Auth
			authVal := base64.StdEncoding.EncodeToString([]byte(authUsername + ":" + authPassword))
			headers["Authorization"] = "Basic " + authVal
			logger.WithFields(logrus.Fields{"scheme": schemeDef.Scheme, "form_href": f.Href}).Debug("Applying basic auth security scheme to HTTP form config")

		case "bearer":
			// W3C WoT: token (optional string for direct token), format (e.g. "jwt"), alg, authorization (URL)
			bearerToken := "${TWINEDGE_BEARER_TOKEN}"
			headers["Authorization"] = "Bearer " + bearerToken
			logger.WithFields(logrus.Fields{"scheme": schemeDef.Scheme, "form_href": f.Href}).Debug("Applying bearer auth security scheme to HTTP form config")

		case "apikey":
			// W3C WoT: in ("header", "query", "cookie"), name (header/query/cookie name)
			// Only handle "header" for Benthos http_client headers
			if schemeDef.In == "header" && schemeDef.Name != "" {
				apiKey := fmt.Sprintf("${TWINEDGE_APIKEY_%s}", schemeDef.Name) // Placeholder by default
				headers[schemeDef.Name] = apiKey
				logger.WithFields(logrus.Fields{"scheme": schemeDef.Scheme, "form_href": f.Href, "key_name": schemeDef.Name}).Debug("Applying apikey security scheme to HTTP form config")
			}

		case "oauth2":
			// W3C WoT: authorization (URL), token (URL), refresh (URL), scopes, flow
			// For forms, indicate intent with a placeholder - actual token must be fetched externally
			headers["Authorization"] = "Bearer ${TWINEDGE_OAUTH2_TOKEN}"
			logger.WithFields(logrus.Fields{"scheme": schemeDef.Scheme, "form_href": f.Href}).Debug("Applying oauth2 placeholder security scheme to HTTP form config")
		}
	}

	if len(headers) == 0 {
		return nil
	}
	return headers
}
