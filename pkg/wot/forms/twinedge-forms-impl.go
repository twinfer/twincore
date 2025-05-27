// pkg/wot/forms/kafka.go
package forms

import (
    _ "embed"
    "bytes"
    "text/template"
    
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
    // Extract security configuration based on WoT security definitions
    // This would map WoT security schemes to Kafka SASL/SSL configs
    return nil
}

// pkg/wot/forms/http.go
package forms

import (
    _ "embed"
    "bytes"
    "text/template"
    
    "github.com/twinedge/gateway/pkg/wot"
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

func (f *HTTPForm) extractAuthHeaders(securityDefs map[string]wot.SecurityScheme) map[string]string {
    headers := make(map[string]string)
    
    for _, scheme := range securityDefs {
        switch scheme.Scheme {
        case "bearer":
            headers["Authorization"] = "Bearer ${TOKEN}"
        case "basic":
            headers["Authorization"] = "Basic ${CREDENTIALS}"
        case "apikey":
            if scheme.In == "header" {
                headers[scheme.Name] = "${API_KEY}"
            }
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