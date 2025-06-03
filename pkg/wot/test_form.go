package wot

// TestForm is a concrete implementation of the Form interface for testing
type TestForm struct {
	OpValue          []string                  `json:"op,omitempty"`
	HrefValue        string                    `json:"href"`
	ContentTypeValue string                    `json:"contentType,omitempty"`
	SecurityValue    []string                  `json:"security,omitempty"`
	ResponseValue    *ExpectedResponse         `json:"response,omitempty"`
	URIVariablesValue map[string]*DataSchema   `json:"uriVariables,omitempty"`
	SubprotocolValue string                    `json:"subprotocol,omitempty"`
}

func (f *TestForm) GetOp() []string                              { return f.OpValue }
func (f *TestForm) GetHref() string                             { return f.HrefValue }
func (f *TestForm) GetContentType() string                      { return f.ContentTypeValue }
func (f *TestForm) GetSecurity() []string                       { return f.SecurityValue }
func (f *TestForm) GetResponse() *ExpectedResponse              { return f.ResponseValue }
func (f *TestForm) GetURIVariables() map[string]*DataSchema     { return f.URIVariablesValue }
func (f *TestForm) GetSubprotocol() string                      { return f.SubprotocolValue }
func (f *TestForm) GetProtocol() string                         { return "http" }

func (f *TestForm) GenerateConfig(securityDefs map[string]SecurityScheme) (map[string]interface{}, error) {
	return map[string]interface{}{
		"href":        f.HrefValue,
		"contentType": f.ContentTypeValue,
		"method":      f.OpValue[0],
	}, nil
}