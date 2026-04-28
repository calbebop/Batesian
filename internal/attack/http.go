package attack

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxBody = 1 << 20 // 1 MB

// HTTPClient is a thin wrapper around net/http.Client with helpers for attack requests.
type HTTPClient struct {
	inner *http.Client
	vars  Vars
}

// NewHTTPClient creates an attack HTTP client.
func NewHTTPClient(opts Options, vars Vars) *HTTPClient {
	timeout := time.Duration(opts.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	transport := &http.Transport{}
	if opts.SkipTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return &HTTPClient{
		inner: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		vars: vars,
	}
}

// Response captures an HTTP response for assertion evaluation.
type Response struct {
	URL        string
	StatusCode int
	Headers    http.Header
	Body       []byte
	Elapsed    time.Duration
}

// BodyString returns the response body as a string.
func (r *Response) BodyString() string {
	return string(r.Body)
}

// IsSuccess returns true for 2xx status codes.
func (r *Response) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

// JSONField extracts a nested field from the response body using a dot-path.
// Example: JSONField("scope") returns the "scope" value from a flat JSON object.
// Returns empty string if the field is absent or the body is not valid JSON.
func (r *Response) JSONField(path string) string {
	var m map[string]interface{}
	if err := json.Unmarshal(r.Body, &m); err != nil {
		return ""
	}
	parts := strings.Split(path, ".")
	var cur interface{} = m
	for _, part := range parts {
		mm, ok := cur.(map[string]interface{})
		if !ok {
			return ""
		}
		cur = mm[part]
	}
	switch v := cur.(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

// ContainsAny returns true if the body contains any of the given substrings.
func (r *Response) ContainsAny(substrings ...string) bool {
	body := r.BodyString()
	for _, s := range substrings {
		if strings.Contains(body, s) {
			return true
		}
	}
	return false
}

// GET sends a GET request to the expanded URL.
func (c *HTTPClient) GET(ctx context.Context, urlTpl string, headers map[string]string) (*Response, error) {
	return c.do(ctx, http.MethodGet, c.vars.Expand(urlTpl), nil, c.vars.ExpandMap(headers))
}

// OPTIONS sends an OPTIONS request (used for CORS preflight probes).
func (c *HTTPClient) OPTIONS(ctx context.Context, urlTpl string, headers map[string]string) (*Response, error) {
	return c.do(ctx, http.MethodOptions, c.vars.Expand(urlTpl), nil, c.vars.ExpandMap(headers))
}

// POST sends a POST request with a JSON body. body may be a map or struct.
func (c *HTTPClient) POST(ctx context.Context, urlTpl string, headers map[string]string, body interface{}) (*Response, error) {
	jsonBytes, err := marshalBody(body, c.vars)
	if err != nil {
		return nil, err
	}
	merged := map[string]string{"Content-Type": "application/json"}
	for k, v := range c.vars.ExpandMap(headers) {
		merged[k] = v
	}
	return c.do(ctx, http.MethodPost, c.vars.Expand(urlTpl), bytes.NewReader(jsonBytes), merged)
}

// do executes an HTTP request and returns the captured Response.
func (c *HTTPClient) do(ctx context.Context, method, url string, body io.Reader, headers map[string]string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("building %s %s: %w", method, url, err)
	}
	req.Header.Set("User-Agent", "batesian/dev (https://github.com/calvin-mcdowell/batesian)")
	// MCP streamable HTTP requires text/event-stream in Accept; A2A servers ignore it.
	req.Header.Set("Accept", "application/json, text/event-stream")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := c.inner.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, url, err)
	}
	defer resp.Body.Close()

	var respBody []byte
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/event-stream") {
		// SSE streams never close; read only the first data event then stop.
		respBody = readFirstSSEEvent(resp.Body)
	} else {
		respBody, err = io.ReadAll(io.LimitReader(resp.Body, maxBody))
		if err != nil {
			return nil, fmt.Errorf("reading response from %s: %w", url, err)
		}
	}

	return &Response{
		URL:        url,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       respBody,
		Elapsed:    elapsed,
	}, nil
}

// readFirstSSEEvent reads a Server-Sent Events stream and returns the JSON payload
// from the first "data:" line. The connection is not drained; the caller's defer
// closes the body once we return. This avoids hanging indefinitely on a stream
// that the server never closes (standard for MCP streamable HTTP transport).
//
// The scanner buffer is set to maxBody (1 MB) because MCP servers can emit
// data lines with large embedded payloads (e.g., server instructions).
func readFirstSSEEvent(r io.Reader) []byte {
	scanner := bufio.NewScanner(io.LimitReader(r, maxBody))
	scanner.Buffer(make([]byte, maxBody), maxBody)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data:") {
			payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			return []byte(payload)
		}
	}
	return nil
}

// marshalBody encodes body as JSON with template variable expansion applied to string values.
func marshalBody(body interface{}, vars Vars) ([]byte, error) {
	if body == nil {
		return nil, nil
	}
	// Encode to JSON, then decode back to interface{} so we can walk and expand strings.
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("encoding request body: %w", err)
	}
	// Expand template vars in the JSON string before re-encoding.
	expanded := vars.Expand(string(raw))
	return []byte(expanded), nil
}
