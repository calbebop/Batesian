package mcp

import (
	"context"
	"strings"

	"github.com/calvin-mcdowell/batesian/internal/attack"
)

// candidatePaths are tried in order when discovering an MCP endpoint.
// Servers commonly mount the JSON-RPC handler at /mcp, /, /api, or /rpc.
var candidatePaths = []string{"/mcp", "/", "/api", "/rpc"}

// endpointCandidates returns candidate URLs to try for the given base URL.
func endpointCandidates(baseURL string) []string {
	out := make([]string, len(candidatePaths))
	for i, p := range candidatePaths {
		out[i] = baseURL + p
	}
	return out
}

// mcpSession holds the discovered MCP endpoint and the session ID returned by
// the server's initialize response. All subsequent JSON-RPC requests in the
// same MCP connection must echo the session ID via the Mcp-Session-Id header;
// servers that implement the MCP 2025-03-26 spec will reject requests that
// omit it with a 4xx error, which would cause all our rule checks to silently
// return no findings.
type mcpSession struct {
	Endpoint  string
	SessionID string
}

// header returns the Mcp-Session-Id header map if a session ID is present,
// or nil if the server did not issue one (older servers, test servers).
func (s mcpSession) header() map[string]string {
	if s.SessionID == "" {
		return nil
	}
	return map[string]string{"Mcp-Session-Id": s.SessionID}
}

// discoverMCPEndpoint probes each candidate path and returns the first one that
// responds to a JSON-RPC POST with a recognisable MCP response. Returns "" if
// none of the candidates respond.
func discoverMCPEndpoint(ctx context.Context, client *attack.HTTPClient, baseURL string) string {
	initBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "batesian", "version": "1.0"},
		},
	}
	for _, ep := range endpointCandidates(baseURL) {
		resp, err := client.POST(ctx, ep, nil, initBody)
		if err != nil || !resp.IsSuccess() {
			continue
		}
		body := string(resp.Body)
		if strings.Contains(body, "protocolVersion") || strings.Contains(body, "jsonrpc") {
			return ep
		}
	}
	return ""
}
