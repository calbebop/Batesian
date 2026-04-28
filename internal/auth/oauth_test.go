package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calvin-mcdowell/batesian/internal/auth"
)

func TestFetchClientCredentialsToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.FormValue("grant_type") != "client_credentials" {
			http.Error(w, "bad grant_type", http.StatusBadRequest)
			return
		}
		if r.FormValue("client_id") != "test-client" {
			http.Error(w, "bad client_id", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "read write",
		})
	}))
	defer srv.Close()

	tok, err := auth.FetchClientCredentialsToken(context.Background(), auth.ClientCredentialsConfig{
		TokenURL:     srv.URL + "/token",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Scopes:       []string{"read", "write"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "test-access-token" {
		t.Errorf("expected access_token=test-access-token, got %q", tok.AccessToken)
	}
	if tok.ExpiresIn != 3600 {
		t.Errorf("expected expires_in=3600, got %d", tok.ExpiresIn)
	}
}

func TestFetchClientCredentialsToken_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
	}))
	defer srv.Close()

	_, err := auth.FetchClientCredentialsToken(context.Background(), auth.ClientCredentialsConfig{
		TokenURL: srv.URL + "/token",
		ClientID: "bad-client",
	})
	if err == nil {
		t.Fatal("expected error for 401 response, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP 401") {
		t.Errorf("expected HTTP 401 in error, got: %v", err)
	}
}

func TestFetchClientCredentialsToken_EmptyToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"token_type":"Bearer"}`)) // Missing access_token.
	}))
	defer srv.Close()

	_, err := auth.FetchClientCredentialsToken(context.Background(), auth.ClientCredentialsConfig{
		TokenURL: srv.URL,
		ClientID: "c",
	})
	if err == nil {
		t.Fatal("expected error for empty access_token, got nil")
	}
}

func TestGeneratePKCE(t *testing.T) {
	p, err := auth.GeneratePKCE()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(p.Verifier) < 43 {
		t.Errorf("PKCE verifier too short: %d chars", len(p.Verifier))
	}
	if p.Challenge == p.Verifier {
		t.Error("PKCE challenge should differ from verifier (must be S256 hash)")
	}

	// Generate twice to confirm uniqueness.
	p2, _ := auth.GeneratePKCE()
	if p.Verifier == p2.Verifier {
		t.Error("PKCE verifiers should be unique across calls")
	}
}

func TestDiscoverTokenURL(t *testing.T) {
	// Serve an OIDC well-known document.
	// Use a mux so the server URL is available inside the handler via r.Host.
	var tokenEndpoint string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":         tokenEndpoint,
				"token_endpoint": tokenEndpoint + "/oauth/token",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	tokenEndpoint = srv.URL

	ep := auth.DiscoverTokenURL(context.Background(), srv.URL)
	if ep == "" {
		t.Fatal("expected token endpoint from OIDC discovery, got empty string")
	}
	if !strings.HasSuffix(ep, "/oauth/token") {
		t.Errorf("unexpected token endpoint: %q", ep)
	}
}

func TestDiscoverTokenURL_NoDiscovery(t *testing.T) {
	// Server has no well-known documents.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	ep := auth.DiscoverTokenURL(context.Background(), srv.URL)
	if ep != "" {
		t.Errorf("expected empty string for server without discovery, got %q", ep)
	}
}
