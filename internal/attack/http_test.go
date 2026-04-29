package attack_test

import (
	"testing"

	"github.com/calvin-mcdowell/batesian/internal/attack"
)

func TestNewUnauthHTTPClient_StripsToken(t *testing.T) {
	opts := attack.Options{
		Token:          "super-secret",
		TimeoutSeconds: 30,
		SkipTLS:        true,
	}
	vars := attack.NewVars("https://example.com", "")

	c := attack.NewUnauthHTTPClient(opts, vars)

	if attack.TokenOf(c) != "" {
		t.Errorf("NewUnauthHTTPClient: expected empty token, got %q", attack.TokenOf(c))
	}
}

func TestNewHTTPClient_PreservesToken(t *testing.T) {
	opts := attack.Options{
		Token:          "my-token",
		TimeoutSeconds: 10,
	}
	vars := attack.NewVars("https://example.com", "")

	c := attack.NewHTTPClient(opts, vars)

	if attack.TokenOf(c) != "my-token" {
		t.Errorf("NewHTTPClient: expected token %q, got %q", "my-token", attack.TokenOf(c))
	}
}
