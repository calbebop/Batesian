package auth

import (
	"context"
	"net/http"
)

// DiscoverTokenURLWithClient is a test-only export of discoverTokenURLWithClient,
// allowing unit tests to inject an httptest server client without bypassing the
// SSRF scheme guard in the public DiscoverTokenURL function.
func DiscoverTokenURLWithClient(ctx context.Context, issuer string, client *http.Client) string {
	return discoverTokenURLWithClient(ctx, issuer, client)
}
