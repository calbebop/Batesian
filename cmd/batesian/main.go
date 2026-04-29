package main

import (
	"os"

	"github.com/calvin-mcdowell/batesian/internal/cli"
)

// Version variables are injected at build time by goreleaser via -ldflags.
// Defaults make `go run ./cmd/batesian` display useful information in development.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cli.SetVersion(version, commit, date)
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
