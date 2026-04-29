# Changelog

All notable changes to Batesian will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Batesian uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- 34 attack rules across A2A and MCP protocols
- Active exploit engine with `confirmed` / `indicator` confidence model
- `batesian scan` command with JSON, table, and SARIF output formats
- `batesian probe` command for rapid attack surface discovery
- `batesian rules` command to list bundled rule packs
- `batesian init` command to scaffold a `batesian.yaml` config file
- OAuth 2.0 support: client credentials and PKCE authorization code flows
- Out-of-band (OOB) listener for SSRF callback detection
- Python SDK (`batesian` package) wrapping the Go CLI
- SARIF output compatible with GitHub Security tab
- CI pipeline: build, test, lint (`golangci-lint`), vulnerability scan (`govulncheck`)
- DCO enforcement for contributor sign-offs
- Goreleaser cross-platform binary releases (Linux, macOS, Windows)
- CWE references on all bundled rules

[Unreleased]: https://github.com/calvin-mcdowell/batesian/compare/HEAD...HEAD
