# Batesian

> **Active adversarial security testing for AI agent protocols.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.25+-00ADD8.svg)](https://golang.org)
[![Build](https://github.com/calvin-mcdowell/batesian/actions/workflows/ci.yml/badge.svg)](https://github.com/calvin-mcdowell/batesian/actions)

Batesian is a red-team CLI that sends crafted adversarial payloads against A2A and MCP protocol
implementations to surface vulnerabilities that observation-only tools never reach: SSRF via
push-notification callbacks, OAuth scope escalation, JWS algorithm confusion, cross-session
context injection, and more.

![Batesian demo](docs/demo.gif)

> **Authorized use only.** Only run Batesian against systems you own or have explicit written
> permission to test. Unauthorized use is illegal and unethical.

---

## Why Batesian exists

Most agent security tooling takes an observational posture: connect to a running server, read what
it exposes, check spec compliance, and pattern-match for known strings. That approach is genuinely
useful and catches a real class of problems.

It leaves another class completely untested. Some vulnerabilities only surface when the system
processes a crafted attack payload such as an abused OAuth registration flow, a push-notification
callback pointed at an attacker-controlled host, a JWS signature stripped down to `"alg":"none"`.
Passive inspection cannot reach these because they require the server to act, not just exist.

Batesian is built for that second class. It does not replace observational scanning. It covers the
ground that observational scanning structurally cannot.

See [docs/comparison.md](docs/comparison.md) for a full breakdown against other tools in the space.

---

## What Batesian tests

Batesian ships **18 A2A rules** and **16 MCP rules**, covering SSRF, OAuth abuse, JWS algorithm
confusion, prompt injection, protocol downgrade, TLS enforcement, and more.

- [A2A rule catalog](docs/rules-a2a.md) — Agent-to-Agent protocol attacks
- [MCP rule catalog](docs/rules-mcp.md) — Model Context Protocol attacks

Each finding is classified as `confirmed` (exploit succeeded) or `indicator` (behavioral signal
warranting manual review). All rules ship with CWE references and remediation guidance.

---

## Quickstart

```bash
# Install (no API keys, no Python, no setup)
go install github.com/calvin-mcdowell/batesian/cmd/batesian@latest

# Probe an A2A endpoint and map the attack surface
batesian probe --target https://agent.example.com --protocol a2a

# Full scan with SARIF output for GitHub Code Scanning
batesian scan --target https://agent.example.com --output sarif > results.sarif

# Run specific rules only
batesian scan --target https://agent.example.com --rule-ids a2a-push-ssrf-001,mcp-tool-poison-001

# Scan an authenticated MCP endpoint (static token)
batesian scan --target https://mcp.example.com --token "$TOKEN"

# Scan with automatic OAuth 2.0 client credentials token acquisition
batesian scan --target https://mcp.example.com \
  --token-url https://auth.example.com/oauth/token \
  --client-id my-client \
  --client-secret "$CLIENT_SECRET" \
  --oauth-scopes mcp:read,mcp:write

# Scan with OAuth 2.0 authorization code + PKCE (interactive; opens browser)
batesian scan --target https://mcp.example.com \
  --auth-url https://auth.example.com/authorize \
  --token-url https://auth.example.com/oauth/token \
  --client-id my-client \
  --oauth-scopes mcp:read

# Generate an annotated batesian.yaml config file
batesian init
```

Use `scan` for SARIF (for example GitHub Code Scanning uploads). The `probe` command does not support `--output sarif`; it is for quick reconnaissance with table or JSON output only.

More options for `scan` (filters, config file, custom rules, OAuth, and more): run `batesian scan --help`.

---

## Rule packs

Attack rules are YAML files. Anyone can write new attack patterns without touching Go. Rules load
at runtime thus no recompilation needed. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full
authoring guide including the rule schema, validation checklist, and testing requirements.

---

## Python SDK

```python
from batesian import Scanner

scanner = Scanner(target="https://agent.example.com")
results = scanner.run(rules=["a2a-push-ssrf-001", "mcp-tool-poison-001"])

for finding in results.findings:
    print(f"[{finding.severity}] {finding.rule_id}: {finding.title}")

assert results.critical_count == 0
```

See [`sdk/python/`](sdk/python/) for installation, full API reference, and CI integration examples.

---

## Status

The rule engine and all 34 bundled rules are production-ready. New rules and protocol coverage are
in active development. Star or watch to follow progress.

---

## Contributing

Contributions welcome, especially new attack rules. No engine knowledge required to write a rule.

See [CONTRIBUTING.md](CONTRIBUTING.md). Contributions are accepted under the same
[Apache License 2.0](LICENSE) as the rest of the project.

---

## References

- [A2A Protocol Specification](https://google.github.io/A2A/)
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/authorization)
- [Unit 42: Agent Session Smuggling in A2A Systems](https://unit42.paloaltonetworks.com/agent-session-smuggling-in-agent2agent-systems/)
- [OWASP GenAI Security Project](https://genai.owasp.org)

---

## License

Apache 2.0. See [LICENSE](LICENSE).
