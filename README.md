# Batesian

> **The adversarial red-team CLI for AI agent protocols.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.26+-00ADD8.svg)](https://golang.org)
[![Build](https://github.com/calvin-mcdowell/batesian/actions/workflows/ci.yml/badge.svg)](https://github.com/calvin-mcdowell/batesian/actions)
[![DCO](https://img.shields.io/badge/contributor%20agreement-DCO-blue.svg)](https://developercertificate.org)

Every other tool in this space is a **scanner**: it connects to your agent and reads what's there. Batesian is an **attacker**. It impersonates malicious agent peers, abuses authentication flows, and sends crafted protocol payloads to find vulnerabilities that passive scanners never see.

---

## Why Batesian exists

The four major open-source agent security tools (Snyk agent-scan, cisco/a2a-scanner, cisco/mcp-scanner, antgroup/MCPScan) all share the same fundamental posture: they connect to a running server and *observe* what's there: reading tool descriptions, checking compliance, pattern-matching text. Not one of them:

- Sends a crafted, malicious protocol payload and tests how the target *responds*
- Abuses the OAuth 2.1 / dynamic client registration flow to escalate privileges
- Impersonates a peer agent to test A2A authentication
- Tests what happens when a malicious callback URL is registered for push notifications
- Produces SARIF output for GitHub Code Scanning integration
- Runs without an external LLM API key or internet connection

Batesian fills every one of those gaps.

---

## What Batesian tests

| ID | Attack Class | Protocol | Description |
|---|---|---|---|
| `a2a-push-ssrf-001` | Push Notification SSRF | A2A | Register a malicious callback URL; confirm the server makes an outbound request to an attacker-controlled host |
| `a2a-extcard-unauth-001` | Extended Agent Card Disclosure | A2A | Probe `GET /extendedAgentCard` without authentication; detect privileged capability leakage |
| `mcp-oauth-dcr-001` | OAuth DCR Scope Escalation | MCP | Abuse the dynamic client registration endpoint to request excessive scopes or hijack redirect URIs |
| `a2a-jws-bypass-001` | JWS Algorithm Confusion | A2A | Send JWS assertions with `"alg":"none"` or RS256→HS256 confusion; detect missing signature validation |
| `a2a-session-smuggling-001` | Agent Session Smuggling | A2A | Inject covert instructions into an ongoing A2A session by acting as a malicious peer agent |
| `mcp-tool-poison-001` | Tool Poisoning Detection | MCP | Probe tool descriptions for embedded prompt injection and exfiltration instructions |
| `a2a-json-rpc-fuzz-001` | JSON-RPC Protocol Fuzzing | A2A / MCP | Mutate JSON-RPC 2.0 messages to find type confusion, parser errors, and deserialization failures |
| `mcp-token-replay-001` | OAuth Token Replay | MCP | Test whether tokens lack `aud` claim binding and can be replayed across endpoints |

## What makes Batesian different

| | Batesian | Snyk agent-scan | cisco/a2a-scanner | cisco/mcp-scanner |
|---|:---:|:---:|:---:|:---:|
| Black-box (no source/config needed) | ✓ | ✗ | partial | partial |
| Active adversarial probing | ✓ | ✗ | ✗ | ✗ |
| OAuth / auth flow attack testing | ✓ | ✗ | ✗ | ✗ |
| A2A protocol coverage | ✓ | ✗ | partial | ✗ |
| MCP protocol coverage | ✓ | ✓ | ✗ | ✓ |
| Cross-protocol (A2A + MCP) session | ✓ | ✗ | ✗ | ✗ |
| SARIF output (GitHub Code Scanning) | ✓ | ✗ | ✗ | ✗ |
| No LLM API key required | ✓ | ✗ | ✗ | ✗ |
| Air-gap / offline compatible | ✓ | ✗ | ✗ | ✗ |
| Go single binary (no Python venv) | ✓ | ✗ | ✗ | ✗ |
| Community-editable rule packs | ✓ | ✗ | partial | partial |

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
batesian scan --target https://agent.example.com --rules rules/a2a/push-ssrf-001.yaml
```

## Rule packs

Batesian attack rules are YAML files. Anyone can write new attack patterns without touching Go. Rules load at runtime; no recompilation needed.

```yaml
id: a2a-push-ssrf-001
info:
  name: A2A Push Notification SSRF
  severity: high
  tags: [a2a, ssrf, push-notification]
  references:
    - https://github.com/google-a2a/a2a-python/issues/786

attack:
  protocol: a2a
  type: push-notification-ssrf
  register:
    pushNotificationConfig:
      url: "{{OOBListener}}"
      token: "batesian-probe"
  trigger:
    send_task: true

assert:
  - condition: oob_callback_received
    description: "Server made outbound HTTP request to attacker-controlled URL"
    severity: high
```

## Python SDK

```python
from batesian import Scanner

scanner = Scanner(target="http://localhost:8080")
results = scanner.run(rules=["a2a/push-ssrf", "mcp/oauth-dcr", "a2a/extcard-unauth"])

for finding in results.findings:
    print(f"[{finding.severity}] {finding.id}: {finding.description}")

assert results.critical_count == 0
```

## Status

🚧 **Early development.** Active construction. Star or watch this repo to follow progress.

Immediate roadmap:
- [ ] `probe` command: A2A Agent Card fetch and attack surface mapping
- [ ] `a2a-push-ssrf-001`: first end-to-end working rule
- [ ] `a2a-extcard-unauth-001`
- [ ] `mcp-oauth-dcr-001`
- [ ] SARIF 2.1.0 output format

## Contributing

Contributions welcome, especially new attack rules. No engine knowledge required to write a rule.

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributors sign off commits with a DCO (`git commit -s`).

## References

- [A2A Protocol Specification](https://a2aprotocol.ai/docs)
- [MCP Security Specification](https://modelcontextprotocol.io/docs/concepts/security)
- [Unit 42: Agent Session Smuggling in A2A Systems](https://unit42.paloaltonetworks.com/agent-session-smuggling-in-agent2agent-systems/) (Oct 2025)
- [OWASP Agentic AI Top 10](https://genai.owasp.org)
- [MCP OAuth 2.1 Authorization Spec](https://modelcontextprotocol.io/docs/concepts/authorization)

## License

Apache 2.0. See [LICENSE](LICENSE).
