# Batesian

> **Active adversarial security testing for AI agent protocols.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.26+-00ADD8.svg)](https://golang.org)
[![Build](https://github.com/calvin-mcdowell/batesian/actions/workflows/ci.yml/badge.svg)](https://github.com/calvin-mcdowell/batesian/actions)
[![DCO](https://img.shields.io/badge/contributor%20agreement-DCO-blue.svg)](https://developercertificate.org)

Batesian is a red-team CLI that sends crafted adversarial payloads against A2A and MCP protocol implementations to surface vulnerabilities that observation-only tools never reach: SSRF via push-notification callbacks, OAuth scope escalation through dynamic client registration, JWS algorithm confusion, cross-session context injection, and more.

> **Authorized use only.** Only run Batesian against systems you own or have explicit written permission to test. Unauthorized use is illegal and unethical.

---

## Why Batesian exists

Most agent security tooling today takes an observational posture: connect to a running server, read what it exposes, check spec compliance, and pattern-match for known strings. That approach is genuinely useful and catches a real class of problems.

It leaves another class completely untested. Some vulnerabilities only surface when the system processes a crafted attack payload -- an abused OAuth registration flow, a push-notification callback pointed at an attacker-controlled host, a JWS signature stripped down to `"alg":"none"`. Passive inspection cannot reach these because they require the server to act, not just exist.

Batesian is built for that second class. It does not replace observational scanning. It covers the ground that observational scanning structurally cannot.

---

## What Batesian tests

| ID | Attack Class | Protocol | Description |
|---|---|---|---|
| `a2a-push-ssrf-001` | Push Notification SSRF | A2A | Register a malicious callback URL; confirm the server makes an outbound request to an attacker-controlled host |
| `a2a-extcard-unauth-001` | Extended Agent Card Disclosure | A2A | Probe `GET /extendedAgentCard` without authentication; detect privileged capability leakage |
| `mcp-oauth-dcr-001` | OAuth DCR Scope Escalation | MCP | Abuse the dynamic client registration endpoint to request excessive scopes or hijack redirect URIs |
| `a2a-jws-algconf-001` | JWS Algorithm Confusion | A2A | Send JWS assertions with `"alg":"none"` or RS256 to HS256 confusion; detect missing signature validation |
| `a2a-session-smuggle-001` | Agent Session Smuggling | A2A | Inject covert instructions into an ongoing A2A session by acting as a malicious peer agent |
| `mcp-tool-poison-001` | Tool Poisoning Detection | MCP | Probe tool descriptions for embedded prompt injection and exfiltration instructions |
| `a2a-task-idor-001` | Task IDOR | A2A | Test whether unauthenticated sessions can retrieve task history belonging to other sessions |
| `mcp-resources-unauth-001` | Unauthenticated Resource Read | MCP | Access MCP resources without credentials; detect exposed secrets or configuration data |
| `mcp-sampling-inject-001` | Sampling Injection | MCP | Detect server-initiated `sampling/createMessage` requests embedding prompt injection |
| `a2a-context-orphan-001` | Cross-Session Context Injection | A2A | Test whether a new session can inject into or read from a context owned by a different session |

## What makes Batesian different

|  | Batesian | Snyk agent-scan | cisco/a2a-scanner | cisco/mcp-scanner |
|---|:---:|:---:|:---:|:---:|
| Active adversarial probing | ✓ | ✗ | ✗ | ✗ |
| OAuth / auth flow attack testing | ✓ | ✗ | ✗ | ✗ |
| A2A protocol coverage | ✓ | ✗ | ✓ | ✗ |
| MCP protocol coverage | ✓ | ✓ | ✗ | ✓ |
| Cross-protocol (A2A + MCP) in one tool | ✓ | ✗ | ✗ | ✗ |
| SARIF output (GitHub Code Scanning) | ✓ | ✗ | ✗ | ✗ |
| Runs without an LLM API key | ✓ | ✗ | partial | partial |
| Air-gap / offline compatible | ✓ | ✗ | ✗ | ✗ |
| Single compiled binary | ✓ | ✗ | ✗ | ✗ |
| YAML rule packs (no Go required) | ✓ | ✗ | ✗ | ✗ |

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

Early development. Active construction. Star or watch this repo to follow progress.

## Contributing

Contributions welcome, especially new attack rules. No engine knowledge required to write a rule.

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributors sign off commits with a DCO (`git commit -s`).

## References

- [A2A Protocol Specification](https://google.github.io/A2A/)
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/authorization)
- [Unit 42: Agent Session Smuggling in A2A Systems](https://unit42.paloaltonetworks.com/agent-session-smuggling-in-agent2agent-systems/)
- [OWASP GenAI Security Project](https://genai.owasp.org)

## License

Apache 2.0. See [LICENSE](LICENSE).
