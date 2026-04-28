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
| `a2a-jws-algconf-001` | JWS Algorithm Confusion | A2A | Send JWS assertions with `"alg":"none"` or RS256-to-HS256 confusion; detect missing signature validation |
| `a2a-session-smuggle-001` | Agent Session Smuggling | A2A | Inject covert instructions into an ongoing A2A session by acting as a malicious peer agent |
| `mcp-tool-poison-001` | Tool Poisoning / Rug Pull | MCP | Probe tool descriptions for embedded prompt injection and exfiltration instructions; detect mid-session description changes |
| `a2a-task-idor-001` | Task IDOR | A2A | Test whether unauthenticated sessions can retrieve task history belonging to other sessions |
| `mcp-resources-unauth-001` | Unauthenticated Resource Read | MCP | Access MCP resources without credentials; detect exposed secrets or configuration data |
| `mcp-sampling-inject-001` | Sampling Injection | MCP | Detect server-initiated `sampling/createMessage` requests embedding prompt injection |
| `a2a-context-orphan-001` | Cross-Session Context Injection | A2A | Test whether a new session can inject into or read from a context owned by a different session |
| `mcp-token-replay-001` | Bearer Token Replay | MCP | Forge and replay OAuth tokens with incorrect audience claims; detect missing `aud` validation |
| `a2a-json-rpc-fuzz-001` | JSON-RPC Mutation Fuzzing | A2A | Send malformed and boundary-case JSON-RPC payloads; detect stack traces and unhandled panics |
| `a2a-peer-impersonation-001` | Peer Agent Impersonation | A2A | Forge JWTs claiming a trusted peer agent identity; detect missing token origin verification |
| `a2a-delegation-escalation-001` | Delegation Escalation | A2A | Inject privileged metadata into `configuration` blocks; detect unauthorized capability acceptance |
| `mcp-init-downgrade-001` | Protocol Version Downgrade | MCP | Negotiate `2024-11-05`; detect servers that disable security controls on older protocol versions |
| `mcp-cors-wildcard-001` | CORS Wildcard with Credentials | MCP | Send a cross-origin preflight with `Origin: https://evil.batesian.invalid`; detect permissive CORS + ACAC headers |
| `mcp-prompt-unauth-001` | Prompt Templates Without Auth | MCP | Access `prompts/list` and `prompts/get` without credentials; detect unauthenticated prompt exposure |
| `a2a-wellknown-hostinject-001` | Agent Card Host Header Injection | A2A | Inject `Host`, `X-Forwarded-Host`; detect reflection of attacker-controlled domains in the Agent Card |
| `a2a-artifact-tamper-001` | Task Artifact Tampering | A2A | Re-submit a completed task with the same ID and different content; detect missing task immutability enforcement |
| `a2a-skill-poison-001` | AgentCard Skill Injection | A2A | Scan skill descriptions and examples for prompt injection patterns using heuristic scoring |
| `a2a-url-mismatch-001` | Agent Card URL Mismatch | A2A | Detect Agent Cards whose `url` field points to a different domain than the card's serving host |
| `mcp-context-flood-001` | Context Window Flooding | MCP | Submit 1MB and 5MB tool call arguments; detect missing payload size limits |
| `mcp-tool-namespace-001` | Tool Namespace Collision | MCP | Connect twice with independent sessions; detect tool description changes between sessions (rug pull precondition) |
| `mcp-sse-hijack-001` | Unauthenticated SSE Stream | MCP | Probe MCP SSE endpoints without credentials; detect streams that accept connections without authentication |

## What makes Batesian different

|  | Batesian | Snyk agent-scan | cisco/a2a-scanner | cisco/mcp-scanner |
|---|:---:|:---:|:---:|:---:|
| **Approach** | Active red-team | Passive supply-chain scan | Passive static + light endpoint | Passive YARA / LLM / behavioral |
| Active adversarial probing (sends attack payloads) | ✓ | ✗ | ✗ | ✗ |
| A2A active attack rules | 13 | 0 | 0 | 0 |
| MCP active attack rules | 11 | 0 | 0 | 0 |
| OOB / blind SSRF detection | ✓ | ✗ | ✗ | ✗ |
| Cryptographic attack testing (JWS alg confusion) | ✓ | ✗ | ✗ | ✗ |
| OAuth flow attack testing (DCR scope escalation) | ✓ | ✗ | ✗ | ✗ |
| CORS misconfiguration testing | ✓ | ✗ | ✗ | ✗ |
| Protocol version downgrade attacks | ✓ | ✗ | ✗ | ✗ |
| Cross-protocol (A2A + MCP) in one tool | ✓ | ✗ | ✗ | ✗ |
| SARIF output (GitHub Code Scanning) | ✓ | ✗ | ✗ | ✗ |
| Single compiled binary, no runtime dependencies | ✓ | ✗ | ✗ | ✗ |
| No cloud account or API key required | ✓ | ✗ (Snyk token) | optional | optional |
| Air-gap / offline compatible | ✓ | ✗ | ✗ | ✗ |
| YAML rule packs (no Go required to add rules) | ✓ | ✗ | ✗ | ✗ |
| Supply-chain / skill file static scanning | ✗ | ✓ | ✗ | partial |
| Source code / behavioral analysis | ✗ | ✗ | ✓ (YARA + LLM) | ✓ (behavioral + YARA) |

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
