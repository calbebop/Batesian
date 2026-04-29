# Batesian

> **Active adversarial security testing for AI agent protocols.**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.25+-00ADD8.svg)](https://golang.org)
[![Build](https://github.com/calvin-mcdowell/batesian/actions/workflows/ci.yml/badge.svg)](https://github.com/calvin-mcdowell/batesian/actions)
[![DCO](https://img.shields.io/badge/contributor%20agreement-DCO-blue.svg)](https://developercertificate.org)

Batesian is a red-team CLI that sends crafted adversarial payloads against A2A and MCP protocol implementations to surface vulnerabilities that observation-only tools never reach: SSRF via push-notification callbacks, OAuth scope escalation through dynamic client registration, JWS algorithm confusion, cross-session context injection, and more.

![Batesian demo](docs/demo.gif)

> **Authorized use only.** Only run Batesian against systems you own or have explicit written permission to test. Unauthorized use is illegal and unethical.

---

## Why Batesian exists

Most agent security tooling today takes an observational posture: connect to a running server, read what it exposes, check spec compliance, and pattern-match for known strings. That approach is genuinely useful and catches a real class of problems.

It leaves another class completely untested. Some vulnerabilities only surface when the system processes a crafted attack payload -- an abused OAuth registration flow, a push-notification callback pointed at an attacker-controlled host, a JWS signature stripped down to `"alg":"none"`. Passive inspection cannot reach these because they require the server to act, not just exist.

Batesian is built for that second class. It does not replace observational scanning. It covers the ground that observational scanning structurally cannot.

---

## What Batesian tests

### A2A (Agent-to-Agent)

| Rule ID | Attack | What it confirms |
|---|---|---|
| `a2a-push-ssrf-001` | Push Notification SSRF | Server makes outbound HTTP request to an attacker-controlled callback URL |
| `a2a-extcard-unauth-001` | Extended Agent Card Disclosure | Privileged capabilities leak from `GET /extendedAgentCard` without authentication |
| `a2a-jws-algconf-001` | JWS Algorithm Confusion | Server accepts JWS with `"alg":"none"` or RS256-to-HS256 downgrade |
| `a2a-session-smuggle-001` | Agent Session Smuggling | Covert instructions injected into a session by a malicious peer agent |
| `a2a-task-idor-001` | Task IDOR | Unauthenticated session retrieves task history belonging to another session |
| `a2a-context-orphan-001` | Cross-Session Context Injection | New session reads or injects into a context owned by a different session |
| `a2a-json-rpc-fuzz-001` | JSON-RPC Mutation Fuzzing | Malformed payloads produce stack traces or unhandled panics |
| `a2a-peer-impersonation-001` | Peer Agent Impersonation | Forged JWT claiming a trusted peer identity accepted without origin verification |
| `a2a-delegation-escalation-001` | Delegation Escalation | Privileged metadata injected in `configuration` blocks accepted without validation |
| `a2a-wellknown-hostinject-001` | Agent Card Host Header Injection | Attacker-controlled domain reflected in Agent Card via `Host` / `X-Forwarded-Host` |
| `a2a-artifact-tamper-001` | Task Artifact Tampering | Completed task re-submitted with different content; server accepts without immutability check |
| `a2a-skill-poison-001` | Skill Description Injection | Agent Card skill descriptions or examples contain prompt injection patterns |
| `a2a-url-mismatch-001` | Agent Card URL Mismatch | Agent Card `url` field points to a different domain than the card's serving host |
| `a2a-tls-downgrade-001` | TLS Downgrade | Agent Card and RPC endpoints respond over plain HTTP without HTTPS redirect |
| `a2a-capability-inflation-001` | Capability Inflation | `tasks/send` with undeclared elevated permissions accepted without a validation error |
| `a2a-security-headers-001` | Missing Security Headers | A2A endpoints return no HSTS, X-Content-Type-Options, or framing protection headers |
| `a2a-registry-poison-001` | Agent Registry Poisoning | Registry endpoint accepts unauthenticated agent card registration or identity overwrite |
| `a2a-circular-delegation-001` | Circular Delegation | Agent accepts `tasks/send` with a 10-hop delegation chain and no depth-limit error |

### MCP (Model Context Protocol)

| Rule ID | Attack | What it confirms |
|---|---|---|
| `mcp-oauth-dcr-001` | OAuth DCR Scope Escalation | Dynamic client registration grants excessive scopes or accepts hijacked redirect URIs |
| `mcp-tool-poison-001` | Tool Poisoning / Rug Pull | Tool descriptions contain prompt injection patterns or change across sessions |
| `mcp-resources-unauth-001` | Unauthenticated Resource Read | Resources endpoint returns secrets or configuration data without credentials |
| `mcp-sampling-inject-001` | Sampling Injection | `sampling/createMessage` requests from the server embed prompt injection |
| `mcp-token-replay-001` | Bearer Token Replay | OAuth tokens with incorrect `aud` claims accepted without audience validation |
| `mcp-init-downgrade-001` | Protocol Version Downgrade | Server disables security controls when negotiating protocol version `2024-11-05` |
| `mcp-cors-wildcard-001` | CORS Wildcard with Credentials | Server returns `Access-Control-Allow-Origin: *` alongside `Access-Control-Allow-Credentials: true` |
| `mcp-prompt-unauth-001` | Prompt Templates Without Auth | `prompts/list` and `prompts/get` respond without credentials |
| `mcp-context-flood-001` | Context Window Flooding | Server accepts 1MB and 5MB tool call arguments with no payload size limit |
| `mcp-tool-namespace-001` | Tool Namespace Collision | Tool descriptions differ between two independent sessions (rug pull precondition) |
| `mcp-sse-hijack-001` | Unauthenticated SSE Stream | SSE stream endpoints accept connections without authentication |
| `mcp-init-instructions-inject-001` | Server Instructions Injection | `serverInfo.instructions` returned at initialize time contains prompt injection patterns |
| `mcp-ratelimit-absent-001` | Missing Rate Limiting | Server accepts 25-request burst with no HTTP 429 or throttle response |
| `mcp-homoglyph-tool-001` | Tool Name Homoglyph | Server accepts `tools/call` with Unicode homoglyph tool names without identity normalization |
| `mcp-injection-params-001` | Tool Parameter Injection | SQL errors, command output, or script tags reflected from unsanitized tool call arguments |
| `mcp-security-headers-001` | Missing Security Headers | MCP endpoints return no HSTS, X-Content-Type-Options, or framing protection headers |

## What makes Batesian different

|  | Batesian | Snyk agent-scan | cisco/a2a-scanner | cisco/mcp-scanner |
|---|:---:|:---:|:---:|:---:|
| **Approach** | Active red-team | Passive supply-chain scan | Passive static + light endpoint | Passive YARA / LLM / behavioral |
| Active adversarial probing | ✓ | ✗ | ✗ | ✗ |
| OOB / blind SSRF detection | ✓ | ✗ | ✗ | ✗ |
| Cryptographic attack testing | ✓ | ✗ | ✗ | ✗ |
| OAuth flow attack testing | ✓ | ✗ | ✗ | ✗ |
| CORS misconfiguration testing | ✓ | ✗ | ✗ | ✗ |
| Protocol version downgrade attacks | ✓ | ✗ | ✗ | ✗ |
| Single compiled binary, no runtime dependencies | ✓ | ✗ | ✗ | ✗ |
| No cloud account or API key required | ✓ | ✗ (Snyk token) | optional | optional |
| Air-gap / offline compatible | ✓ | ✗ | ✗ | ✗ |
| YAML rule packs (no Go required to add rules) | ✓ | ✗ | ✗ | ✗ |

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

# Generate an annotated batesian.yaml config file
batesian init
```

## Rule packs

Batesian attack rules are YAML files. Anyone can write new attack patterns without touching Go. Rules load at runtime; no recompilation needed.

Each rule pairs a metadata block with an `attack.type` that maps to a registered Go executor. The executor reads target-specific parameters from the YAML and decides how to probe the server. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full authoring guide.

```yaml
# Minimal rule skeleton -- see CONTRIBUTING.md for the full schema.
id: a2a-example-001
info:
  name: Example A2A Rule
  author: your-handle
  severity: high          # critical | high | medium | low | info
  description: |
    One-paragraph description of the vulnerability and why it matters.
  references:
    - https://a2aprotocol.ai/docs/specification
  tags:
    - a2a
    - authentication

attack:
  protocol: a2a           # a2a | mcp
  type: a2a-example       # must match a registered executor in engine.go

assert:
  - condition: example_condition
    description: "Human-readable finding description"
    severity: high

remediation: |
  Detailed fix guidance for developers.
```

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
