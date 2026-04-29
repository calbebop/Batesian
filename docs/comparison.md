# Batesian vs. Other Tools

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

## Why the distinction matters

Most agent security tooling takes an observational posture: connect, read what the server exposes,
check spec compliance, and pattern-match for known strings. That catches a real class of problems.

It leaves another class completely untested. Some vulnerabilities only surface when the system
processes a crafted attack payload -- an abused OAuth registration flow, a push-notification
callback pointed at an attacker-controlled host, a JWS signature stripped to `"alg":"none"`.
Passive inspection cannot reach these because they require the server to act, not just exist.

Batesian is built for that second class. It does not replace observational scanning. It covers the
ground that observational scanning structurally cannot.
