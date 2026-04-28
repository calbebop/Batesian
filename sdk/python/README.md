# batesian Python SDK

Python wrapper around the [Batesian](https://github.com/calvin-mcdowell/batesian) red-team CLI for AI agent protocols.

## Requirements

- Python 3.9+
- The `batesian` CLI binary installed and on `PATH`

```bash
go install github.com/calvin-mcdowell/batesian/cmd/batesian@latest
```

## Install

```bash
pip install batesian
```

Or from source (within this directory):

```bash
pip install -e .
```

## Usage

```python
from batesian import Scanner

scanner = Scanner(target="https://agent.example.com")
results = scanner.run(rules=["a2a-push-ssrf-001", "mcp-tool-poison-001"])

for finding in results.findings:
    print(f"[{finding.severity}] {finding.rule_id}: {finding.title}")

assert results.critical_count == 0
```

### Scan all rules for a protocol

```python
results = scanner.run(protocol="mcp")
print(f"Found {results.high_count} high-severity issues")
```

### Filter by severity

```python
results = scanner.run(severities=["critical", "high"])
```

### Authenticated scan (static token)

```python
scanner = Scanner(target="https://mcp.example.com", token="my-bearer-token")
results = scanner.run()
```

### Authenticated scan (OAuth 2.0 client credentials)

```python
scanner = Scanner(
    target="https://mcp.example.com",
    token_url="https://auth.example.com/oauth/token",
    client_id="my-client-id",
    client_secret="my-client-secret",
    oauth_scopes=["mcp:read", "mcp:write"],
)
results = scanner.run()
```

### Use in CI (fail on critical findings)

```python
import sys
from batesian import Scanner

scanner = Scanner(target="https://agent.example.com")
results = scanner.run()

if results.critical_count > 0:
    for f in results.findings_by_severity("critical"):
        print(f"CRITICAL: {f.title}")
    sys.exit(1)
```

## API Reference

### `Scanner`

| Parameter | Type | Description |
|---|---|---|
| `target` | `str` | Base URL of the agent or MCP server |
| `binary_path` | `str` | Explicit path to batesian binary (optional) |
| `token` | `str` | Bearer token for authenticated requests |
| `token_url` | `str` | OAuth 2.0 token endpoint |
| `client_id` | `str` | OAuth 2.0 client ID |
| `client_secret` | `str` | OAuth 2.0 client secret |
| `oauth_scopes` | `list[str]` | OAuth 2.0 scopes |
| `timeout` | `int` | Per-request HTTP timeout in seconds (default: 10) |
| `skip_tls` | `bool` | Skip TLS verification (default: False) |
| `config` | `str` | Path to `batesian.yaml` config file |

### `Results`

| Property | Type | Description |
|---|---|---|
| `findings` | `list[Finding]` | All findings from the scan |
| `critical_count` | `int` | Number of critical-severity findings |
| `high_count` | `int` | Number of high-severity findings |
| `medium_count` | `int` | Number of medium-severity findings |
| `confirmed_count` | `int` | Findings with confirmed exploit confidence |
| `findings_by_severity(s)` | `list[Finding]` | Filter findings by severity string |
| `findings_for_rule(id)` | `list[Finding]` | Filter findings by rule ID |

### `Finding`

| Property | Type | Description |
|---|---|---|
| `rule_id` | `str` | Rule identifier (e.g. `a2a-push-ssrf-001`) |
| `severity` | `str` | `critical`, `high`, `medium`, `low`, `info` |
| `confidence` | `str` | `confirmed` or `indicator` |
| `title` | `str` | Short finding description |
| `description` | `str` | Detailed explanation |
| `evidence` | `str` | Raw evidence from the probe |
| `remediation` | `str` | Fix guidance |
| `is_confirmed` | `bool` | True when confidence is `confirmed` |

## Binary discovery

The SDK searches for the `batesian` binary in this order:

1. `binary_path` constructor argument
2. `BATESIAN_BIN` environment variable
3. `batesian` / `batesian.exe` on `PATH`
4. `~/go/bin/batesian`, `/usr/local/bin/batesian`

## License

Apache 2.0
