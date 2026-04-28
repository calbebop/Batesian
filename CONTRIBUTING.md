# Contributing to Batesian

Thank you for your interest in contributing. Please read this document before opening a pull request.

## Developer Certificate of Origin (DCO)

All contributors must sign off their commits with a DCO. This is a lightweight way to certify that you wrote (or have the right to submit) the contribution.

Add `-s` to your commit command:

```bash
git commit -s -m "feat: add new attack rule for X"
```

This adds a `Signed-off-by: Your Name <your@email.com>` trailer to the commit. A GitHub Action will automatically verify DCO compliance on all pull requests.

The DCO does not transfer copyright. You retain ownership of your contribution. It simply certifies you have the right to submit it under the project's Apache 2.0 license.

## Ways to contribute

- **Attack rules**: Add new YAML rule files under `rules/a2a/` or `rules/mcp/`. This is the highest-value contribution and requires no Go knowledge.
- **Protocol support**: Extend coverage to new A2A/MCP transport variants or authentication schemes.
- **Bug reports**: Open an issue with reproduction steps. For security-relevant bugs in Batesian itself, follow [SECURITY.md](SECURITY.md) instead.
- **Documentation**: Improve docs, examples, or the project website.

## Development setup

```bash
git clone https://github.com/calvin-mcdowell/batesian
cd batesian
go mod tidy
go build ./...
go test ./...
```

## Pull request guidelines

- One logical change per PR
- Include tests for new functionality
- Run `go vet ./...` and `golangci-lint run` before submitting
- New attack rules must include at least one test fixture in `test/fixtures/`
- Sign off your commits: `git commit -s`
- Rule IDs must follow the format: `<protocol>-<attack-class>-<NNN>` (e.g., `a2a-push-ssrf-001`)

## Rule authoring guide

Every rule YAML file must include:

```yaml
id: <protocol>-<attack-class>-<NNN>   # e.g. a2a-push-ssrf-001
info:
  name: <human-readable name>
  author: <your GitHub handle>
  severity: critical | high | medium | low | info
  description: |
    <what does this test, and why does it matter?>
  references:
    - <URL to research paper, CVE, or spec section>
  tags:
    - <protocol: a2a or mcp>
    - <attack class>

attack:
  protocol: a2a | mcp
  type: <attack type identifier>
  # ... attack-specific fields

assert:
  - condition: <condition identifier>
    description: <what this finding means>
    severity: <severity if triggered>

remediation: |
  <how to fix this vulnerability>
```

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
