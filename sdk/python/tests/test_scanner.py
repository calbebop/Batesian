"""Tests for batesian._scanner.Scanner.

The binary is never actually invoked in these tests. Instead, subprocess.run
is monkeypatched to return controlled JSON output, isolating the SDK logic
from the Go binary.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from batesian._models import Results, ScanError
from batesian._scanner import Scanner
from batesian._binary import BinaryNotFoundError


MOCK_FINDINGS = [
    {
        "rule_id": "a2a-push-ssrf-001",
        "rule_name": "A2A Push Notification SSRF",
        "severity": "high",
        "confidence": "confirmed",
        "title": "Server made outbound request",
        "description": "OOB callback received.",
        "evidence": "HTTP GET from 1.2.3.4",
        "remediation": "Validate callback URLs.",
        "target_url": "https://agent.example.com",
    }
]

MOCK_JSON_OUTPUT = json.dumps(
    {
        "target": "https://agent.example.com",
        "findings": MOCK_FINDINGS,
        "rules_run": 1,
        "duration_ms": 500,
    }
)


def _mock_proc(stdout: str = MOCK_JSON_OUTPUT, returncode: int = 0, stderr: str = "") -> MagicMock:
    mock = MagicMock()
    mock.stdout = stdout
    mock.stderr = stderr
    mock.returncode = returncode
    return mock


@pytest.fixture
def scanner():
    with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
        return Scanner(target="https://agent.example.com", timeout=10)


class TestScannerRun:
    def test_returns_results_with_findings(self, scanner):
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            results = scanner.run()
        assert isinstance(results, Results)
        assert len(results.findings) == 1
        assert results.findings[0].rule_id == "a2a-push-ssrf-001"
        assert results.high_count == 1
        assert results.critical_count == 0

    def test_passes_target_to_cli(self, scanner):
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            scanner.run()
        cmd = mock_run.call_args[0][0]
        assert "--target" in cmd
        assert "https://agent.example.com" in cmd

    def test_uses_json_output_format(self, scanner):
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            scanner.run()
        cmd = mock_run.call_args[0][0]
        assert "--output" in cmd
        assert "json" in cmd

    def test_passes_rule_ids(self, scanner):
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            scanner.run(rules=["a2a-push-ssrf-001", "mcp-tool-poison-001"])
        cmd = mock_run.call_args[0][0]
        assert "--rule-ids" in cmd
        assert "a2a-push-ssrf-001,mcp-tool-poison-001" in cmd

    def test_passes_protocol(self, scanner):
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            scanner.run(protocol="mcp")
        cmd = mock_run.call_args[0][0]
        assert "--protocol" in cmd
        assert "mcp" in cmd

    def test_passes_severities(self, scanner):
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            scanner.run(severities=["critical", "high"])
        cmd = mock_run.call_args[0][0]
        assert "--severity" in cmd
        assert "critical,high" in cmd

    def test_passes_oob_flag(self, scanner):
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            scanner.run(oob=True)
        cmd = mock_run.call_args[0][0]
        assert "--oob" in cmd

    def test_oob_url_overrides_oob_flag(self, scanner):
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            scanner.run(oob=True, oob_url="https://oob.example.com/tok")
        cmd = mock_run.call_args[0][0]
        assert "--oob-url" in cmd
        assert "--oob" not in cmd

    def test_raises_scan_error_on_empty_output(self, scanner):
        with patch("subprocess.run", return_value=_mock_proc(stdout="")):
            with pytest.raises(ScanError, match="no output"):
                scanner.run()

    def test_raises_scan_error_on_invalid_json(self, scanner):
        with patch("subprocess.run", return_value=_mock_proc(stdout="not json")):
            with pytest.raises(ScanError, match="parse"):
                scanner.run()

    def test_raises_scan_error_on_timeout(self, scanner):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="batesian", timeout=10)):
            with pytest.raises(ScanError, match="timed out"):
                scanner.run()

    def test_zero_findings_is_valid(self, scanner):
        empty_output = json.dumps({"target": "https://x.com", "findings": [], "rules_run": 5, "duration_ms": 100})
        with patch("subprocess.run", return_value=_mock_proc(stdout=empty_output)):
            results = scanner.run()
        assert results.critical_count == 0
        assert results.findings == []

    def test_token_passed_to_cli(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(target="https://x.com", token="secret-token")
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            s.run()
        cmd = mock_run.call_args[0][0]
        assert "--token" in cmd
        assert "secret-token" in cmd

    def test_oauth_flags_passed(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(
                target="https://x.com",
                token_url="https://auth.example.com/token",
                client_id="my-client",
                client_secret="my-secret",
                oauth_scopes=["read", "write"],
            )
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            s.run()
        cmd = mock_run.call_args[0][0]
        assert "--token-url" in cmd
        assert "--client-id" in cmd
        assert "--client-secret" in cmd
        assert "--oauth-scopes" in cmd
        assert "read,write" in cmd


class TestScannerBuildCommand:
    def test_skip_tls_flag(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(target="https://x.com", skip_tls=True)
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            s.run()
        cmd = mock_run.call_args[0][0]
        assert "--skip-tls" in cmd

    def test_config_file_passed(self):
        with patch("batesian._scanner.find_binary", return_value="/fake/batesian"):
            s = Scanner(target="https://x.com", config="/path/to/batesian.yaml")
        with patch("subprocess.run", return_value=_mock_proc()) as mock_run:
            s.run()
        cmd = mock_run.call_args[0][0]
        assert "--config" in cmd
        assert "/path/to/batesian.yaml" in cmd
