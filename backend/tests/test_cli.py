"""
Unit tests for RepoShield CLI & Report Generators.
"""
import json
import pytest
from app.models.finding import Finding, Severity, Category
from app.models.scan import ScanResult, ScanState
from app.utils.html_generator import generate_html_report
from app.cli import format_scan_output, handle_report_command, scan_local_or_remote

def test_html_report_generation():
    scan = ScanResult(
        scan_id="test-html-scan",
        repo_url="https://github.com/example/test-repo",
        owner="example",
        repo="test-repo",
        branch="main",
        status=ScanState.COMPLETED,
        started_at="2026-10-25T10:00:00Z",
        findings=[
            Finding(
                id="f-sec-1",
                fingerprint="fp-sec-1",
                title="Exposed AWS Access Key",
                description="Hardcoded credential in config",
                category=Category.SECRETS,
                severity=Severity.CRITICAL,
                file_path="config.py",
                detector_name="Gitleaks Engine",
                rule_id="gitleaks:aws-access-token",
                evidence="AKIA1234567890ABCDEF",
                remediation="Revoke credential immediately"
            )
        ]
    )
    html_out = generate_html_report(scan)
    assert "<!DOCTYPE html>" in html_out
    assert "RepoShield Security Intelligence Report" in html_out
    assert "test-repo" in html_out
    assert "CRITICAL" in html_out
    # Credential evidence must be redacted
    assert "AKIA" in html_out or "[REDACTED" in html_out

def test_cli_report_file_parsing(tmp_path):
    report_file = tmp_path / "scan_report.json"
    scan = ScanResult(
        scan_id="test-cli-1",
        repo_url="https://github.com/acme/project",
        owner="acme",
        repo="project",
        branch="main",
        status=ScanState.COMPLETED,
        started_at="2026-10-25T10:00:00Z",
        findings=[]
    )
    report_file.write_text(scan.model_dump_json())

    exit_code = handle_report_command(str(report_file), out_format="json")
    assert exit_code == 0

@pytest.mark.anyio
async def test_cli_scan_clean_directory(tmp_path):
    # Empty temporary directory
    exit_code = await scan_local_or_remote(str(tmp_path), fail_on="high", out_format="table")
    assert exit_code == 0
