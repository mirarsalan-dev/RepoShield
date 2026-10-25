import json
import pytest
from app.models.finding import Finding, Severity, Category
from app.models.scan import ScanResult, ScanState
from app.utils.sarif_generator import generate_sarif_report

def test_sarif_report_valid_structure():
    scan = ScanResult(
        scan_id="test-123",
        repo_url="https://github.com/org/repo",
        owner="org",
        repo="repo",
        branch="main",
        commit_sha="a1b2c3d",
        status=ScanState.COMPLETED,
        started_at="2026-10-24T12:00:00Z",
        completed_at="2026-10-24T12:00:10Z",
        findings=[
            Finding(
                id="f-1",
                fingerprint="fp123",
                title="Command Injection in exec()",
                description="Unsanitized user input passed to exec()",
                category=Category.SAST,
                severity=Severity.CRITICAL,
                file_path="src/server.js",
                line_start=42,
                detector_name="Semgrep",
                rule_id="javascript.lang.security.exec",
                remediation="Use execFile instead"
            )
        ]
    )

    sarif_str = generate_sarif_report(scan)
    data = json.loads(sarif_str)

    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "RepoShield"
    assert len(run["results"]) == 1
    res = run["results"][0]
    assert res["ruleId"] == "javascript.lang.security.exec"
    assert res["level"] == "error"
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/server.js"
