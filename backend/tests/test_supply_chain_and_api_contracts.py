import pytest
from app.models.finding import Finding, Severity, Category, Confidence
from app.models.scan import ScanResult, ScanState
from app.services.supply_chain_service import analyze_supply_chain
from app.scanners.api_security_scanner import ApiSecurityScanner, normalize_path

def test_supply_chain_analysis_deductions_and_provenance():
    wf_unpinned = Finding(
        id="f-wf-1",
        fingerprint="fp-wf-1",
        title="Unpinned Third-Party Action @main",
        description="Workflow uses mutable branch ref",
        category=Category.INFRASTRUCTURE,
        severity=Severity.MEDIUM,
        file_path=".github/workflows/ci.yml",
        line_start=15,
        detector_name="ConfigSecurity",
        rule_id="github-actions.security.unpinned-action",
        remediation="Pin to immutable SHA"
    )

    wf_perms = Finding(
        id="f-wf-2",
        fingerprint="fp-wf-2",
        title="Overly Broad GITHUB_TOKEN (write-all)",
        description="Workflow grants write-all scopes",
        category=Category.INFRASTRUCTURE,
        severity=Severity.HIGH,
        file_path=".github/workflows/deploy.yml",
        line_start=8,
        detector_name="ConfigSecurity",
        rule_id="github-actions.security.write-all-permissions",
        remediation="Declare explicit scopes"
    )

    scan = ScanResult(
        scan_id="test-scan-supply-chain",
        repo_url="https://github.com/acme/project",
        owner="acme",
        repo="project",
        branch="main",
        status=ScanState.COMPLETED,
        findings=[wf_unpinned, wf_perms],
        started_at="2026-03-01T10:00:00Z"
    )

    report = analyze_supply_chain(scan)

    assert report.total_workflow_issues == 2
    assert report.unpinned_actions_count == 1
    assert report.excessive_permissions_count == 1
    assert report.score < 100
    assert report.provenance_status == "MISSING_MATERIAL"

    # Verify provenance checks separate missing material from failed
    slsa_check = next(p for p in report.provenance_checks if "SLSA" in p.name)
    assert slsa_check.status == "MISSING_MATERIAL"
    assert "actions/attest-build-provenance" in slsa_check.evidence

def test_api_route_normalization():
    p1 = "/api/v1/users/{id}"
    p2 = "/api/v1/users/:id"
    p3 = "/api/v1/users/{user_id}/"

    assert normalize_path(p1) == "/api/v1/users/{param}"
    assert normalize_path(p2) == "/api/v1/users/{param}"
    assert normalize_path(p3) == "/api/v1/users/{param}"

@pytest.mark.asyncio
async def test_api_security_scanner_spec_analysis():
    scanner = ApiSecurityScanner()
    mock_spec = {
        "openapi": "3.0.0",
        "servers": [{"url": "http://api.example.com"}],
        "paths": {
            "/api/v1/admin/delete": {
                "delete": {
                    "summary": "Delete account",
                    "security": []
                }
            },
            "/api/v1/users": {
                "post": {
                    "summary": "Create user",
                    "requestBody": {} # Missing content schema
                },
                "get": {
                    "summary": "Get user",
                    "responses": {
                        "200": {
                            "description": "User details",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "properties": {
                                            "password_hash": {"type": "string"},
                                            "email": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    endpoints, findings = scanner._analyze_openapi_spec(mock_spec, "openapi.json")

    assert len(endpoints) == 3
    # Check insecure cleartext server warning
    assert any("insecure-server-url" in f.rule_id for f in findings)
    # Check missing auth on sensitive admin route
    assert any("missing-auth" in f.rule_id for f in findings)
    # Check missing input validation on POST
    assert any("missing-input-validation" in f.rule_id for f in findings)
    # Check excessive data exposure for password_hash
    assert any("excessive-data-exposure" in f.rule_id for f in findings)
