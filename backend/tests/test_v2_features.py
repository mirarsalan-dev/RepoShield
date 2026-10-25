"""
Unit & Integration tests for RepoShield V2 features:
- Fix Validation Lab
- Risk Intelligence Engine (CISA KEV, EPSS, Exploitability)
- Attack Path Visualizer Engine
- Repository Security Posture Scanner
- CycloneDX VEX Generator
- Anti-SSRF and Website Security Destination Validation
"""
import pytest
from app.models.finding import Finding, Severity, Category, Confidence
from app.models.scan import ScanResult, ScanState
from app.core.risk_intelligence import evaluate_finding_risk, enrich_findings_with_risk_intelligence, CISA_KEV_CATALOG
from app.services.fix_validation_service import fix_validation_service, FixValidationRequest, FixValidationStatus
from app.services.attack_path_service import attack_path_service
from app.scanners.posture_scanner import RepositoryPostureScanner, PostureCheckStatus
from app.utils.vex_generator import generate_cyclonedx_vex
from app.api.website_security import validate_public_destination
from fastapi import HTTPException

def test_risk_intelligence_cisa_kev():
    finding = Finding(
        id="test-log4shell",
        title="Apache Log4j RCE",
        description="Remote code execution in Log4j",
        category=Category.DEPENDENCIES,
        severity=Severity.CRITICAL,
        file_path="pom.xml",
        detector_name="OSV API",
        rule_id="GHSA-jfh8-c2jp-5v3q",
        remediation="Upgrade log4j to 2.17.1",
        cve_id="CVE-2021-44228",
        cvss_score=10.0
    )
    prio, rationale, epss, pctl, is_kev = evaluate_finding_risk(finding)
    assert prio == "P1 - Immediate"
    assert is_kev is True
    assert "CISA Known Exploited Vulnerabilities" in rationale
    assert epss is not None and epss > 0.9

def test_risk_intelligence_active_secret():
    finding = Finding(
        id="test-aws-secret",
        title="Exposed AWS Secret Key",
        description="AWS Secret Key exposed in code",
        category=Category.SECRETS,
        severity=Severity.CRITICAL,
        file_path="config.py",
        detector_name="Gitleaks Engine",
        rule_id="gitleaks:aws-secret-key",
        remediation="Revoke AWS key immediately",
        is_historical=False,
        remains_in_head=True
    )
    prio, rationale, epss, pctl, is_kev = evaluate_finding_risk(finding)
    assert prio == "P1 - Immediate"
    assert "Active unredacted cloud or production credential" in rationale

def test_attack_path_service_links_secrets_to_assets():
    sec_finding = Finding(
        id="sec-1",
        fingerprint="fp1",
        title="Exposed Secret: AWS Access Key ID",
        description="AWS key leak",
        category=Category.SECRETS,
        severity=Severity.CRITICAL,
        file_path="backend/deploy.py",
        detector_name="Gitleaks Engine",
        rule_id="gitleaks:aws-access-token",
        evidence="AKIAIOSFODNN7EXAMPLE",
        remediation="Revoke key",
        attack_path_node_type="CREDENTIAL_EXPOSURE"
    )
    graph = attack_path_service.generate_attack_paths([sec_finding])
    assert graph.total_paths == 1
    assert len(graph.chains) == 1
    assert len(graph.nodes) == 2
    assert graph.nodes[0].node_type == "CREDENTIAL_EXPOSURE"
    assert graph.nodes[1].node_type == "SENSITIVE_ASSET"
    assert len(graph.choke_points) == 1

@pytest.mark.anyio
async def test_fix_validation_resolved(tmp_path):
    orig_code = 'const apiKey = "AKIA1234567890ABCDEF";\nrun();'
    remed_code = 'const apiKey = process.env.API_KEY;\nrun();'

    finding = Finding(
        id="f1",
        fingerprint="fp_fixval",
        title="Exposed AWS Access Key ID",
        description="AWS key in source",
        category=Category.SECRETS,
        severity=Severity.CRITICAL,
        file_path="client.js",
        detector_name="Gitleaks Engine",
        rule_id="gitleaks:aws-access-token",
        remediation="Use process.env"
    )

    req = FixValidationRequest(
        finding=finding,
        original_code=orig_code,
        remediated_code=remed_code,
        file_path="client.js"
    )
    result = await fix_validation_service.validate_fix(req)
    assert result.status == FixValidationStatus.VERIFIED_RESOLVED
    assert "No changes detected." not in result.diff_unified

@pytest.mark.anyio
async def test_fix_validation_still_detected(tmp_path):
    orig_code = 'const apiKey = "AKIA1234567890ABCDEF";\nrun();'
    # Still has an AWS key
    remed_code = 'const apiKey = "AKIA9999999999ZZZZZZ";\nrun();'

    finding = Finding(
        id="f1",
        fingerprint="fp_fixval_still",
        title="Exposed AWS Access Key ID",
        description="AWS key in source",
        category=Category.SECRETS,
        severity=Severity.CRITICAL,
        file_path="client.js",
        detector_name="Gitleaks Engine",
        rule_id="gitleaks:aws-access-token",
        remediation="Use process.env"
    )

    req = FixValidationRequest(
        finding=finding,
        original_code=orig_code,
        remediated_code=remed_code,
        file_path="client.js"
    )
    result = await fix_validation_service.validate_fix(req)
    assert result.status == FixValidationStatus.STILL_DETECTED

def test_vex_generation():
    scan = ScanResult(
        scan_id="vex-scan-1",
        repo_url="https://github.com/acme/proj",
        owner="acme",
        repo="proj",
        branch="main",
        status=ScanState.COMPLETED,
        started_at="2026-10-25T00:00:00Z",
        findings=[
            Finding(
                id="f-log4j",
                title="Log4j RCE",
                description="RCE vulnerability",
                category=Category.DEPENDENCIES,
                severity=Severity.CRITICAL,
                file_path="pom.xml",
                package_name="org.apache.logging.log4j:log4j-core",
                installed_version="2.14.0",
                detector_name="OSV API",
                rule_id="CVE-2021-44228",
                remediation="Upgrade to 2.17.1",
                reachability_status="CONFIRMED"
            )
        ]
    )
    vex_json = generate_cyclonedx_vex(scan)
    assert "CycloneDX" in vex_json
    assert "CVE-2021-44228" in vex_json
    assert '"state": "affected"' in vex_json

def test_website_security_ssrf_blocking():
    # Loopback IP
    with pytest.raises(HTTPException) as exc_info:
        validate_public_destination("http://127.0.0.1:8080")
    assert exc_info.value.status_code == 400

    # Localhost
    with pytest.raises(HTTPException) as exc_info:
        validate_public_destination("http://localhost:3000")
    assert exc_info.value.status_code == 400

    # Cloud metadata
    with pytest.raises(HTTPException) as exc_info:
        validate_public_destination("http://169.254.169.254/latest/meta-data")
    assert exc_info.value.status_code == 400
