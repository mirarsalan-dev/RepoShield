import pytest
from app.models.finding import Finding, Severity, Category, Confidence
from app.models.scan import ScanResult, ScanState
from app.services.container_inspector_service import inspect_container_security
from app.services.compliance_service import generate_compliance_evidence

def test_container_inspector_root_user_and_ports():
    root_finding = Finding(
        id="f-container-root",
        fingerprint="fp-container-root",
        title="Container Running as Root",
        description="Container image explicitly sets USER to root",
        category=Category.INFRASTRUCTURE,
        severity=Severity.HIGH,
        file_path="Dockerfile",
        line_start=12,
        detector_name="ConfigSecurity",
        rule_id="dockerfile.security.root-user",
        evidence="USER root\nEXPOSE 22 8080\nFROM python:3.11-slim",
        remediation="Declare USER nonroot"
    )

    scan = ScanResult(
        scan_id="test-scan-container",
        repo_url="https://github.com/acme/project",
        owner="acme",
        repo="project",
        branch="main",
        status=ScanState.COMPLETED,
        findings=[root_finding],
        started_at="2026-03-01T10:00:00Z"
    )

    report = inspect_container_security(scan)

    assert report.dockerfiles_found >= 1
    assert report.runs_as_root is True
    assert any(risk.instruction == "USER" for risk in report.layer_risks)
    assert report.base_image is not None
    assert "Static container configuration analysis only" in report.safety_disclosure
    assert len(report.unsupported_checks) >= 2

    # Verify sensitive port 22 flagged as HIGH_RISK
    ssh_port = next((p for p in report.exposed_ports if p.port == 22), None)
    assert ssh_port is not None
    assert ssh_port.risk_level == "HIGH_RISK"

def test_compliance_evidence_pack_generation():
    secret_finding = Finding(
        id="f-sec-1",
        fingerprint="fp-sec-1",
        title="Exposed AWS Secret Key",
        description="AWS API secret token in settings.py",
        category=Category.SECRETS,
        severity=Severity.CRITICAL,
        file_path="settings.py",
        detector_name="Gitleaks",
        rule_id="gitleaks.aws-key",
        remediation="Revoke credential"
    )

    dep_finding = Finding(
        id="f-dep-1",
        fingerprint="fp-dep-1",
        title="Remote Code Execution in Jackson Databind",
        description="CVE-2020-8840 deserialization vulnerability",
        category=Category.DEPENDENCIES,
        severity=Severity.HIGH,
        file_path="pom.xml",
        detector_name="OSV",
        rule_id="GHSA-87jh-4jh2",
        remediation="Upgrade Jackson to 2.9.10.3"
    )

    scan = ScanResult(
        scan_id="test-scan-compliance",
        repo_url="https://github.com/acme/project",
        owner="acme",
        repo="project",
        branch="main",
        status=ScanState.COMPLETED,
        findings=[secret_finding, dep_finding],
        started_at="2026-03-01T10:00:00Z"
    )

    report = generate_compliance_evidence(scan)

    assert report.total_controls >= 5
    assert report.failing_controls_count >= 2
    assert "OWASP ASVS v4.0" in report.frameworks
    assert "NIST SSDF SP 800-218" in report.frameworks
    assert "IMPORTANT LEGAL & AUDIT NOTICE" in report.disclaimer

    # ASVS Secrets control must be failing
    asvs_secrets = next(c for c in report.controls if c.control_id == "ASVS-14.4.1")
    assert asvs_secrets.status == "FAIL_DETECTED_FLAWS"
    assert asvs_secrets.finding_count == 1
    assert "Scanner validates pattern and entropy heuristics" in asvs_secrets.limitations_note

    # ASVS Dependencies control must be failing
    asvs_deps = next(c for c in report.controls if c.control_id == "ASVS-14.2.1")
    assert asvs_deps.status == "FAIL_DETECTED_FLAWS"
    assert asvs_deps.finding_count == 1
