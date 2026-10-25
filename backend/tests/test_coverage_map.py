"""
Unit tests for RepoShield V3 — Security Coverage Map (Phase 1).
Validates all 9 coverage categories, accurate execution statuses, exclusion boundaries, and non-misleading metrics.
"""

import pytest
from app.core.coverage import build_comprehensive_coverage_map, COVERAGE_CATEGORIES
from app.models.scan import ScannerExecutionStatus
from app.models.finding import Finding, Severity, Category

def test_coverage_categories_completeness():
    expected_ids = {
        "secret_scanning",
        "git_history",
        "sast",
        "dependencies",
        "infrastructure",
        "api_contract",
        "container_image",
        "supply_chain",
        "custom_rules"
    }
    actual_ids = {c["id"] for c in COVERAGE_CATEGORIES}
    assert actual_ids == expected_ids
    assert len(COVERAGE_CATEGORIES) == 9

def test_build_comprehensive_coverage_map_statuses():
    raw_coverage = {
        "gitleaks": ScannerExecutionStatus(
            scanner_name="Gitleaks Engine",
            tool_version="v8.18.2",
            status="SUCCESS",
            duration_seconds=1.2,
            findings_count=2
        ),
        "semgrep": ScannerExecutionStatus(
            scanner_name="Semgrep AST",
            tool_version="1.60.0",
            status="SUCCESS",
            duration_seconds=2.4,
            findings_count=1
        ),
        "osv": ScannerExecutionStatus(
            scanner_name="OSV Scanner",
            tool_version="v1",
            status="SUCCESS",
            duration_seconds=0.8,
            findings_count=3
        ),
        "infrastructure": ScannerExecutionStatus(
            scanner_name="IaC Scanner",
            tool_version="v2",
            status="SUCCESS",
            duration_seconds=0.5,
            findings_count=0
        )
    }

    findings = [
        Finding(
            id="f1",
            title="Exposed Token",
            description="Secret in code",
            category=Category.SECRETS,
            severity=Severity.HIGH,
            file_path="config.py",
            detector_name="Gitleaks Engine",
            rule_id="gitleaks:aws",
            remediation="Rotate key"
        ),
        Finding(
            id="f2",
            title="Historical Leak",
            description="Leaked in commit",
            category=Category.SECRETS,
            severity=Severity.HIGH,
            file_path="src/app.py",
            detector_name="Gitleaks Engine",
            rule_id="gitleaks:slack",
            remediation="Rotate token",
            is_historical=True
        )
    ]

    coverage_map = build_comprehensive_coverage_map(
        target_dir=".",
        raw_coverage=raw_coverage,
        findings=findings,
        total_files_analyzed=45,
        total_files_excluded=12,
        exclusion_reasons=["Excluded node_modules vendor files"]
    )

    # 1. Total 9 categories present
    assert len(coverage_map) == 9

    # 2. Secret scanning status
    assert coverage_map["secret_scanning"].status == "Completed"
    assert coverage_map["secret_scanning"].findings_count == 1  # only non-historical
    assert coverage_map["secret_scanning"].files_analyzed_count == 45
    assert coverage_map["secret_scanning"].files_excluded_count == 12

    # 3. Git history scanning status
    assert coverage_map["git_history"].status == "Completed"
    assert coverage_map["git_history"].findings_count == 1  # historical leak

    # 4. SAST status
    assert coverage_map["sast"].status == "Completed"

    # 5. Container Image status (realistically unsupported without Docker daemon)
    assert coverage_map["container_image"].status == "Unsupported"
    assert len(coverage_map["container_image"].warnings) > 0

    # 6. Custom rules status (not configured in repo)
    assert coverage_map["custom_rules"].status == "Not run"
