import pytest
from app.models.finding import Finding, Severity, Category, Confidence
from app.models.scan import ScanResult, ScanState
from app.services.timeline_service import extract_timeline_events

def test_timeline_extraction_with_git_history_and_advisories():
    finding_hist = Finding(
        id="f-hist-1",
        fingerprint="fp-hist-1",
        title="Hardcoded AWS Secret Access Key in Git History",
        description="Historical commit contains exposed credential",
        category=Category.SECRETS,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        file_path="src/config/aws.py",
        detector_name="Gitleaks Git History",
        rule_id="gitleaks:aws-access-token",
        remediation="Revoke exposed key and purge commit with git-filter-repo",
        is_historical=True,
        commit_sha="a1b2c3d4e5f6a1b2",
        commit_author="Dev Author",
        commit_date="2026-01-10T14:22:00Z"
    )

    finding_dep = Finding(
        id="f-dep-1",
        fingerprint="fp-dep-1",
        title="Prototype Pollution in lodash",
        description="Vulnerable lodash version",
        category=Category.DEPENDENCIES,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path="package.json",
        detector_name="Google OSV",
        rule_id="GHSA-p6mc-m468-83gw",
        cve_id="CVE-2019-10744",
        remediation="Bump lodash to 4.17.21",
        package_name="lodash",
        installed_version="4.17.11",
        fixed_version="4.17.21"
    )

    scan = ScanResult(
        scan_id="test-scan-timeline-01",
        repo_url="https://github.com/acme/api",
        owner="acme",
        repo="api",
        branch="main",
        commit_sha="c9d8e7f6a5b4",
        commit_author="Main Author",
        status=ScanState.COMPLETED,
        findings=[finding_hist, finding_dep],
        started_at="2026-03-01T09:55:00Z",
        created_at="2026-03-01T10:00:00Z"
    )

    review_annotations = {
        "fp-dep-1": {
            "finding_id": "f-dep-1",
            "status": "FIX_REQUIRED",
            "remediation_decision": "PLANNED_SPRINT",
            "reviewer": "Security Lead",
            "reviewed_at": "2026-03-02T11:00:00Z",
            "investigation_notes": "Assigned to Sprint 42",
            "verification_status": "UNVERIFIED"
        }
    }

    events = extract_timeline_events(scan, review_annotations=review_annotations)

    assert len(events) >= 4

    event_types = [e["event_type"] for e in events]
    assert "CODE_INTRODUCTION" in event_types
    assert "ADVISORY_PUBLISHED" in event_types
    assert "FIRST_RECORDED_DETECTION" in event_types
    assert "TRIAGE_REVIEWED" in event_types

    # Verify historical finding has high confidence from commit sha
    hist_intro = next(e for e in events if e["event_type"] == "CODE_INTRODUCTION" and e["finding_id"] == "f-hist-1")
    assert hist_intro["confidence"] == "HIGH"
    assert hist_intro["commit_sha"] == "a1b2c3d4e5f6a1b2"
    assert hist_intro["is_gap_or_uncertain"] is False

    # Verify triage event has review metadata
    triage_ev = next(e for e in events if e["event_type"] == "TRIAGE_REVIEWED")
    assert "Sprint 42" in triage_ev["description"]
    assert "Security Lead" in triage_ev["description"]

def test_timeline_sorting_order():
    f1 = Finding(
        id="f1",
        fingerprint="fp1",
        title="Test Insecure Evaluator",
        description="Test eval finding",
        category=Category.SAST,
        severity=Severity.MEDIUM,
        file_path="app/main.py",
        detector_name="Semgrep",
        rule_id="semgrep:eval",
        remediation="Use literal_eval"
    )

    scan = ScanResult(
        scan_id="test-scan-sorting",
        repo_url="https://github.com/acme/app",
        owner="acme",
        repo="app",
        branch="main",
        status=ScanState.COMPLETED,
        findings=[f1],
        started_at="2026-05-10T11:55:00Z",
        created_at="2026-05-10T12:00:00Z"
    )

    events = extract_timeline_events(scan)
    assert len(events) >= 1
    # Verify newest first or valid dates
    for i in range(len(events) - 1):
        assert events[i]["timestamp"] >= events[i+1]["timestamp"]
