import pytest
from app.models.finding import Finding, Severity, Category, FindingStatus
from app.models.policy import SecurityPolicy, PolicySuppression
from app.api.policy import evaluate_policy_against_findings

def test_policy_passes_clean_findings():
    policy = SecurityPolicy()
    findings = []
    result = evaluate_policy_against_findings(policy, findings)
    assert result.passed is True
    assert len(result.violations) == 0

def test_policy_fails_on_critical_finding():
    policy = SecurityPolicy(fail_on_critical=True)
    findings = [
        Finding(
            id="f-1",
            title="Exposed AWS Key",
            description="Leaked AWS key",
            category=Category.SECRETS,
            severity=Severity.CRITICAL,
            file_path="config.py",
            detector_name="Gitleaks",
            rule_id="aws-key",
            remediation="Revoke key"
        )
    ]
    result = evaluate_policy_against_findings(policy, findings)
    assert result.passed is False
    assert len(result.violations) >= 1
    assert any("Critical finding detected" in v or "Exposed secret" in v for v in result.violations)

def test_policy_suppression_with_valid_reason():
    policy = SecurityPolicy(
        fail_on_critical=True,
        require_suppression_reason=True,
        suppressions=[
            PolicySuppression(rule_id="aws-key", reason="Test mock secret used in unit tests only")
        ]
    )
    findings = [
        Finding(
            id="f-1",
            title="Exposed AWS Key",
            description="Leaked AWS key",
            category=Category.SECRETS,
            severity=Severity.CRITICAL,
            file_path="tests/mock.py",
            detector_name="Gitleaks",
            rule_id="aws-key",
            status=FindingStatus.SUPPRESSED,
            suppression_reason="Test mock secret used in unit tests only",
            remediation="Revoke key"
        )
    ]
    result = evaluate_policy_against_findings(policy, findings)
    assert result.passed is True
    assert result.suppressed_count == 1
