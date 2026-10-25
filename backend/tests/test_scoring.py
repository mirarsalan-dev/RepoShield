from app.core.scoring import calculate_risk_score
from app.models.finding import Finding, Severity, Category

def test_empty_findings_risk_score():
    score = calculate_risk_score([])
    assert score.score == 0.0
    assert score.level == "SECURE"
    assert score.total_findings == 0

def test_critical_secret_escalation():
    critical_finding = Finding(
        id="test-1",
        title="Exposed AWS Access Key",
        description="Leaked cloud credentials",
        category=Category.SECRETS,
        severity=Severity.CRITICAL,
        file_path=".env",
        detector_name="Gitleaks",
        rule_id="gitleaks:aws-access-token",
        remediation="Revoke key immediately"
    )
    score = calculate_risk_score([critical_finding])
    assert score.critical_count == 1
    assert score.level == "CRITICAL"
    assert score.score >= 75.0 # Verified override for critical secrets

def test_low_findings_score():
    low_finding = Finding(
        id="test-2",
        title="Weak Hash Function",
        description="MD5 in use",
        category=Category.SAST,
        severity=Severity.LOW,
        file_path="crypto.py",
        detector_name="Semgrep",
        rule_id="semgrep:python.lang.security.insecure-hash-md5",
        remediation="Use SHA-256"
    )
    score = calculate_risk_score([low_finding])
    assert score.level == "LOW"
    assert score.score < 25.0
