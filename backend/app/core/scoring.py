import math
from app.models.finding import Finding, Severity, Category, FindingStatus
from app.models.scan import RiskScore

def calculate_risk_score(findings: list[Finding]) -> RiskScore:
    """
    Computes transparent, deterministic security risk score.
    Uses transparent weighted index based on verified industry metrics.
    Excludes suppressed findings from active risk weighting.
    """
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    info_count = 0
    unknown_count = 0

    secrets_count = 0
    dependencies_count = 0
    sast_count = 0
    infrastructure_count = 0
    suppressed_count = 0
    reviewed_count = 0

    raw_weighted_sum = 0.0

    for f in findings:
        if f.status == FindingStatus.SUPPRESSED:
            suppressed_count += 1
            continue

        if f.status == FindingStatus.REVIEWED:
            reviewed_count += 1

        # Category breakdown
        if f.category == Category.SECRETS:
            secrets_count += 1
        elif f.category == Category.DEPENDENCIES:
            dependencies_count += 1
        elif f.category == Category.SAST:
            sast_count += 1
        elif f.category == Category.INFRASTRUCTURE:
            infrastructure_count += 1

        # Severity weighting
        if f.severity == Severity.CRITICAL:
            critical_count += 1
            raw_weighted_sum += 15.0
        elif f.severity == Severity.HIGH:
            high_count += 1
            raw_weighted_sum += 8.0
        elif f.severity == Severity.MEDIUM:
            medium_count += 1
            raw_weighted_sum += 4.0
        elif f.severity == Severity.LOW:
            low_count += 1
            raw_weighted_sum += 1.5
        elif f.severity == Severity.UNKNOWN:
            unknown_count += 1
            raw_weighted_sum += 3.0
        elif f.severity == Severity.INFO:
            info_count += 1
            raw_weighted_sum += 0.2

    active_count = len(findings) - suppressed_count

    if active_count == 0:
        score = 0.0
        level = "SECURE"
        summary = "No unsuppressed security findings detected in repository scan."
    else:
        # Logistic curve: 100 * (1 - e^(-sum / 35))
        score = round(100.0 * (1.0 - math.exp(-raw_weighted_sum / 35.0)), 1)
        
        # Hard override if ANY critical finding exists
        if critical_count > 0:
            score = max(score, 75.0)

        if score >= 75.0 or critical_count > 0:
            level = "CRITICAL"
            summary = f"Immediate action required: {critical_count} Critical and {high_count} High severity issues identified."
        elif score >= 50.0 or high_count > 0:
            level = "HIGH"
            summary = f"High security risk: {high_count} high-severity findings require remediation prior to production."
        elif score >= 25.0 or medium_count > 0:
            level = "MEDIUM"
            summary = f"Moderate security exposure: {medium_count} medium-severity findings detected."
        else:
            level = "LOW"
            summary = f"Low risk posture: {low_count + info_count} minor findings and code hygiene alerts detected."

    return RiskScore(
        score=score,
        level=level,
        summary=summary,
        formula_explanation="Transparent weighted heuristic: Critical=15pts, High=8pts, Medium=4pts, Low=1.5pts; normalized via continuous logistic curve (min 75 if Critical present).",
        total_findings=len(findings),
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        info_count=info_count,
        unknown_count=unknown_count,
        secrets_count=secrets_count,
        dependencies_count=dependencies_count,
        sast_count=sast_count,
        infrastructure_count=infrastructure_count,
        suppressed_count=suppressed_count,
        reviewed_count=reviewed_count,
        p1_count=sum(1 for f in findings if f.exploitability_priority and "P1" in f.exploitability_priority),
        p2_count=sum(1 for f in findings if f.exploitability_priority and "P2" in f.exploitability_priority),
        p3_count=sum(1 for f in findings if f.exploitability_priority and "P3" in f.exploitability_priority),
        p4_count=sum(1 for f in findings if f.exploitability_priority and "P4" in f.exploitability_priority),
        cisa_kev_count=sum(1 for f in findings if getattr(f, "cisa_kev", False)),
        historical_secrets_count=sum(1 for f in findings if getattr(f, "is_historical", False)),
    )
