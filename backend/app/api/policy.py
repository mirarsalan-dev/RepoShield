from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter
from pydantic import BaseModel, Field
from app.models.finding import Finding, Severity, Category, FindingStatus
from app.models.policy import SecurityPolicy, PolicyEvaluationResult
from app.models.scan import ScanResult

router = APIRouter(prefix="/api/policy", tags=["Policies & PR Checks"])

SEVERITY_WEIGHT = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
    Severity.UNKNOWN: 0
}

class PRCheckRequest(BaseModel):
    base_scan: ScanResult
    head_scan: ScanResult
    policy: Optional[SecurityPolicy] = None

class PRCheckResult(BaseModel):
    passed: bool
    status: str # "PASSED", "FAILED"
    base_repo: str
    base_branch: str
    head_repo: str
    head_branch: str
    new_findings: list[Finding]
    resolved_findings: list[Finding]
    recurring_findings: list[Finding]
    unchanged_findings: list[Finding] = Field(default_factory=list)
    severity_increased: list[Finding]
    severity_decreased: list[Finding]
    policy_evaluation: PolicyEvaluationResult
    policy_result: Optional[PolicyEvaluationResult] = None
    summary: str

def evaluate_policy_against_findings(policy: SecurityPolicy, findings: list[Finding]) -> PolicyEvaluationResult:
    now_iso = datetime.now(timezone.utc).isoformat()
    violations = []
    warnings = []

    suppression_rules = {s.rule_id: s for s in policy.suppressions}

    critical_count = 0
    high_count = 0
    secrets_count = 0
    dependencies_count = 0
    suppressed_count = 0

    max_allowed_weight = SEVERITY_WEIGHT.get(policy.max_permitted_severity, 3)

    for f in findings:
        # Check explicit suppressions
        is_suppressed = f.status == FindingStatus.SUPPRESSED or f.rule_id in suppression_rules
        if is_suppressed:
            suppressed_count += 1
            if policy.require_suppression_reason:
                sup_reason = f.suppression_reason or (suppression_rules.get(f.rule_id).reason if f.rule_id in suppression_rules else "")
                if not sup_reason or len(sup_reason.strip()) < 5:
                    violations.append(f"Finding '{f.title}' is suppressed without a required documented justification.")
            continue

        if f.severity == Severity.CRITICAL:
            critical_count += 1
            if policy.fail_on_critical:
                violations.append(f"Critical finding detected: [{f.rule_id}] {f.title} ({f.file_path})")
        elif f.severity == Severity.HIGH:
            high_count += 1
            if policy.fail_on_high:
                violations.append(f"High finding detected: [{f.rule_id}] {f.title} ({f.file_path})")

        # Category checks
        if f.category == Category.SECRETS:
            secrets_count += 1
            if policy.fail_on_secrets:
                violations.append(f"Exposed secret forbidden by policy: [{f.rule_id}] in {f.file_path}")

        if f.category == Category.DEPENDENCIES:
            dependencies_count += 1
            if policy.warn_on_dependencies:
                warnings.append(f"Vulnerable dependency flagged: {f.package_name or f.title} ({f.installed_version or ''})")

        # Max permitted severity threshold
        f_weight = SEVERITY_WEIGHT.get(f.severity, 0)
        if f_weight > max_allowed_weight:
            violations.append(f"Finding severity {f.severity.value} exceeds maximum permitted threshold ({policy.max_permitted_severity.value}): {f.title}")

    passed = len(violations) == 0
    if passed:
        summary = f"All {len(findings)} findings comply with policy '{policy.name}' ({suppressed_count} suppressed)."
    else:
        summary = f"Policy '{policy.name}' failed with {len(violations)} violation(s)."

    return PolicyEvaluationResult(
        passed=passed,
        policy_name=policy.name,
        violations=violations,
        warnings=warnings,
        critical_count=critical_count,
        high_count=high_count,
        secrets_count=secrets_count,
        dependencies_count=dependencies_count,
        suppressed_count=suppressed_count,
        evaluated_at=now_iso,
        summary=summary
    )

@router.post("/evaluate", response_model=PolicyEvaluationResult)
async def evaluate_policy_endpoint(payload: dict):
    """
    Evaluates a SecurityPolicy against a ScanResult.
    """
    policy_data = payload.get("policy", {})
    policy = SecurityPolicy(**policy_data) if policy_data else SecurityPolicy()
    
    scan_data = payload.get("scan", {})
    findings = [Finding(**f) for f in scan_data.get("findings", [])]

    return evaluate_policy_against_findings(policy, findings)

@router.post("/pr-check", response_model=PRCheckResult)
async def evaluate_pr_check(payload: PRCheckRequest):
    """
    Compares proposed head scan against base scan and evaluates Pull Request security gate.
    """
    policy = payload.policy or SecurityPolicy()
    base_findings = payload.base_scan.findings
    head_findings = payload.head_scan.findings

    base_map = {f.fingerprint: f for f in base_findings if f.fingerprint}
    head_map = {f.fingerprint: f for f in head_findings if f.fingerprint}

    new_findings = []
    recurring_findings = []
    severity_increased = []
    severity_decreased = []

    for fp, h_find in head_map.items():
        if fp not in base_map:
            new_findings.append(h_find)
        else:
            b_find = base_map[fp]
            recurring_findings.append(h_find)
            h_weight = SEVERITY_WEIGHT.get(h_find.severity, 0)
            b_weight = SEVERITY_WEIGHT.get(b_find.severity, 0)
            if h_weight > b_weight:
                severity_increased.append(h_find)
            elif h_weight < b_weight:
                severity_decreased.append(h_find)

    # Resolved findings: present in base but missing in head
    resolved_findings = [b for fp, b in base_map.items() if fp not in head_map]

    # Evaluate policy against newly introduced findings
    eval_result = evaluate_policy_against_findings(policy, new_findings)

    status = "PASSED" if eval_result.passed else "FAILED"
    summary = (
        f"PR Gate {status}: {len(new_findings)} new finding(s) introduced, "
        f"{len(resolved_findings)} finding(s) resolved. Policy violations: {len(eval_result.violations)}."
    )

    return PRCheckResult(
        passed=eval_result.passed,
        status=status,
        base_repo=payload.base_scan.repo,
        base_branch=payload.base_scan.branch,
        head_repo=payload.head_scan.repo,
        head_branch=payload.head_scan.branch,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        recurring_findings=recurring_findings,
        unchanged_findings=recurring_findings,
        severity_increased=severity_increased,
        severity_decreased=severity_decreased,
        policy_evaluation=eval_result,
        policy_result=eval_result,
        summary=summary
    )
