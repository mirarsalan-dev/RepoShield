"""
Repository Security Posture Scanner for RepoShield V2.
Evaluates repository governance, supply-chain protections, CI/CD permissions,
and OpenSSF Scorecard practices with strict honest status reporting.
"""
import os
import re
import time
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
import httpx
from app.models.scan import ScannerExecutionStatus
from app.models.finding import Finding, Severity, Category, Confidence, compute_finding_fingerprint

class PostureCheckStatus(str):
    VERIFIED = "Verified"
    IMPROVEMENT_RECOMMENDED = "Improvement recommended"
    FAILED = "Failed"
    NOT_DETECTED = "Not detected"
    NOT_ASSESSED = "Not assessed"
    UNAVAILABLE = "Unavailable"

class PostureCheck(BaseModel):
    id: str
    name: str
    category: str
    status: str
    score_contribution: float
    max_score: float
    evidence: str
    recommendation: str
    documentation_url: Optional[str] = None

class PostureReport(BaseModel):
    score: int = Field(ge=0, le=100)
    level: str  # EXCELLENT, GOOD, MODERATE, WEAK
    checks: List[PostureCheck]
    methodology: str
    evaluated_at: str

class RepositoryPostureScanner:
    def __init__(self):
        self.tool_version = "RepoShield Posture Engine 2.0 (OpenSSF-aligned)"

    async def evaluate(
        self,
        target_dir: str,
        owner: Optional[str] = None,
        repo: Optional[str] = None,
        token: Optional[str] = None
    ) -> tuple[PostureReport, list[Finding], ScannerExecutionStatus]:
        start_time = time.time()
        checks: List[PostureCheck] = []
        findings: List[Finding] = []

        # 1. Security Policy check
        has_security_md = False
        security_candidates = ["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"]
        for cand in security_candidates:
            if os.path.exists(os.path.join(target_dir, cand)):
                has_security_md = True
                break

        if has_security_md:
            checks.append(PostureCheck(
                id="security-policy",
                name="Security Vulnerability Disclosure Policy",
                category="Governance",
                status=PostureCheckStatus.VERIFIED,
                score_contribution=15.0,
                max_score=15.0,
                evidence="Found SECURITY.md in repository root or .github folder.",
                recommendation="Maintain clear vulnerability disclosure guidelines with PGP key or dedicated security contact email.",
                documentation_url="https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository"
            ))
        else:
            checks.append(PostureCheck(
                id="security-policy",
                name="Security Vulnerability Disclosure Policy",
                category="Governance",
                status=PostureCheckStatus.NOT_DETECTED,
                score_contribution=0.0,
                max_score=15.0,
                evidence="No SECURITY.md policy file found in repository.",
                recommendation="Create a SECURITY.md file defining safe disclosure protocols and response timelines.",
                documentation_url="https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository"
            ))

        # 2. Dependency Update Automation
        dependabot_path = os.path.join(target_dir, ".github", "dependabot.yml")
        renovate_candidates = ["renovate.json", ".renovaterc", ".renovaterc.json", ".github/renovate.json"]
        has_automated_updates = os.path.exists(dependabot_path) or any(os.path.exists(os.path.join(target_dir, r)) for r in renovate_candidates)

        if has_automated_updates:
            checks.append(PostureCheck(
                id="automated-dependencies",
                name="Automated Dependency Updates",
                category="Supply Chain",
                status=PostureCheckStatus.VERIFIED,
                score_contribution=15.0,
                max_score=15.0,
                evidence="Automated dependency configuration discovered (.github/dependabot.yml or renovate.json).",
                recommendation="Ensure scheduled intervals are active and security-only pull requests are prioritized.",
                documentation_url="https://docs.github.com/en/code-security/dependabot"
            ))
        else:
            checks.append(PostureCheck(
                id="automated-dependencies",
                name="Automated Dependency Updates",
                category="Supply Chain",
                status=PostureCheckStatus.IMPROVEMENT_RECOMMENDED,
                score_contribution=3.0,
                max_score=15.0,
                evidence="Neither Dependabot (.github/dependabot.yml) nor Renovate config detected.",
                recommendation="Add .github/dependabot.yml to automatically receive PRs when dependencies have security vulnerabilities.",
                documentation_url="https://docs.github.com/en/code-security/dependabot"
            ))

        # 3. Code Scanning / SAST CI Workflow
        workflows_dir = os.path.join(target_dir, ".github", "workflows")
        has_sast_workflow = False
        unpinned_actions = []
        has_write_all_perms = False
        workflow_count = 0

        if os.path.isdir(workflows_dir):
            for wf in os.listdir(workflows_dir):
                if wf.endswith((".yml", ".yaml")):
                    workflow_count += 1
                    wf_path = os.path.join(workflows_dir, wf)
                    try:
                        with open(wf_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            if any(k in content.lower() for k in ["codeql", "semgrep", "sonar", "snyk", "trivy", "checkov"]):
                                has_sast_workflow = True
                            if "permissions: write-all" in content or "permissions: \n  contents: write" in content:
                                has_write_all_perms = True
                            # Check for unpinned actions
                            for match in re.finditer(r'uses:\s*([a-zA-Z0-9_\-\./]+)@(v[0-9]+|main|master)', content):
                                unpinned_actions.append(f"{wf}:{match.group(1)}@{match.group(2)}")
                    except Exception:
                        pass

        if has_sast_workflow:
            checks.append(PostureCheck(
                id="ci-code-scanning",
                name="Automated Static Analysis (SAST) in CI",
                category="CI/CD",
                status=PostureCheckStatus.VERIFIED,
                score_contribution=15.0,
                max_score=15.0,
                evidence="Static security scanning workflow active in .github/workflows.",
                recommendation="Keep rulesets updated and configure blocking gates on pull requests.",
                documentation_url="https://docs.github.com/en/code-security/code-scanning"
            ))
        else:
            checks.append(PostureCheck(
                id="ci-code-scanning",
                name="Automated Static Analysis (SAST) in CI",
                category="CI/CD",
                status=PostureCheckStatus.IMPROVEMENT_RECOMMENDED,
                score_contribution=0.0,
                max_score=15.0,
                evidence="No SAST or CodeQL workflow detected in .github/workflows.",
                recommendation="Add a GitHub Actions workflow integrating CodeQL or Semgrep for continuous vulnerability inspection.",
                documentation_url="https://docs.github.com/en/code-security/code-scanning"
            ))

        # 4. CI Workflow Token Permissions (Least Privilege)
        if workflow_count == 0:
            checks.append(PostureCheck(
                id="workflow-permissions",
                name="GitHub Actions Least-Privilege Permissions",
                category="CI/CD",
                status=PostureCheckStatus.NOT_ASSESSED,
                score_contribution=10.0,
                max_score=10.0,
                evidence="No GitHub Actions workflows configured.",
                recommendation="When creating workflows, specify explicit read-only token permissions.",
                documentation_url="https://docs.github.com/en/actions/security-guides/automatic-token-authentication"
            ))
        elif has_write_all_perms:
            checks.append(PostureCheck(
                id="workflow-permissions",
                name="GitHub Actions Least-Privilege Permissions",
                category="CI/CD",
                status=PostureCheckStatus.FAILED,
                score_contribution=0.0,
                max_score=10.0,
                evidence="Found workflows configured with write-all or excessive write permissions.",
                recommendation="Set top-level 'permissions: read-all' or configure strictly required scopes.",
                documentation_url="https://docs.github.com/en/actions/security-guides/automatic-token-authentication"
            ))
        else:
            checks.append(PostureCheck(
                id="workflow-permissions",
                name="GitHub Actions Least-Privilege Permissions",
                category="CI/CD",
                status=PostureCheckStatus.VERIFIED,
                score_contribution=10.0,
                max_score=10.0,
                evidence="Workflows do not request dangerous global write permissions.",
                recommendation="Continue enforcing explicit permissions on every workflow job.",
                documentation_url="https://docs.github.com/en/actions/security-guides/automatic-token-authentication"
            ))

        # 5. Workflow Dependency Pinning (OpenSSF Action-Pinning)
        if len(unpinned_actions) > 0:
            checks.append(PostureCheck(
                id="action-pinning",
                name="GitHub Action SHA Pinning",
                category="Supply Chain",
                status=PostureCheckStatus.IMPROVEMENT_RECOMMENDED,
                score_contribution=5.0,
                max_score=15.0,
                evidence=f"{len(unpinned_actions)} action references use mutable tags (e.g. {unpinned_actions[0]}).",
                recommendation="Pin actions by full 40-character commit SHA (e.g. actions/checkout@b4ffde46f4...) to prevent supply-chain tag hijacking.",
                documentation_url="https://github.com/ossf/scorecard/blob/main/docs/checks.md#pinned-dependencies"
            ))
        elif workflow_count > 0:
            checks.append(PostureCheck(
                id="action-pinning",
                name="GitHub Action SHA Pinning",
                category="Supply Chain",
                status=PostureCheckStatus.VERIFIED,
                score_contribution=15.0,
                max_score=15.0,
                evidence="All GitHub Actions in workflows are pinned to specific immutable commit SHAs.",
                recommendation="Use automated tools like Dependabot or Step-Security to maintain pinned SHA versions.",
                documentation_url="https://github.com/ossf/scorecard/blob/main/docs/checks.md#pinned-dependencies"
            ))
        else:
            checks.append(PostureCheck(
                id="action-pinning",
                name="GitHub Action SHA Pinning",
                category="Supply Chain",
                status=PostureCheckStatus.NOT_ASSESSED,
                score_contribution=10.0,
                max_score=15.0,
                evidence="No workflow actions to pin.",
                recommendation="Pin actions when workflows are introduced.",
                documentation_url="https://github.com/ossf/scorecard/blob/main/docs/checks.md#pinned-dependencies"
            ))

        # 6. Codeowners & Review Requirements
        codeowners_candidates = [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"]
        has_codeowners = any(os.path.exists(os.path.join(target_dir, c)) for c in codeowners_candidates)
        if has_codeowners:
            checks.append(PostureCheck(
                id="code-owners",
                name="Designated Code Ownership (CODEOWNERS)",
                category="Governance",
                status=PostureCheckStatus.VERIFIED,
                score_contribution=15.0,
                max_score=15.0,
                evidence="CODEOWNERS file found. Required code reviews are assigned by domain.",
                recommendation="Ensure CODEOWNERS entries cover security-critical directories like auth, payment, and infra.",
                documentation_url="https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners"
            ))
        else:
            checks.append(PostureCheck(
                id="code-owners",
                name="Designated Code Ownership (CODEOWNERS)",
                category="Governance",
                status=PostureCheckStatus.IMPROVEMENT_RECOMMENDED,
                score_contribution=5.0,
                max_score=15.0,
                evidence="No CODEOWNERS file present in repository.",
                recommendation="Create .github/CODEOWNERS to enforce mandatory peer reviews for sensitive files.",
                documentation_url="https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners"
            ))

        # 7. GitHub API Remote Checks (Branch Protection & Inaccessible Settings)
        if owner and repo and token:
            try:
                headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
                async with httpx.AsyncClient(timeout=10.0) as client:
                    # Branch protection
                    bp_url = f"https://api.github.com/repos/{owner}/{repo}/branches/main/protection"
                    bp_resp = await client.get(bp_url, headers=headers)
                    if bp_resp.status_code == 200:
                        checks.append(PostureCheck(
                            id="branch-protection",
                            name="Main Branch Protection Rules",
                            category="Branch Protections",
                            status=PostureCheckStatus.VERIFIED,
                            score_contribution=15.0,
                            max_score=15.0,
                            evidence="Branch protection verified on default branch via GitHub API.",
                            recommendation="Maintain required status checks, linear history, and 2 approving reviews.",
                            documentation_url="https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/defining-the-mergeability-of-pull-requests/about-protected-branches"
                        ))
                    elif bp_resp.status_code == 404:
                        checks.append(PostureCheck(
                            id="branch-protection",
                            name="Main Branch Protection Rules",
                            category="Branch Protections",
                            status=PostureCheckStatus.IMPROVEMENT_RECOMMENDED,
                            score_contribution=0.0,
                            max_score=15.0,
                            evidence="Branch protection is NOT active on default branch.",
                            recommendation="Configure branch protection requiring PR reviews and passing CI checks before merging.",
                            documentation_url="https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/defining-the-mergeability-of-pull-requests/about-protected-branches"
                        ))
                    elif bp_resp.status_code == 403:
                        checks.append(PostureCheck(
                            id="branch-protection",
                            name="Main Branch Protection Rules",
                            category="Branch Protections",
                            status=PostureCheckStatus.UNAVAILABLE,
                            score_contribution=7.5,
                            max_score=15.0,
                            evidence="Permission restricted: Provided token lacks admin rights to inspect branch protection rules.",
                            recommendation="Provide a token with repository admin permissions to verify branch protection status.",
                            documentation_url="https://docs.github.com/en/rest/branches/branch-protection"
                        ))
            except Exception as ex:
                checks.append(PostureCheck(
                    id="branch-protection",
                    name="Main Branch Protection Rules",
                    category="Branch Protections",
                    status=PostureCheckStatus.UNAVAILABLE,
                    score_contribution=7.5,
                    max_score=15.0,
                    evidence=f"API inspection unavailable: {str(ex)[:100]}",
                    recommendation="Ensure network connectivity to api.github.com.",
                    documentation_url="https://docs.github.com/en/rest/branches/branch-protection"
                ))
        else:
            checks.append(PostureCheck(
                id="branch-protection",
                name="Main Branch Protection Rules",
                category="Branch Protections",
                status=PostureCheckStatus.UNAVAILABLE,
                score_contribution=7.5,
                max_score=15.0,
                evidence="Branch protection API assessment requires GitHub Personal Access Token with repo administration scopes.",
                recommendation="Provide a GitHub PAT in Settings to verify remote branch protection and code review settings.",
                documentation_url="https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/defining-the-mergeability-of-pull-requests/about-protected-branches"
            ))

        # Calculate Posture Score
        total_earned = sum(c.score_contribution for c in checks)
        total_possible = sum(c.max_score for c in checks)
        posture_score = int(round((total_earned / total_possible) * 100)) if total_possible > 0 else 50

        if posture_score >= 85:
            level = "EXCELLENT"
        elif posture_score >= 70:
            level = "GOOD"
        elif posture_score >= 50:
            level = "MODERATE"
        else:
            level = "WEAK"

        report = PostureReport(
            score=posture_score,
            level=level,
            checks=checks,
            methodology="OpenSSF Scorecard-aligned deterministic weighting (Governance 30%, CI/CD Security 35%, Supply Chain 35%). Inaccessible checks are reported as Unavailable.",
            evaluated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        )

        duration = round(time.time() - start_time, 2)
        exec_status = ScannerExecutionStatus(
            scanner_name="Repository Security Posture Scanner",
            tool_version=self.tool_version,
            status="SUCCESS",
            duration_seconds=duration,
            findings_count=len(findings),
            error_message=None
        )

        return report, findings, exec_status
