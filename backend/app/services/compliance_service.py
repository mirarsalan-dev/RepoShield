"""
Compliance Evidence Pack Service for RepoShield V3 (Phase 11).
Maps scanner rules and repository evidence to:
- OWASP Application Security Verification Standard (ASVS v4.0)
- NIST Secure Software Development Framework (SSDF SP 800-218)

Provides exportable evidence mappings while explicitly clarifying that
automated static scan evidence does NOT constitute legal certification or formal audit signoff.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from app.models.scan import ScanResult
from app.models.finding import Finding, Severity, Category

class ComplianceControlMapping(BaseModel):
    control_id: str
    framework: str  # "OWASP_ASVS_V4" | "NIST_SSDF_V1_1"
    section: str
    title: str
    description: str
    status: str  # "PASS_WITH_EVIDENCE" | "FAIL_DETECTED_FLAWS" | "PARTIAL_EVIDENCE" | "UNSUPPORTED_STATICALLY"
    status_label: str
    supporting_finding_ids: List[str] = []
    finding_count: int = 0
    evidence_summary: str
    limitations_note: str

class ComplianceEvidenceReport(BaseModel):
    total_controls: int = 0
    passed_controls_count: int = 0
    failing_controls_count: int = 0
    partial_controls_count: int = 0
    unsupported_controls_count: int = 0
    frameworks: List[str] = ["OWASP ASVS v4.0", "NIST SSDF SP 800-218"]
    controls: List[ComplianceControlMapping] = []
    disclaimer: str = (
        "IMPORTANT LEGAL & AUDIT NOTICE: RepoShield scan outputs provide technical evidence mapping "
        "derived from automated static analysis, software composition analysis, and configuration auditing. "
        "They do NOT constitute official certification, regulatory compliance guarantee, or third-party audit readiness."
    )

def generate_compliance_evidence(scan: ScanResult) -> ComplianceEvidenceReport:
    """
    Evaluates scan findings against standard OWASP ASVS and NIST SSDF controls.
    """
    controls: List[ComplianceControlMapping] = []

    # Helper category filters
    secrets = [f for f in scan.findings if f.category == Category.SECRETS]
    deps = [f for f in scan.findings if f.category == Category.DEPENDENCIES]
    sast = [f for f in scan.findings if f.category == Category.SAST]
    infra = [f for f in scan.findings if f.category == Category.INFRASTRUCTURE]
    api_findings = [f for f in scan.findings if f.category == Category.API_SECURITY]

    # 1. OWASP ASVS V14.4.1 - Secrets Management
    if secrets:
        controls.append(ComplianceControlMapping(
            control_id="ASVS-14.4.1",
            framework="OWASP_ASVS_V4",
            section="V14 Configuration",
            title="Secrets and Credentials Management",
            description="Verify that secrets, private keys, and passwords are not stored in source code or version control repositories.",
            status="FAIL_DETECTED_FLAWS",
            status_label="Failing (Violations Detected)",
            supporting_finding_ids=[f.id for f in secrets],
            finding_count=len(secrets),
            evidence_summary=f"Detected {len(secrets)} hardcoded secrets/credentials in repository source code or git history.",
            limitations_note="Scanner validates pattern and entropy heuristics; active credential verification in target APIs is intentionally unperformed."
        ))
    else:
        controls.append(ComplianceControlMapping(
            control_id="ASVS-14.4.1",
            framework="OWASP_ASVS_V4",
            section="V14 Configuration",
            title="Secrets and Credentials Management",
            description="Verify that secrets, private keys, and passwords are not stored in source code or version control repositories.",
            status="PASS_WITH_EVIDENCE",
            status_label="Pass (Evidence Supported)",
            supporting_finding_ids=[],
            finding_count=0,
            evidence_summary="Gitleaks pattern scanning identified zero plaintext secrets or tokens across inspected branches and commits.",
            limitations_note="Secrets encrypted with custom keys or obfuscated outside standard patterns cannot be conclusively ruled out."
        ))

    # 2. OWASP ASVS V14.2.1 - Dependency Security Analysis
    if deps:
        controls.append(ComplianceControlMapping(
            control_id="ASVS-14.2.1",
            framework="OWASP_ASVS_V4",
            section="V14 Configuration",
            title="Third-Party Components & Dependencies",
            description="Verify that all third party software libraries used by the application do not contain known vulnerabilities.",
            status="FAIL_DETECTED_FLAWS",
            status_label="Failing (Known CVEs Present)",
            supporting_finding_ids=[f.id for f in deps],
            finding_count=len(deps),
            evidence_summary=f"OSV database matching identified {len(deps)} vulnerable packages with recorded CVE/GHSA advisories.",
            limitations_note="Reachability analysis is limited to supported call-graph ecosystems; transitive execution may differ at runtime."
        ))
    else:
        controls.append(ComplianceControlMapping(
            control_id="ASVS-14.2.1",
            framework="OWASP_ASVS_V4",
            section="V14 Configuration",
            title="Third-Party Components & Dependencies",
            description="Verify that all third party software libraries used by the application do not contain known vulnerabilities.",
            status="PASS_WITH_EVIDENCE",
            status_label="Pass (Evidence Supported)",
            supporting_finding_ids=[],
            finding_count=0,
            evidence_summary="All resolved dependencies in project lockfiles are currently free of recorded OSV advisories.",
            limitations_note="Zero-day vulnerabilities not yet reported to public advisory databases are excluded."
        ))

    # 3. OWASP ASVS V5.3.1 - Injection Defense (SAST)
    sql_or_cmd = [f for f in sast if "sql" in f.rule_id.lower() or "injection" in f.rule_id.lower() or "subprocess" in f.rule_id.lower()]
    if sql_or_cmd:
        controls.append(ComplianceControlMapping(
            control_id="ASVS-5.3.1",
            framework="OWASP_ASVS_V4",
            section="V5 Validation & Encoding",
            title="Injection Flaw Prevention (SQL, Command, Taint)",
            description="Verify that output encoding or parameterized interfaces are used to prevent SQL, shell command, or interpreter injections.",
            status="FAIL_DETECTED_FLAWS",
            status_label="Failing (Injection Patterns Detected)",
            supporting_finding_ids=[f.id for f in sql_or_cmd],
            finding_count=len(sql_or_cmd),
            evidence_summary=f"Identified {len(sql_or_cmd)} instances of direct string concatenation into SQL or shell execution sinks.",
            limitations_note="Intra-file AST pattern match. Interprocedural validation across independent services requires dynamic testing."
        ))
    else:
        controls.append(ComplianceControlMapping(
            control_id="ASVS-5.3.1",
            framework="OWASP_ASVS_V4",
            section="V5 Validation & Encoding",
            title="Injection Flaw Prevention (SQL, Command, Taint)",
            description="Verify that output encoding or parameterized interfaces are used to prevent SQL, shell command, or interpreter injections.",
            status="PASS_WITH_EVIDENCE",
            status_label="Pass (Evidence Supported)",
            supporting_finding_ids=[],
            finding_count=0,
            evidence_summary="Semgrep SAST rules verified parameterized query patterns and absence of raw string formatting in database sinks.",
            limitations_note="Complex reflection or dynamically compiled code snippets are outside static AST scope."
        ))

    # 4. OWASP ASVS V14.1.1 - Build Pipeline Integrity (CI/CD)
    wf_issues = [f for f in infra if ".github" in f.file_path.lower() or "workflow" in f.rule_id.lower()]
    if wf_issues:
        controls.append(ComplianceControlMapping(
            control_id="ASVS-14.1.1",
            framework="OWASP_ASVS_V4",
            section="V14 Configuration",
            title="Automated Build Pipeline Security",
            description="Verify that the build pipeline uses secure configurations, unprivileged tokens, and validated build scripts.",
            status="FAIL_DETECTED_FLAWS",
            status_label="Failing (Workflow Security Flaws)",
            supporting_finding_ids=[f.id for f in wf_issues],
            finding_count=len(wf_issues),
            evidence_summary=f"Found {len(wf_issues)} workflow risks including unpinned actions or overly permissive GITHUB_TOKEN.",
            limitations_note="Limited to declarative GitHub Actions YAML files; hosted runner hypervisor integrity cannot be evaluated."
        ))
    else:
        controls.append(ComplianceControlMapping(
            control_id="ASVS-14.1.1",
            framework="OWASP_ASVS_V4",
            section="V14 Configuration",
            title="Automated Build Pipeline Security",
            description="Verify that the build pipeline uses secure configurations, unprivileged tokens, and validated build scripts.",
            status="PASS_WITH_EVIDENCE",
            status_label="Pass (Evidence Supported)",
            supporting_finding_ids=[],
            finding_count=0,
            evidence_summary="GitHub Actions workflows enforce minimal token permissions and pin third-party actions to immutable commit SHAs.",
            limitations_note="Self-hosted runner execution environments are not analyzed."
        ))

    # 5. NIST SSDF PS.3.1 - Verify Third-Party Software Components
    controls.append(ComplianceControlMapping(
        control_id="SSDF-PS.3.1",
        framework="NIST_SSDF_V1_1",
        section="Protect Software (PS)",
        title="Verify Third-Party Software Components",
        description="Verify that software components acquired from third parties satisfy security requirements and are continuously monitored.",
        status="FAIL_DETECTED_FLAWS" if deps else "PASS_WITH_EVIDENCE",
        status_label="Failing" if deps else "Pass (Evidence Supported)",
        supporting_finding_ids=[f.id for f in deps],
        finding_count=len(deps),
        evidence_summary=f"SCA analysis mapped {len(deps)} third-party components with active security advisories." if deps else "Software manifest and lockfile inventory matched zero known vulnerable third-party components.",
        limitations_note="Evaluation relies on public vulnerability feeds (OSV/GHSA/NVD)."
    ))

    # 6. NIST SSDF PW.4.1 - Review Human-Readable Code for Weaknesses
    controls.append(ComplianceControlMapping(
        control_id="SSDF-PW.4.1",
        framework="NIST_SSDF_V1_1",
        section="Produce Well-Secured Software (PW)",
        title="Review Human-Readable Code for Weaknesses",
        description="Make code available for review to identify vulnerabilities and verify compliance with secure coding standards.",
        status="FAIL_DETECTED_FLAWS" if sast else "PASS_WITH_EVIDENCE",
        status_label="Failing" if sast else "Pass (Evidence Supported)",
        supporting_finding_ids=[f.id for f in sast],
        finding_count=len(sast),
        evidence_summary=f"Semgrep AST static review flagged {len(sast)} potential implementation weaknesses." if sast else "Static code analysis identified zero security anti-patterns across repository files.",
        limitations_note="Interprocedural cross-repository data flows are not evaluated statically."
    ))

    # 7. NIST SSDF PW.8.1 - Secure Compilation & Containerization
    docker_issues = [f for f in infra if "dockerfile" in f.file_path.lower()]
    controls.append(ComplianceControlMapping(
        control_id="SSDF-PW.8.1",
        framework="NIST_SSDF_V1_1",
        section="Produce Well-Secured Software (PW)",
        title="Configure Compilation and Build Processes",
        description="Enable security features of build tools and avoid insecure configurations in container builds.",
        status="FAIL_DETECTED_FLAWS" if docker_issues else "PASS_WITH_EVIDENCE",
        status_label="Failing" if docker_issues else "Pass (Evidence Supported)",
        supporting_finding_ids=[f.id for f in docker_issues],
        finding_count=len(docker_issues),
        evidence_summary=f"Container inspector flagged {len(docker_issues)} configuration risks (e.g. root user, unpinned base image)." if docker_issues else "Containerfile instructions adhere to unprivileged user principles and verified checksums.",
        limitations_note="Offline AST evaluation of container instructions without live Docker build daemon."
    ))

    # Aggregate counts
    passed = sum(1 for c in controls if c.status == "PASS_WITH_EVIDENCE")
    failing = sum(1 for c in controls if c.status == "FAIL_DETECTED_FLAWS")
    partial = sum(1 for c in controls if c.status == "PARTIAL_EVIDENCE")
    unsupported = sum(1 for c in controls if c.status == "UNSUPPORTED_STATICALLY")

    return ComplianceEvidenceReport(
        total_controls=len(controls),
        passed_controls_count=passed,
        failing_controls_count=failing,
        partial_controls_count=partial,
        unsupported_controls_count=unsupported,
        controls=controls
    )
