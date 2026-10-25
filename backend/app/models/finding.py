import hashlib
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"

class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class Category(str, Enum):
    SECRETS = "SECRETS"
    DEPENDENCIES = "DEPENDENCIES"
    SAST = "SAST"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    API_SECURITY = "API_SECURITY"
    POSTURE = "POSTURE"

class FindingStatus(str, Enum):
    OPEN = "OPEN"
    REVIEWED = "REVIEWED"
    SUPPRESSED = "SUPPRESSED"
    RESOLVED = "RESOLVED"

def compute_finding_fingerprint(
    category: str,
    detector_name: str,
    rule_id: str,
    file_path: str,
    line_start: Optional[int] = None,
    package_name: Optional[str] = None,
) -> str:
    """Compute a deterministic, stable fingerprint for finding deduplication and diffing."""
    parts = [
        str(category).upper(),
        str(detector_name).lower(),
        str(rule_id).lower(),
        str(file_path).lower(),
        str(line_start or 0),
        str(package_name or "").lower(),
    ]
    raw = ":".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

class Finding(BaseModel):
    id: str = Field(description="Unique identifier for finding")
    fingerprint: str = Field(default="", description="Deterministic fingerprint for diffing and policy matching")
    title: str = Field(description="Summary title of the issue")
    description: str = Field(description="Detailed explanation of the vulnerability or risk")
    category: Category = Field(description="Category: SECRETS, DEPENDENCIES, SAST, INFRASTRUCTURE, API_SECURITY, or POSTURE")
    severity: Severity = Field(description="Severity classification")
    confidence: Confidence = Field(default=Confidence.HIGH, description="Confidence level of detection")
    raw_severity: Optional[str] = Field(default=None, description="Original scanner reported severity string")
    file_path: str = Field(description="Relative path of file inside repository")
    line_start: Optional[int] = Field(default=None, description="Starting line number")
    line_end: Optional[int] = Field(default=None, description="Ending line number")
    detector_name: str = Field(description="Tool detector name, e.g. Gitleaks, OSV, Semgrep, ConfigCheck")
    rule_id: str = Field(description="Scanner rule ID or vulnerability identifier")
    evidence: Optional[str] = Field(default=None, description="Redacted snippet or offending code snippet")
    remediation: str = Field(description="Actionable fix recommendations")
    cve_id: Optional[str] = Field(default=None, description="CVE identifier if applicable")
    ghsa_id: Optional[str] = Field(default=None, description="GitHub Security Advisory ID if applicable")
    cwe_id: Optional[str] = Field(default=None, description="CWE identifier e.g. CWE-798, CWE-89")
    cvss_score: Optional[float] = Field(default=None, description="CVSS v3 base score if available")
    package_name: Optional[str] = Field(default=None, description="Vulnerable package name for dependency findings")
    installed_version: Optional[str] = Field(default=None, description="Detected vulnerable version")
    fixed_version: Optional[str] = Field(default=None, description="Recommended remediation package version")
    ecosystem: Optional[str] = Field(default=None, description="npm, PyPI, Go, Maven, Cargo, Composer")
    direct_dependency: Optional[bool] = Field(default=None, description="True if direct dependency, False if transitive")
    update_command: Optional[str] = Field(default=None, description="Suggested command to remediate package")
    breaking_change_risk: Optional[str] = Field(default=None, description="Estimated breaking change risk e.g. Low, Major bump")
    technical_impact: Optional[str] = Field(default=None, description="Impact and exploitability context")
    secure_code_example: Optional[str] = Field(default=None, description="Secure code example or pattern")
    suggested_patch: Optional[str] = Field(default=None, description="Unified diff patch recommendation")
    status: FindingStatus = Field(default=FindingStatus.OPEN, description="Finding status: OPEN, REVIEWED, SUPPRESSED, RESOLVED")
    suppression_reason: Optional[str] = Field(default=None, description="Documented reason for suppression")
    suppression_expires_at: Optional[str] = Field(default=None, description="ISO timestamp when suppression expires")
    first_detected_at: Optional[str] = Field(default=None, description="Timestamp when finding was first detected")

    # V2 Enhancements: Git History Secret Scanning
    is_historical: bool = Field(default=False, description="Whether secret was discovered in historical commit rather than HEAD")
    commit_sha: Optional[str] = Field(default=None, description="Commit SHA where historical secret was introduced")
    commit_author: Optional[str] = Field(default=None, description="Author of commit where secret was detected")
    commit_date: Optional[str] = Field(default=None, description="Date of historical commit")
    remains_in_head: Optional[bool] = Field(default=None, description="True if secret pattern is still present in current HEAD working tree")

    # V2 Enhancements: Exploitability & Risk Prioritization
    epss_score: Optional[float] = Field(default=None, description="Exploit Prediction Scoring System probability (0.0 to 1.0)")
    epss_percentile: Optional[float] = Field(default=None, description="EPSS percentile relative to all CVEs")
    cisa_kev: bool = Field(default=False, description="True if listed in CISA Known Exploited Vulnerabilities catalog")
    exploitability_priority: Optional[str] = Field(default=None, description="Calculated priority: P1 - Immediate, P2 - High, P3 - Moderate, P4 - Low")
    priority_rationale: Optional[str] = Field(default=None, description="Evidence-backed transparent explanation of priority ranking")

    # V2 Enhancements: Reachability Analysis
    reachability_status: Optional[str] = Field(default=None, description="CONFIRMED, POTENTIALLY_REACHABLE, NO_EVIDENCE, INCONCLUSIVE, UNSUPPORTED")
    reachability_evidence: Optional[str] = Field(default=None, description="Summary of static call analysis or imported modules")

    # V2 Enhancements: Security Learning Mode
    beginner_explanation: Optional[str] = Field(default=None, description="Simplified explanation of the vulnerability")
    developer_explanation: Optional[str] = Field(default=None, description="Actionable explanation of code impact and resolution")
    security_engineer_explanation: Optional[str] = Field(default=None, description="Technical in-depth threat model, detection boundaries, and trade-offs")

    # V2 Enhancements: Attack Path Visualizer & Graphs
    attack_path_node_type: Optional[str] = Field(default=None, description="ENTRY_POINT, LATERAL_MOVEMENT, CREDENTIAL_EXPOSURE, SENSITIVE_ASSET")
    related_finding_ids: list[str] = Field(default_factory=list, description="IDs of linked findings in identified attack chains")

    # V2 Enhancements: API & Infrastructure metadata
    endpoint_method: Optional[str] = Field(default=None, description="HTTP method e.g. GET, POST")
    endpoint_path: Optional[str] = Field(default=None, description="API route path e.g. /api/v1/users")
    iac_resource_type: Optional[str] = Field(default=None, description="IaC resource type e.g. Dockerfile, Kubernetes, Terraform")

class FindingFilterParams(BaseModel):
    severity: Optional[list[Severity]] = None
    category: Optional[list[Category]] = None
    status: Optional[list[FindingStatus]] = None
    confidence: Optional[list[Confidence]] = None
    file_path: Optional[str] = None
    search: Optional[str] = None
    exploitability_priority: Optional[list[str]] = None
    cisa_kev_only: Optional[bool] = None
    is_historical: Optional[bool] = None
