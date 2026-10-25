from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
from app.models.finding import Finding, Severity, Category
from app.models.sbom import SBOMComponent

class ScanState(str, Enum):
    QUEUED = "QUEUED"
    CLONING = "CLONING"
    SCANNING_SECRETS = "SCANNING_SECRETS"
    SCANNING_DEPENDENCIES = "SCANNING_DEPENDENCIES"
    SCANNING_SAST = "SCANNING_SAST"
    SCANNING_INFRASTRUCTURE = "SCANNING_INFRASTRUCTURE"
    FINALIZING = "FINALIZING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"

class ScannerExecutionStatus(BaseModel):
    scanner_name: str
    tool_version: str
    status: str # "Completed", "Completed with warnings", "Failed", "Not run", "Unsupported", "In progress"
    category_name: Optional[str] = None
    duration_seconds: float = 0.0
    findings_count: int = 0
    error_message: Optional[str] = None
    files_analyzed_count: int = 0
    files_excluded_count: int = 0
    exclusion_reasons: list[str] = Field(default_factory=list)
    rules_executed_count: int = 0
    scope_description: str = ""
    warnings: list[str] = Field(default_factory=list)
    recommended_next_steps: list[str] = Field(default_factory=list)

class RiskScore(BaseModel):
    score: float = Field(ge=0.0, le=100.0, description="Risk index from 0 (Safe) to 100 (Critical)")
    level: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW, SECURE")
    summary: str = Field(description="Summary of risk posture")
    formula_explanation: str = Field(
        default="Deterministic weighted score: Critical*15 + High*8 + Medium*4 + Low*1.5, normalized to 100 max."
    )
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    unknown_count: int = 0
    secrets_count: int = 0
    dependencies_count: int = 0
    sast_count: int = 0
    infrastructure_count: int = 0
    suppressed_count: int = 0
    reviewed_count: int = 0
    p1_count: int = 0
    p2_count: int = 0
    p3_count: int = 0
    p4_count: int = 0
    cisa_kev_count: int = 0
    historical_secrets_count: int = 0

class ScanRequest(BaseModel):
    repo_url: str = Field(description="GitHub repository URL")
    branch: Optional[str] = Field(default=None, description="Branch to scan")
    commit_sha: Optional[str] = Field(default=None, description="Specific commit SHA to scan")
    github_token: Optional[str] = Field(default=None, description="Optional GitHub token for rate limit increase")
    enable_secrets: bool = True
    enable_dependencies: bool = True
    enable_sast: bool = True
    enable_infrastructure: bool = True
    enable_api_security: bool = True
    enable_posture: bool = True

class ScanResponse(BaseModel):
    scan_id: str
    repo_url: str
    status: ScanState
    message: str

class ScanResult(BaseModel):
    scan_id: str
    repo_url: str
    owner: str
    repo: str
    branch: str
    commit_sha: Optional[str] = None
    commit_author: Optional[str] = None
    commit_date: Optional[str] = None
    status: ScanState
    progress: int = 0
    current_step: str = ""
    started_at: str
    created_at: Optional[str] = None
    completed_at: Optional[str] = None
    scanned_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    scanners_coverage: dict[str, ScannerExecutionStatus] = {}
    findings: list[Finding] = []
    sbom_components: list[SBOMComponent] = []
    risk_score: Optional[RiskScore] = None
    posture_report: Optional[dict] = None
    attack_path_graph: Optional[dict] = None
    api_security_report: Optional[dict] = None
    logs: list[str] = []
    error_detail: Optional[str] = None
