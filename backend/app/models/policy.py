from typing import Optional
from pydantic import BaseModel, Field
from app.models.finding import Severity

class PolicySuppression(BaseModel):
    rule_id: str
    reason: str
    expires_at: Optional[str] = None
    created_at: Optional[str] = None

class SecurityPolicy(BaseModel):
    policy_id: str = Field(default="default", description="Identifier for policy")
    name: str = Field(default="Standard Developer Security Gate", description="Human-readable policy name")
    fail_on_critical: bool = Field(default=True, description="Fail scan/gate if any CRITICAL finding is detected")
    fail_on_high: bool = Field(default=True, description="Fail scan/gate if any HIGH finding is detected")
    fail_on_secrets: bool = Field(default=True, description="Fail scan/gate if any unsuppressed secret is detected")
    warn_on_dependencies: bool = Field(default=True, description="Produce warnings for vulnerable dependencies")
    fail_on_sast_high: bool = Field(default=True, description="Fail on high-severity static code analysis flaws")
    require_suppression_reason: bool = Field(default=True, description="Reject suppressions without documented reasons")
    max_permitted_severity: Severity = Field(default=Severity.MEDIUM, description="Maximum allowed severity before gating fails")
    suppressions: list[PolicySuppression] = Field(default_factory=list, description="Explicit rule or finding suppressions")

class PolicyEvaluationResult(BaseModel):
    passed: bool
    policy_name: str
    violations: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    secrets_count: int = 0
    dependencies_count: int = 0
    suppressed_count: int = 0
    evaluated_at: str
    summary: str
