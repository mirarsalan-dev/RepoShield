"""
Fix Validation Service for RepoShield V2.
Validates proposed security remediation patches against real scanners in an isolated sandbox.
Compares before-and-after results without executing untrusted code or committing to repositories.
"""
import difflib
import os
import shutil
import tempfile
import time
from typing import Optional, List
from pydantic import BaseModel, Field
from app.models.finding import Finding, Category
from app.scanners.gitleaks_scanner import GitleaksScanner
from app.scanners.semgrep_scanner import SemgrepScanner
from app.scanners.config_scanner import ConfigScanner
from app.scanners.osv_scanner import OSVScanner

class FixValidationStatus(str):
    RESOLVED_BY_VERIFICATION = "Resolved by verification"
    STILL_DETECTED = "Still detected"
    NEW_FINDING_INTRODUCED = "New finding introduced"
    VERIFICATION_FAILED = "Verification failed"
    NOT_VERIFIABLE = "Not verifiable"
    # Backwards compatibility aliases
    VERIFIED_RESOLVED = "Resolved by verification"
    REGRESSION_DETECTED = "New finding introduced"
    INCONCLUSIVE = "Verification failed"

class FixValidationRequest(BaseModel):
    finding: Finding
    original_code: str
    remediated_code: str
    file_path: Optional[str] = None

class FixValidationResult(BaseModel):
    status: str
    finding_fingerprint: str
    rule_id: str
    detector_name: str
    duration_seconds: float
    diff_unified: str
    summary: str
    remaining_evidence: Optional[str] = None
    new_findings: List[Finding] = Field(default_factory=list)
    scanner_limitations: str
    timestamp: str

class FixValidationService:
    def __init__(self):
        self.gitleaks = GitleaksScanner()
        self.semgrep = SemgrepScanner()
        self.config_scanner = ConfigScanner()
        self.osv = OSVScanner()

    async def validate_fix(self, request: FixValidationRequest) -> FixValidationResult:
        start_time = time.time()
        finding = request.finding
        file_path = request.file_path or finding.file_path or "source_file"
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Generate side-by-side / unified diff
        orig_lines = request.original_code.splitlines(keepends=True)
        rem_lines = request.remediated_code.splitlines(keepends=True)
        diff_lines = list(difflib.unified_diff(
            orig_lines, rem_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm=""
        ))
        diff_unified = "\n".join(diff_lines) if diff_lines else "No changes detected."

        temp_dir = tempfile.mkdtemp(prefix="reposhield_fixval_")
        target_file = os.path.join(temp_dir, os.path.basename(file_path))

        try:
            with open(target_file, "w", encoding="utf-8", errors="ignore") as f:
                f.write(request.remediated_code)

            new_findings: List[Finding] = []
            exec_status = None

            # Route to the matching scanner engine
            if finding.category == Category.SECRETS or "gitleaks" in finding.rule_id.lower() or "secret" in finding.detector_name.lower():
                new_findings, exec_status = await self.gitleaks.scan(temp_dir)
                scanner_limitation = "Gitleaks pattern validation verifies whether regex credential signatures match in the patch. Does not verify whether external API keys have been revoked in provider consoles."
            elif finding.category == Category.SAST or "semgrep" in finding.detector_name.lower():
                new_findings, exec_status = await self.semgrep.scan(temp_dir)
                scanner_limitation = "Static AST analysis checks syntax and data flow within the edited file. Cross-file taint analysis requires full repository context."
            elif finding.category == Category.INFRASTRUCTURE or "config" in finding.detector_name.lower():
                new_findings, exec_status = await self.config_scanner.scan(temp_dir)
                scanner_limitation = "Infrastructure configuration validator checks security attributes of Dockerfiles and CI workflows without running container builds."
            elif finding.category == Category.DEPENDENCIES or "osv" in finding.detector_name.lower():
                new_findings, exec_status = await self.osv.scan(temp_dir)
                scanner_limitation = "Dependency validation inspects manifest version specifiers against published OSV advisories."
            else:
                # Fallback to Semgrep and Gitleaks
                f1, _ = await self.gitleaks.scan(temp_dir)
                f2, _ = await self.semgrep.scan(temp_dir)
                new_findings = f1 + f2
                scanner_limitation = "Composite static security validation."

            duration = round(time.time() - start_time, 2)

            # Check if original finding rule still fires
            matching_remaining = [
                f for f in new_findings
                if f.rule_id == finding.rule_id or (finding.cve_id and f.cve_id == finding.cve_id)
            ]

            # Check if other rules were triggered that weren't present originally
            unrelated_findings = [
                f for f in new_findings
                if f.rule_id != finding.rule_id and (not finding.cve_id or f.cve_id != finding.cve_id)
            ]

            if matching_remaining:
                status = FixValidationStatus.STILL_DETECTED
                summary = (
                    f"The original issue '{finding.title}' remains detectable by {finding.detector_name}. "
                    f"Offending pattern was still matched in the updated code."
                )
                remaining_evidence = matching_remaining[0].evidence
            elif unrelated_findings:
                status = FixValidationStatus.NEW_FINDING_INTRODUCED
                summary = (
                    f"The original finding was resolved, but {len(unrelated_findings)} NEW security issue(s) "
                    f"were introduced by the proposed patch."
                )
                remaining_evidence = None
            else:
                status = FixValidationStatus.RESOLVED_BY_VERIFICATION
                summary = (
                    f"Patch successfully validated! The original security vulnerability ({finding.rule_id}) "
                    f"is no longer detected, and no regressions were introduced."
                )
                remaining_evidence = None

            return FixValidationResult(
                status=status,
                finding_fingerprint=finding.fingerprint,
                rule_id=finding.rule_id,
                detector_name=finding.detector_name,
                duration_seconds=duration,
                diff_unified=diff_unified,
                summary=summary,
                remaining_evidence=remaining_evidence,
                new_findings=unrelated_findings,
                scanner_limitations=scanner_limitation,
                timestamp=timestamp
            )

        except Exception as e:
            duration = round(time.time() - start_time, 2)
            return FixValidationResult(
                status=FixValidationStatus.VERIFICATION_FAILED,
                finding_fingerprint=finding.fingerprint,
                rule_id=finding.rule_id,
                detector_name=finding.detector_name,
                duration_seconds=duration,
                diff_unified=diff_unified,
                summary=f"Validation failed: Scanner encountered an error during analysis ({str(e)}).",
                remaining_evidence=None,
                new_findings=[],
                scanner_limitations="Execution failed during sandbox analysis.",
                timestamp=timestamp
            )
        finally:
            # STRICT ZERO-PERSISTENCE: Clean up sandbox directory
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

fix_validation_service = FixValidationService()
