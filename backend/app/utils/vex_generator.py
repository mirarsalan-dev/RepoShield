"""
CycloneDX VEX (Vulnerability Exploitability eXchange) Generator for RepoShield V2.
Generates compliant CycloneDX 1.5 VEX documents linking component vulnerabilities
with documented analysis status, justifications, and remediation evidence.
"""
import json
import uuid
from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field
from app.models.scan import ScanResult

class VexStatement(BaseModel):
    vulnerability_id: str
    component_purl: str
    status: str  # "affected", "not_affected", "fixed", "under_investigation"
    justification: Optional[str] = None  # e.g., "code_not_reachable", "protected_by_mitigating_control", "inline_mitigations_already_exist"
    impact: Optional[str] = None
    action_statement: Optional[str] = None

def generate_cyclonedx_vex(scan: ScanResult, custom_statements: Optional[List[VexStatement]] = None) -> str:
    """
    Generates a CycloneDX 1.5 JSON VEX document.
    """
    serial = f"urn:uuid:{uuid.uuid4()}"
    timestamp = datetime.now(timezone.utc).isoformat()

    statements_map = {}
    if custom_statements:
        for s in custom_statements:
            key = f"{s.vulnerability_id}:{s.component_purl}"
            statements_map[key] = s

    vulnerabilities = []
    for f in scan.findings:
        if f.package_name:
            cve = f.cve_id or f.ghsa_id or f.rule_id
            purl = f"pkg:generic/{f.package_name}@{f.installed_version}" if f.installed_version else f"pkg:generic/{f.package_name}"
            key = f"{cve}:{purl}"

            # Check if user documented custom statement
            if key in statements_map:
                stmt = statements_map[key]
                status = stmt.status
                justification = stmt.justification
                impact = stmt.impact or f.technical_impact
                action = stmt.action_statement or f.remediation
            else:
                # Default status based on analysis
                if f.reachability_status == "CONFIRMED":
                    status = "affected"
                    justification = None
                    impact = f"Vulnerable code actively imported in {f.file_path}."
                    action = f.remediation
                elif f.reachability_status == "NO_EVIDENCE":
                    status = "under_investigation"
                    justification = "code_not_present"
                    impact = "Transitive dependency; no direct code references detected."
                    action = "Audit runtime call tree before final assessment."
                else:
                    status = "affected"
                    justification = None
                    impact = f.technical_impact or "Potential application impact."
                    action = f.remediation

            vuln_entry = {
                "id": cve,
                "source": {
                    "name": "RepoShield VEX Intelligence",
                    "url": f"https://osv.dev/vulnerability/{f.rule_id}"
                },
                "analysis": {
                    "state": status,
                    "justification": justification,
                    "response": ["will_not_fix"] if status == "not_affected" else ["workaround_available", "update"],
                    "detail": impact
                },
                "affects": [
                    {
                        "ref": purl
                    }
                ]
            }
            if action:
                vuln_entry["recommendation"] = action

            vulnerabilities.append(vuln_entry)

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "RepoShield",
                    "name": "RepoShield VEX Generator",
                    "version": "2.0.0"
                }
            ],
            "component": {
                "type": "application",
                "name": f"{scan.owner}/{scan.repo}",
                "version": scan.commit_sha[:7] if scan.commit_sha else "HEAD"
            }
        },
        "vulnerabilities": vulnerabilities
    }

    return json.dumps(doc, indent=2)
