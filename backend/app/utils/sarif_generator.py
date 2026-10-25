import json
from app.models.scan import ScanResult
from app.models.finding import Severity

def generate_sarif_report(scan: ScanResult) -> str:
    """
    Generates an OASIS SARIF v2.1.0 report compatible with GitHub Code Scanning.
    """
    rules_map = {}
    results = []

    for f in scan.findings:
        # Map severity to SARIF level
        level = "warning"
        if f.severity in (Severity.CRITICAL, Severity.HIGH):
            level = "error"
        elif f.severity in (Severity.LOW, Severity.INFO):
            level = "note"

        rule_id = f.rule_id or "reposhield-rule"

        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": f.title[:64],
                "shortDescription": {
                    "text": f.title
                },
                "fullDescription": {
                    "text": f.description[:500] if f.description else f.title
                },
                "defaultConfiguration": {
                    "level": level
                },
                "help": {
                    "text": f.remediation or "Review and fix the security finding.",
                    "markdown": f"**Remediation:** {f.remediation}\n\n**Category:** {f.category}\n**Severity:** {f.severity}"
                },
                "properties": {
                    "category": f.category,
                    "cwe": [f.cwe_id] if f.cwe_id else [],
                    "cve": [f.cve_id] if f.cve_id else [],
                    "tags": [f.category.lower(), f.severity.lower()]
                }
            }

        start_line = f.line_start or 1
        end_line = f.line_end or start_line

        result_item = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": f"{f.title} - {f.description[:200]}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file_path.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": start_line,
                            "endLine": end_line
                        }
                    }
                }
            ],
            "partialFingerprints": {
                "primaryLocationLineHash": f.fingerprint or ""
            }
        }
        results.append(result_item)

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RepoShield",
                        "organization": "RepoShield Security",
                        "product": "RepoShield GitHub Security Analyzer",
                        "version": "2.0.0",
                        "semanticVersion": "2.0.0",
                        "informationUri": "https://github.com/RepoShield",
                        "rules": list(rules_map.values())
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": scan.status == "COMPLETED",
                        "endTimeUtc": scan.completed_at or scan.started_at
                    }
                ]
            }
        ]
    }

    return json.dumps(sarif_doc, indent=2)
