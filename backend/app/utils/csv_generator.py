import csv
import io
from app.models.scan import ScanResult

def generate_csv_report(scan: ScanResult) -> str:
    """
    Generates a structured, sanitized CSV security report.
    All secrets are pre-redacted before insertion.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Header section
    writer.writerow(["# REPOSHIELD CYBERSECURITY AUDIT REPORT"])
    writer.writerow(["Repository", f"{scan.owner}/{scan.repo}"])
    writer.writerow(["Repository URL", scan.repo_url])
    writer.writerow(["Branch / Ref", scan.branch])
    writer.writerow(["Scan Timestamp", scan.started_at])
    writer.writerow(["Duration (seconds)", scan.duration_seconds or 0])
    if scan.risk_score:
        writer.writerow(["Risk Score", f"{scan.risk_score.score} / 100 ({scan.risk_score.level})"])
        writer.writerow(["Total Findings", scan.risk_score.total_findings])
    writer.writerow([])

    # Table columns
    writer.writerow([
        "Finding ID",
        "Category",
        "Severity",
        "Title",
        "Detector",
        "Rule / Advisory ID",
        "File Path",
        "Line Start",
        "Line End",
        "Evidence (Redacted)",
        "Remediation Guidance",
        "CVE ID",
        "GHSA ID",
        "CVSS Score",
        "Package Name",
        "Installed Version",
        "Fixed Version"
    ])

    for f in scan.findings:
        writer.writerow([
            f.id,
            f.category.value,
            f.severity.value,
            f.title,
            f.detector_name,
            f.rule_id,
            f.file_path,
            f.line_start or "",
            f.line_end or "",
            (f.evidence or "").replace("\n", " "),
            f.remediation.replace("\n", " "),
            f.cve_id or "",
            f.ghsa_id or "",
            f.cvss_score or "",
            f.package_name or "",
            f.installed_version or "",
            f.fixed_version or ""
        ])

    return output.getvalue()
