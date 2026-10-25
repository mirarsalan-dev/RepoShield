"""
HTML Audit Report Generator for RepoShield V2.
Generates a standalone, dependency-free, macOS-styled HTML security audit report.
Zero database requirement. All credentials strictly redacted.
"""
import html
from app.models.scan import ScanResult
from app.utils.redaction import redact_text

def generate_html_report(scan: ScanResult) -> str:
    """Generates a self-contained, offline-renderable HTML report."""
    risk = scan.risk_score
    score = risk.score if risk else 0
    level = risk.level if risk else "UNKNOWN"
    total = len(scan.findings)

    # Color mapping
    level_color = "#34C759" if level in ("LOW", "SECURE") else ("#FF9500" if level == "MEDIUM" else "#FF3B30")

    findings_rows = []
    for f in scan.findings:
        sev = f.severity.value
        sev_color = "#FF3B30" if sev == "CRITICAL" else ("#FF9500" if sev == "HIGH" else ("#F5A623" if sev == "MEDIUM" else "#34C759"))
        evidence = redact_text(f.evidence) if f.evidence else ""
        evidence_html = f"<pre style='background:#f4f4f6;padding:6px;border-radius:4px;font-size:11px;overflow-x:auto;'>{html.escape(evidence[:300])}</pre>" if evidence else "<span style='color:#8e8e93;'>N/A</span>"
        prio = f.exploitability_priority or "P3"

        row = f"""
        <tr style="border-bottom:1px solid #e5e5ea;">
            <td style="padding:10px 12px;white-space:nowrap;">
                <span style="display:inline-block;padding:2px 8px;border-radius:4px;font-weight:600;font-size:11px;background:{sev_color}1a;color:{sev_color};border:1px solid {sev_color}4d;">
                    • {html.escape(sev)}
                </span>
            </td>
            <td style="padding:10px 12px;font-size:11px;font-family:monospace;color:#6e6e73;">{html.escape(prio)}</td>
            <td style="padding:10px 12px;font-weight:500;">
                <div>{html.escape(f.title)}</div>
                <div style="font-size:11px;color:#8e8e93;font-family:monospace;margin-top:2px;">{html.escape(f.rule_id)}</div>
            </td>
            <td style="padding:10px 12px;font-size:12px;font-family:monospace;color:#48484a;">{html.escape(f.file_path or '-')}:{f.line_start or 1}</td>
            <td style="padding:10px 12px;">{evidence_html}</td>
            <td style="padding:10px 12px;font-size:12px;color:#3a3a3c;">{html.escape(f.remediation[:200])}</td>
        </tr>
        """
        findings_rows.append(row)

    findings_tbody = "\n".join(findings_rows) if findings_rows else "<tr><td colspan='6' style='text-align:center;padding:24px;color:#8e8e93;'>Zero vulnerabilities detected. Repository is clean.</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RepoShield Security Audit — {html.escape(scan.repo or scan.scan_id)}</title>
<style>
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: #f5f5f7;
    color: #1d1d1f;
    margin: 0;
    padding: 32px 20px;
  }}
  .container {{
    max-width: 1100px;
    margin: 0 auto;
    background: #ffffff;
    border-radius: 12px;
    border: 1px solid #d2d2d7;
    box-shadow: 0 4px 20px rgba(0,0,0,0.06);
    overflow: hidden;
  }}
  .header {{
    padding: 24px;
    background: #ffffff;
    border-bottom: 1px solid #e5e5ea;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 16px;
  }}
  .stat-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 12px;
    padding: 20px 24px;
    background: #fafafa;
    border-bottom: 1px solid #e5e5ea;
  }}
  .stat-card {{
    background: #ffffff;
    border: 1px solid #e5e5ea;
    border-radius: 8px;
    padding: 12px 16px;
  }}
  .stat-label {{ font-size: 11px; text-transform: uppercase; color: #86868b; font-weight: 600; }}
  .stat-value {{ font-size: 20px; font-weight: 700; margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; text-align: left; }}
  th {{ background: #f5f5f7; padding: 10px 12px; font-size: 11px; text-transform: uppercase; color: #6e6e73; font-weight: 600; border-bottom: 1px solid #d2d2d7; }}
  .footer {{ padding: 16px 24px; background: #fafafa; border-top: 1px solid #e5e5ea; font-size: 11px; color: #86868b; display: flex; justify-content: space-between; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <div style="font-size: 12px; color: #007aff; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">RepoShield Security Intelligence Report</div>
      <h1 style="margin: 4px 0 0; font-size: 22px; font-weight: 700;">{html.escape(scan.repo or scan.scan_id)}</h1>
      <div style="font-size: 12px; color: #6e6e73; font-family: monospace; margin-top: 4px;">{html.escape(scan.repo_url)} • SHA: {html.escape((scan.commit_sha or 'HEAD')[:8])}</div>
    </div>
    <div style="text-align: right;">
      <div style="display: inline-block; padding: 6px 14px; border-radius: 20px; background: {level_color}1a; border: 1px solid {level_color}4d; color: {level_color}; font-weight: 700; font-size: 14px;">
        Risk Score: {score}/100 ({level})
      </div>
      <div style="font-size: 11px; color: #86868b; margin-top: 4px;">Generated: {scan.completed_at or scan.started_at}</div>
    </div>
  </div>

  <div class="stat-grid">
    <div class="stat-card">
      <div class="stat-label">Total Findings</div>
      <div class="stat-value">{total}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Critical / High</div>
      <div class="stat-value" style="color: #ff3b30;">{sum(1 for f in scan.findings if f.severity in ("CRITICAL", "HIGH"))}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Medium / Low</div>
      <div class="stat-value" style="color: #ff9500;">{sum(1 for f in scan.findings if f.severity in ("MEDIUM", "LOW"))}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">SBOM Components</div>
      <div class="stat-value">{len(scan.sbom_components)}</div>
    </div>
  </div>

  <div style="overflow-x: auto;">
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Priority</th>
          <th>Vulnerability & Rule</th>
          <th>File Location</th>
          <th>Evidence (Redacted)</th>
          <th>Remediation</th>
        </tr>
      </thead>
      <tbody>
        {findings_tbody}
      </tbody>
    </table>
  </div>

  <div class="footer">
    <span>RepoShield V2 — Deterministic Security Intelligence (Zero Database)</span>
    <span>100% Credential Redaction Enforced</span>
  </div>
</div>
</body>
</html>
"""
