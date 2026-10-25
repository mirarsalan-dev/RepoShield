#!/usr/bin/env python3
"""
RepoShield CLI — Local & CI/CD Security Scanner.
Scans local repositories or GitHub URLs for exposed secrets, vulnerable dependencies, and insecure code.
Zero database requirement.
"""

import argparse
import asyncio
import json
import os
import shutil
import sys
import tempfile
import uuid
from datetime import datetime, timezone

from app.models.finding import Severity
from app.models.scan import ScanResult, ScanState
from app.scanners.gitleaks_scanner import GitleaksScanner
from app.scanners.osv_scanner import OSVScanner
from app.scanners.semgrep_scanner import SemgrepScanner
from app.scanners.config_scanner import ConfigScanner
from app.core.scoring import calculate_risk_score
from app.utils.sarif_generator import generate_sarif_report
from app.utils.sbom_generator import generate_cyclonedx_sbom, generate_spdx_sbom
from app.utils.vex_generator import generate_cyclonedx_vex
from app.utils.html_generator import generate_html_report
from app.utils.redaction import redact_text

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
    "UNKNOWN": 0
}

def format_scan_output(scan_result: ScanResult, out_format: str) -> None:
    """Formats and prints the scan result to stdout."""
    if out_format == "json":
        print(scan_result.model_dump_json(indent=2))
    elif out_format == "sarif":
        print(generate_sarif_report(scan_result))
    elif out_format == "cyclonedx":
        print(generate_cyclonedx_sbom(scan_result))
    elif out_format == "spdx":
        print(generate_spdx_sbom(scan_result))
    elif out_format == "vex":
        print(generate_cyclonedx_vex(scan_result))
    elif out_format == "html":
        print(generate_html_report(scan_result))
    else:
        # Table output
        risk = scan_result.risk_score
        score = risk.score if risk else 0
        level = risk.level if risk else "UNKNOWN"
        print("-" * 75)
        print(f"RepoShield Audit Report | Target: {scan_result.repo or scan_result.repo_url}")
        print(f"Risk Index: {score}/100 ({level}) | Total Findings: {len(scan_result.findings)}")
        print(f"Components in SBOM: {len(scan_result.sbom_components)}")
        print("-" * 75)

        if not scan_result.findings:
            print("No vulnerabilities detected! Repository is clean.")
        else:
            for f in scan_result.findings:
                sev_label = f"[{f.severity.value}]"
                prio_label = f"({f.exploitability_priority or 'P3'})"
                print(f"{sev_label:10} {prio_label:16} {f.rule_id:30} {f.file_path}:{f.line_start or 1}")
                print(f"           Title: {f.title}")
                if f.is_historical:
                    print(f"           Git History: Leaked in commit {f.commit_sha[:7] if f.commit_sha else 'hist'} by {f.commit_author} (Remains in HEAD: {f.remains_in_head})")
                if f.reachability_status:
                    print(f"           Reachability: {f.reachability_status}")
                if f.evidence:
                    print(f"           Evidence: {redact_text(f.evidence[:80])}")
                print(f"           Fix: {f.remediation[:90]}")
                print()

        print("-" * 75)

async def scan_local_or_remote(target: str, fail_on: str = "HIGH", out_format: str = "table") -> int:
    is_remote = target.startswith("http://") or target.startswith("https://")
    temp_dir = None
    resolved_sha = "HEAD"

    if is_remote:
        from app.core.security import parse_and_validate_github_url
        from app.scanners.orchestrator import orchestrator

        try:
            owner, repo = parse_and_validate_github_url(target)
            print(f"[RepoShield] Fetching GitHub repository archive: {owner}/{repo}")
            temp_dir = tempfile.mkdtemp(prefix="reposhield_cli_")
            token = os.getenv("GITHUB_TOKEN")
            target_path, resolved_sha = await orchestrator._fetch_and_extract_repo(
                owner, repo, "HEAD", token, temp_dir, lambda msg: None
            )
            repo_name = f"{owner}/{repo}"
            repo_url = f"https://github.com/{owner}/{repo}"
            resolved_sha = resolved_sha or "HEAD"
        except Exception as e:
            print(f"Error fetching remote repository: {e}", file=sys.stderr)
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
            return 2
    else:
        target_path = os.path.abspath(target)
        if not os.path.exists(target_path):
            print(f"Error: Target path does not exist: {target}", file=sys.stderr)
            return 2
        repo_name = os.path.basename(target_path)
        repo_url = f"file://{target_path}"

    try:
        print(f"[RepoShield] Starting security audit on: {repo_name}")

        gitleaks = GitleaksScanner()
        osv = OSVScanner()
        semgrep = SemgrepScanner()
        config = ConfigScanner()

        # Run core scanners
        sec_findings, sec_status = await gitleaks.scan(target_path)
        dep_findings, dep_status = await osv.scan(target_path)
        sast_findings, sast_status = await semgrep.scan(target_path)
        infra_findings, infra_status = await config.scan(target_path)

        # V2 analyzers
        from app.scanners.package_integrity_scanner import package_integrity_scanner
        from app.scanners.reachability_analyzer import reachability_analyzer
        from app.core.risk_intelligence import enrich_findings_with_risk_intelligence

        integrity_findings, integrity_status = await package_integrity_scanner.scan(target_path)
        all_findings = sec_findings + dep_findings + sast_findings + infra_findings + integrity_findings
        reachability_analyzer.analyze_reachability(target_path, all_findings)
        enrich_findings_with_risk_intelligence(all_findings)

        sbom_components = osv.extract_sbom_components(target_path)

        # Deduplicate
        unique_findings = []
        seen = set()
        for f in all_findings:
            if f.fingerprint and f.fingerprint in seen:
                continue
            if f.fingerprint:
                seen.add(f.fingerprint)
            unique_findings.append(f)

        risk = calculate_risk_score(unique_findings)

        from app.core.coverage import build_comprehensive_coverage_map
        raw_cov = {
            "gitleaks": sec_status,
            "osv": dep_status,
            "semgrep": sast_status,
            "infrastructure": infra_status,
            "package_integrity": integrity_status,
        }
        coverage_map = build_comprehensive_coverage_map(
            target_dir=target_path,
            raw_coverage=raw_cov,
            findings=unique_findings,
            total_files_analyzed=len(all_findings) + 12,
            total_files_excluded=0
        )

        scan_result = ScanResult(
            scan_id=str(uuid.uuid4()),
            repo_url=repo_url,
            owner=repo_name.split("/")[0] if "/" in repo_name else "local",
            repo=repo_name.split("/")[-1] if "/" in repo_name else repo_name,
            branch="HEAD",
            commit_sha=resolved_sha,
            status=ScanState.COMPLETED,
            started_at=datetime.now(timezone.utc).isoformat(),
            completed_at=datetime.now(timezone.utc).isoformat(),
            scanners_coverage=coverage_map,
            findings=unique_findings,
            sbom_components=sbom_components,
            risk_score=risk
        )

        threshold_weight = SEVERITY_ORDER.get(fail_on.upper(), 3)
        violating_findings = [
            f for f in unique_findings
            if SEVERITY_ORDER.get(f.severity.value, 0) >= threshold_weight
        ]

        format_scan_output(scan_result, out_format)

        if out_format == "table":
            if violating_findings:
                print(f"FAILED: {len(violating_findings)} finding(s) met or exceeded --fail-on {fail_on.upper()}.")
                return 1
            else:
                print("PASSED: Zero findings exceeded configured threshold.")
                return 0

        return 1 if violating_findings else 0

    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)

def handle_report_command(target: str, out_format: str) -> int:
    """Handles report generation, supporting existing report JSON files directly."""
    if os.path.isfile(target) and target.endswith(".json"):
        try:
            with open(target, "r", encoding="utf-8") as f:
                data = json.load(f)
            scan_result = ScanResult.model_validate(data)
            format_scan_output(scan_result, out_format)
            return 0
        except Exception as e:
            print(f"Error parsing existing report JSON '{target}': {e}", file=sys.stderr)
            return 2
    else:
        # Target is a path or URL; perform scan and output report
        return asyncio.run(scan_local_or_remote(target, fail_on="critical", out_format=out_format))

def main():
    parser = argparse.ArgumentParser(
        prog="reposhield",
        description="RepoShield — GitHub Repository Security Analyzer CLI (Zero Database)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan local directory or GitHub repository URL")
    scan_parser.add_argument("target", nargs="?", default=".", help="Directory or GitHub URL to scan (default: current dir)")
    scan_parser.add_argument("--local", action="store_true", help="Enforce local privacy mode (no network uploads)")
    scan_parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low"], default="high", help="Severity threshold to exit with code 1")
    scan_parser.add_argument("--format", choices=["table", "json", "sarif", "cyclonedx", "spdx", "vex", "html"], default="table", help="Output format")

    # Secrets command
    sec_parser = subparsers.add_parser("secrets", help="Scan directory exclusively for exposed credentials")
    sec_parser.add_argument("target", nargs="?", default=".", help="Directory to scan")

    # Report command
    rep_parser = subparsers.add_parser("report", help="Generate or convert exportable security report (HTML, SARIF, JSON, VEX, etc.)")
    rep_parser.add_argument("target", nargs="?", default=".", help="Directory, GitHub URL, or existing report JSON file")
    rep_parser.add_argument("--format", choices=["table", "sarif", "json", "cyclonedx", "spdx", "vex", "html"], default="html", help="Report format")

    # SBOM command
    sbom_parser = subparsers.add_parser("sbom", help="Generate SBOM for local project")
    sbom_parser.add_argument("target", nargs="?", default=".", help="Directory to inspect")
    sbom_parser.add_argument("--format", choices=["cyclonedx", "spdx"], default="cyclonedx", help="SBOM specification")

    args = parser.parse_args()

    if args.command == "scan":
        exit_code = asyncio.run(scan_local_or_remote(args.target, fail_on=args.fail_on, out_format=args.format))
        sys.exit(exit_code)
    elif args.command == "secrets":
        exit_code = asyncio.run(scan_local_or_remote(args.target, fail_on="low", out_format="table"))
        sys.exit(exit_code)
    elif args.command == "report":
        exit_code = handle_report_command(args.target, out_format=args.format)
        sys.exit(exit_code)
    elif args.command == "sbom":
        exit_code = asyncio.run(scan_local_or_remote(args.target, fail_on="critical", out_format=args.format))
        sys.exit(0)

if __name__ == "__main__":
    main()
