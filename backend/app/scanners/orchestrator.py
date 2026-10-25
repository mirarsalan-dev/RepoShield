import asyncio
import io
import os
import re
import shutil
import tarfile
import tempfile
import time
import httpx
from datetime import datetime, timezone
from typing import Optional
from app.config import settings
from app.core.security import parse_and_validate_github_url, is_safe_extract_path
from app.core.memory_store import memory_store
from app.core.scoring import calculate_risk_score
from app.models.finding import Finding
from app.models.scan import ScanResult, ScanState, ScannerExecutionStatus
from app.scanners.gitleaks_scanner import GitleaksScanner
from app.scanners.osv_scanner import OSVScanner
from app.scanners.semgrep_scanner import SemgrepScanner
from app.scanners.config_scanner import ConfigScanner
from app.scanners.package_integrity_scanner import package_integrity_scanner
from app.scanners.api_security_scanner import api_security_scanner
from app.scanners.posture_scanner import RepositoryPostureScanner
from app.scanners.reachability_analyzer import reachability_analyzer
from app.core.risk_intelligence import enrich_findings_with_risk_intelligence
from app.services.attack_path_service import attack_path_service

class ScanOrchestrator:
    def __init__(self):
        self.gitleaks = GitleaksScanner()
        self.osv = OSVScanner()
        self.semgrep = SemgrepScanner()
        self.config_scanner = ConfigScanner()
        self.posture_scanner = RepositoryPostureScanner()

    async def execute_scan(
        self,
        scan_id: str,
        repo_url: str,
        branch: Optional[str] = None,
        commit_sha: Optional[str] = None,
        github_token: Optional[str] = None,
        enable_secrets: bool = True,
        enable_dependencies: bool = True,
        enable_sast: bool = True,
        enable_infrastructure: bool = True,
        enable_api_security: bool = True,
        enable_posture: bool = True
    ) -> None:
        """
        Orchestrates an end-to-end security scan in an ephemeral isolated worker environment.
        Ensures strict cleanup of all temporary files and never persists data to any database.
        """
        start_time = time.time()
        owner, repo = parse_and_validate_github_url(repo_url)
        ref = commit_sha or branch or "HEAD"

        scan_result = await memory_store.get_scan(scan_id)
        if not scan_result:
            return

        def log(msg: str):
            timestamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
            scan_result.logs.append(f"[{timestamp}] {msg}")

        temp_dir = tempfile.mkdtemp(prefix="reposhield_scan_")

        try:
            log(f"Initiated scan for {owner}/{repo} (ref: {ref})")
            await memory_store.update_scan(
                scan_id,
                status=ScanState.CLONING,
                progress=10,
                current_step="Downloading repository archive from GitHub API"
            )

            # 1. Download repository tarball securely
            token = github_token or settings.GITHUB_DEFAULT_TOKEN
            extracted_path, resolved_sha = await self._fetch_and_extract_repo(owner, repo, ref, token, temp_dir, log)

            if resolved_sha and not scan_result.commit_sha:
                scan_result.commit_sha = resolved_sha

            all_findings = []
            scanners_coverage = {}

            # 2. Secret Scanning (Gitleaks & Git History)
            if enable_secrets:
                log("Executing Gitleaks secret detection scanner on working tree...")
                await memory_store.update_scan(
                    scan_id,
                    status=ScanState.SCANNING_SECRETS,
                    progress=20,
                    current_step="Scanning for exposed credentials, API keys, and certificates (Gitleaks)"
                )
                sec_findings, sec_status = await self.gitleaks.scan(extracted_path)
                all_findings.extend(sec_findings)
                scanners_coverage["gitleaks"] = sec_status

                # Attempt Git History commit diff analysis via GitHub Commits API
                log("Inspecting recent Git commit history for historical leaks...")
                hist_findings = await self._fetch_and_scan_commit_history(owner, repo, token, extracted_path, log)
                all_findings.extend(hist_findings)
                log(f"Gitleaks scan complete: {len(sec_findings) + len(hist_findings)} secret finding(s) detected.")
            else:
                log("Gitleaks secret detection skipped per scan configuration.")

            # 3. Dependency Vulnerabilities (OSV API & Package Integrity)
            sbom_components = []
            if enable_dependencies:
                log("Auditing dependency manifests against OSV vulnerability intelligence...")
                await memory_store.update_scan(
                    scan_id,
                    status=ScanState.SCANNING_DEPENDENCIES,
                    progress=40,
                    current_step="Auditing manifests against OSV vulnerability database (OSV API)"
                )
                dep_findings, dep_status = await self.osv.scan(extracted_path)
                sbom_components = self.osv.extract_sbom_components(extracted_path)
                all_findings.extend(dep_findings)
                scanners_coverage["osv"] = dep_status

                # Package Integrity & Typosquatting
                log("Auditing packages for typosquatting and suspicious install scripts...")
                integrity_findings, integrity_status = await package_integrity_scanner.scan(extracted_path)
                all_findings.extend(integrity_findings)
                scanners_coverage["package_integrity"] = integrity_status
                log(f"OSV & Supply Chain audit complete: {len(dep_findings) + len(integrity_findings)} finding(s). Discovered {len(sbom_components)} SBOM components.")
            else:
                log("Dependency vulnerability analysis skipped per scan configuration.")

            # 4. Static Application Security Testing (Semgrep)
            if enable_sast:
                log("Running Semgrep static code analysis rules...")
                await memory_store.update_scan(
                    scan_id,
                    status=ScanState.SCANNING_SAST,
                    progress=60,
                    current_step="Performing static application security testing (Semgrep SAST)"
                )
                sast_findings, sast_status = await self.semgrep.scan(extracted_path)
                all_findings.extend(sast_findings)
                scanners_coverage["semgrep"] = sast_status
                log(f"Semgrep SAST complete: {len(sast_findings)} finding(s) in {sast_status.duration_seconds}s")
            else:
                log("Semgrep static code analysis skipped per scan configuration.")

            # 5. Infrastructure and Configuration Auditing
            if enable_infrastructure:
                log("Auditing container Dockerfiles, Kubernetes manifests, and CI/CD workflows...")
                await memory_store.update_scan(
                    scan_id,
                    status=ScanState.SCANNING_INFRASTRUCTURE,
                    progress=75,
                    current_step="Auditing Dockerfiles and CI/CD workflow security (ConfigAudit)"
                )
                infra_findings, infra_status = await self.config_scanner.scan(extracted_path)
                all_findings.extend(infra_findings)
                scanners_coverage["infrastructure"] = infra_status
                log(f"Infrastructure audit complete: {len(infra_findings)} finding(s) in {infra_status.duration_seconds}s")
            else:
                log("Infrastructure auditing skipped per scan configuration.")

            # 6. API Security Analysis
            api_report_data = None
            if enable_api_security:
                log("Auditing OpenAPI specifications and endpoint declarations...")
                api_report, api_findings, api_status = await api_security_scanner.scan(extracted_path)
                all_findings.extend(api_findings)
                scanners_coverage["api_security"] = api_status
                api_report_data = api_report.model_dump()
                log(f"API Security audit complete: {len(api_findings)} finding(s) across {api_report.total_endpoints} endpoint(s)")

            # 7. Repository Security Posture (OpenSSF-aligned)
            posture_report_data = None
            if enable_posture:
                log("Evaluating repository security governance and OpenSSF Scorecard practices...")
                posture_report, posture_findings, posture_status = await self.posture_scanner.evaluate(
                    extracted_path, owner=owner, repo=repo, token=token
                )
                all_findings.extend(posture_findings)
                scanners_coverage["posture"] = posture_status
                posture_report_data = posture_report.model_dump()
                log(f"Repository Security Posture evaluated: {posture_report.score}/100 ({posture_report.level})")

            # 8. Reachability Analysis
            log("Correlating dependency vulnerabilities with application call paths...")
            reachability_analyzer.analyze_reachability(extracted_path, all_findings)

            # 9. Deduplication & Exploitability Risk Prioritization
            log("Applying Risk Intelligence Engine (CISA KEV, EPSS estimation, CVSS)...")
            await memory_store.update_scan(
                scan_id,
                status=ScanState.FINALIZING,
                progress=90,
                current_step="Aggregating findings, risk intelligence, and attack paths"
            )

            # Deduplicate findings by fingerprint
            unique_findings = []
            seen_fps = set()
            for f in all_findings:
                if f.fingerprint and f.fingerprint in seen_fps:
                    continue
                if f.fingerprint:
                    seen_fps.add(f.fingerprint)
                unique_findings.append(f)

            # Enrich with Risk Intelligence (CISA KEV, EPSS, Exploitability P1-P4)
            enrich_findings_with_risk_intelligence(unique_findings)

            # 10. Attack Path Graph Synthesis
            log("Synthesizing evidence-backed Attack Paths...")
            attack_path_graph = attack_path_service.generate_attack_paths(unique_findings)
            attack_path_data = attack_path_graph.model_dump()

            risk_score = calculate_risk_score(unique_findings)
            duration = round(time.time() - start_time, 2)
            completed_at = datetime.now(timezone.utc).isoformat()

            # 11. Security Coverage Map Synthesis (Phase 1)
            total_files = 0
            excluded_files = 0
            for root, dirs, files in os.walk(extracted_path):
                if any(x in root for x in ["node_modules", ".venv", ".git", "__pycache__"]):
                    excluded_files += len(files)
                    continue
                total_files += len(files)

            from app.core.coverage import build_comprehensive_coverage_map
            coverage_map = build_comprehensive_coverage_map(
                target_dir=extracted_path,
                raw_coverage=scanners_coverage,
                findings=unique_findings,
                total_files_analyzed=total_files,
                total_files_excluded=excluded_files
            )

            log(f"Scan finished successfully in {duration}s. Final Risk Index: {risk_score.score}/100 ({risk_score.level})")

            await memory_store.update_scan(
                scan_id,
                status=ScanState.COMPLETED,
                progress=100,
                current_step="Analysis complete",
                completed_at=completed_at,
                scanned_at=completed_at,
                commit_sha=scan_result.commit_sha or resolved_sha,
                duration_seconds=duration,
                findings=unique_findings,
                sbom_components=sbom_components,
                risk_score=risk_score,
                posture_report=posture_report_data,
                attack_path_graph=attack_path_data,
                api_security_report=api_report_data,
                scanners_coverage=coverage_map
            )

        except Exception as e:
            duration = round(time.time() - start_time, 2)
            err_msg = str(e)
            log(f"Scan failed: {err_msg}")
            await memory_store.update_scan(
                scan_id,
                status=ScanState.FAILED,
                progress=100,
                current_step="Scan terminated with error",
                duration_seconds=duration,
                error_detail=err_msg
            )
        finally:
            # STRICT ZERO DATABASE / ISOLATION: Always erase all temporary repository files
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    async def _fetch_and_scan_commit_history(
        self,
        owner: str,
        repo: str,
        token: Optional[str],
        target_dir: str,
        log
    ) -> list[Finding]:
        """
        Retrieves recent commit diffs from GitHub API to inspect historical secret commits.
        Gracefully handles unauthenticated or rate-limited scenarios.
        """
        commits_url = f"https://api.github.com/repos/{owner}/{repo}/commits?per_page=10"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "RepoShield-Security-Scanner/2.0"
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        commit_patches = []
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(commits_url, headers=headers)
                if resp.status_code == 200:
                    commit_list = resp.json()
                    for c_entry in commit_list[:6]:
                        c_sha = c_entry.get("sha", "")
                        c_author = c_entry.get("commit", {}).get("author", {}).get("name", "Unknown")
                        c_date = c_entry.get("commit", {}).get("author", {}).get("date", "")[:10]
                        # Fetch commit detail with diff
                        c_detail_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{c_sha}"
                        detail_resp = await client.get(c_detail_url, headers=headers)
                        if detail_resp.status_code == 200:
                            detail_json = detail_resp.json()
                            files = detail_json.get("files", [])
                            for f in files:
                                patch = f.get("patch", "")
                                fname = f.get("filename", "")
                                if patch:
                                    commit_patches.append({
                                        "sha": c_sha,
                                        "author": c_author,
                                        "date": c_date,
                                        "patch": patch,
                                        "filename": fname
                                    })
                elif resp.status_code == 403:
                    log("GitHub API rate limit prevents commit history diff download; working tree scanned only.")
                    return []
                else:
                    log(f"Commit history scan unavailable for this target (HTTP {resp.status_code}).")
                    return []
        except Exception as e:
            log(f"Git history fetch limitation: {str(e)[:80]}")
            return []

        if commit_patches:
            return self.gitleaks.scan_commit_diffs(target_dir, commit_patches)
        return []

    async def _fetch_and_extract_repo(
        self,
        owner: str,
        repo: str,
        ref: str,
        token: Optional[str],
        dest_dir: str,
        log
    ) -> tuple[str, Optional[str]]:
        """
        Fetches repository tarball archive from GitHub API and extracts it securely with Zip-Slip defense.
        Returns (extracted_root_path, resolved_commit_sha).
        """
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "RepoShield-Security-Scanner/1.0"
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        tarball_url = f"https://api.github.com/repos/{owner}/{repo}/tarball/{ref}"
        log(f"Fetching repository archive from GitHub API: {owner}/{repo}@{ref}")

        async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
            resp = await client.get(tarball_url, headers=headers)
            if resp.status_code == 404:
                raise ValueError(f"Repository '{owner}/{repo}' or reference '{ref}' not found or is private.")
            elif resp.status_code == 403:
                rate_limit = resp.headers.get("x-ratelimit-remaining", "0")
                if rate_limit == "0":
                    raise ValueError("GitHub API rate limit exceeded. Please provide a GitHub Personal Access Token in Settings to proceed.")
                raise ValueError(f"Access forbidden by GitHub API: {resp.text[:150]}")
            elif resp.status_code != 200:
                raise ValueError(f"GitHub API returned error HTTP {resp.status_code}: {resp.text[:150]}")

            content_bytes = resp.content
            size_mb = len(content_bytes) / (1024 * 1024)
            if size_mb > settings.MAX_SCAN_SIZE_MB:
                raise ValueError(f"Repository archive size ({size_mb:.1f}MB) exceeds configured safety limit ({settings.MAX_SCAN_SIZE_MB}MB).")

            log(f"Downloaded {size_mb:.2f}MB archive. Extracting safely...")

            resolved_sha = None
            first_dir = None

            # Extract tarball with strict Path Traversal / Zip-Slip defense
            with tarfile.open(fileobj=io.BytesIO(content_bytes), mode="r:*") as tar:
                for member in tar.getmembers():
                    dest_file_path = os.path.join(dest_dir, member.name)
                    if not is_safe_extract_path(dest_dir, dest_file_path):
                        raise SecurityError(f"Malicious path traversal detected in archive entry: {member.name}")

                    if member.issym() or member.islnk():
                        continue

                    tar.extract(member, path=dest_dir)
                    if not first_dir and member.isdir():
                        parts = member.name.split("/")
                        if parts:
                            first_dir = os.path.join(dest_dir, parts[0])
                            # GitHub tarball root folders follow format: {owner}-{repo}-{commit_sha[:7]}
                            root_name = parts[0]
                            match = re.search(r'-([0-9a-f]{7,40})$', root_name)
                            if match:
                                resolved_sha = match.group(1)

            extracted_root = first_dir if first_dir and os.path.exists(first_dir) else dest_dir
            log(f"Extracted repository files into isolated worker sandbox: {os.path.basename(extracted_root)}")
            return extracted_root, resolved_sha

orchestrator = ScanOrchestrator()
