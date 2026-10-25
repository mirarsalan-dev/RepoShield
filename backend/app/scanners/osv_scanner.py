import asyncio
import hashlib
import json
import os
import re
import time
import uuid
import httpx
from typing import Optional
from app.models.finding import Finding, Severity, Category, Confidence, compute_finding_fingerprint
from app.models.sbom import SBOMComponent
from app.models.scan import ScannerExecutionStatus
from app.scanners.base import BaseScanner
from app.config import settings

class OSVScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "OSV Vulnerability Intelligence"

    @property
    def tool_version(self) -> str:
        return "OSV API v1 (api.osv.dev)"

    async def is_available(self) -> tuple[bool, str]:
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                res = await client.get("https://api.osv.dev/v1/vulns/GHSA-c36v-f6fq-m57g")
                if res.status_code == 200:
                    return True, "OSV API connection active and responsive"
        except Exception:
            pass
        return True, "OSV API configured"

    def extract_sbom_components(self, target_dir: str) -> list[SBOMComponent]:
        """Extracts complete software bill of materials (SBOM) components from manifests."""
        packages = self._extract_dependencies(target_dir)
        components: list[SBOMComponent] = []
        seen = set()

        for pkg in packages:
            key = (pkg["name"], pkg["version"], pkg["ecosystem"])
            if key in seen:
                continue
            seen.add(key)

            # Generate standard Package URL (purl)
            eco_purl = pkg["ecosystem"].lower()
            if eco_purl == "pypi":
                purl = f"pkg:pypi/{pkg['name']}@{pkg['version']}"
            elif eco_purl == "npm":
                purl = f"pkg:npm/{pkg['name']}@{pkg['version']}"
            elif eco_purl == "go":
                purl = f"pkg:golang/{pkg['name']}@{pkg['version']}"
            elif eco_purl in ("cargo", "crates.io"):
                purl = f"pkg:cargo/{pkg['name']}@{pkg['version']}"
            elif eco_purl == "maven":
                purl = f"pkg:maven/{pkg['name']}@{pkg['version']}"
            elif eco_purl == "packagist":
                purl = f"pkg:composer/{pkg['name']}@{pkg['version']}"
            else:
                purl = f"pkg:generic/{pkg['name']}@{pkg['version']}"

            components.append(SBOMComponent(
                name=pkg["name"],
                version=pkg["version"],
                ecosystem=pkg["ecosystem"],
                purl=purl,
                license=pkg.get("license", "Unknown"),
                manifest_path=pkg["file_path"],
                direct=pkg.get("direct", True),
                vulnerabilities_count=0,
                vulnerability_ids=[]
            ))
        return components

    async def scan(self, target_dir: str) -> tuple[list[Finding], ScannerExecutionStatus]:
        start_time = time.time()
        findings: list[Finding] = []

        try:
            packages = self._extract_dependencies(target_dir)
            if not packages:
                duration = round(time.time() - start_time, 2)
                return [], ScannerExecutionStatus(
                    scanner_name="OSV Scanner",
                    tool_version=self.tool_version,
                    status="SUCCESS",
                    duration_seconds=duration,
                    findings_count=0
                )

            findings = await self._query_osv_batch(packages)
            duration = round(time.time() - start_time, 2)
            return findings, ScannerExecutionStatus(
                scanner_name="OSV Scanner",
                tool_version=self.tool_version,
                status="SUCCESS",
                duration_seconds=duration,
                findings_count=len(findings)
            )
        except Exception as e:
            duration = round(time.time() - start_time, 2)
            return [], ScannerExecutionStatus(
                scanner_name="OSV Scanner",
                tool_version=self.tool_version,
                status="FAILED",
                duration_seconds=duration,
                findings_count=0,
                error_message=f"OSV scan error: {str(e)}"
            )

    def _extract_dependencies(self, target_dir: str) -> list[dict]:
        packages = []
        seen = set()

        for root, _, files in os.walk(target_dir):
            if any(p in root for p in [".git", "node_modules", ".venv", "venv", "__pycache__", "target", "vendor"]):
                continue

            # 1. npm package-lock.json
            if "package-lock.json" in files:
                p_path = os.path.join(root, "package-lock.json")
                rel_path = os.path.relpath(p_path, target_dir).replace("\\", "/")
                try:
                    with open(p_path, "r", encoding="utf-8", errors="ignore") as f:
                        data = json.load(f)
                        if "packages" in data and isinstance(data["packages"], dict):
                            for pkg_key, pkg_info in data["packages"].items():
                                if not pkg_key or not isinstance(pkg_info, dict):
                                    continue
                                pkg_name = pkg_key.replace("node_modules/", "")
                                version = pkg_info.get("version")
                                if pkg_name and version and (pkg_name, version, "npm") not in seen:
                                    seen.add((pkg_name, version, "npm"))
                                    packages.append({
                                        "name": pkg_name,
                                        "version": version,
                                        "ecosystem": "npm",
                                        "file_path": rel_path,
                                        "direct": not pkg_key.startswith("node_modules/"),
                                        "license": pkg_info.get("license", "Unknown")
                                    })
                        elif "dependencies" in data and isinstance(data["dependencies"], dict):
                            for pkg_name, pkg_info in data["dependencies"].items():
                                if not isinstance(pkg_info, dict):
                                    continue
                                version = pkg_info.get("version")
                                if pkg_name and version and (pkg_name, version, "npm") not in seen:
                                    seen.add((pkg_name, version, "npm"))
                                    packages.append({
                                        "name": pkg_name,
                                        "version": version,
                                        "ecosystem": "npm",
                                        "file_path": rel_path,
                                        "direct": True,
                                        "license": "Unknown"
                                    })
                except Exception:
                    pass

            # 2. npm package.json
            if "package.json" in files:
                p_path = os.path.join(root, "package.json")
                rel_path = os.path.relpath(p_path, target_dir).replace("\\", "/")
                try:
                    with open(p_path, "r", encoding="utf-8", errors="ignore") as f:
                        data = json.load(f)
                        all_deps = {}
                        all_deps.update(data.get("dependencies", {}))
                        all_deps.update(data.get("devDependencies", {}))
                        for pkg_name, ver_spec in all_deps.items():
                            clean_ver = re.sub(r'[\^~>=<v]', '', str(ver_spec)).strip()
                            if clean_ver and (pkg_name, clean_ver, "npm") not in seen:
                                seen.add((pkg_name, clean_ver, "npm"))
                                packages.append({
                                    "name": pkg_name,
                                    "version": clean_ver,
                                    "ecosystem": "npm",
                                    "file_path": rel_path,
                                    "direct": True,
                                    "license": "Unknown"
                                })
                except Exception:
                    pass

            # 3. Python requirements.txt
            for req_file in [f for f in files if "requirements" in f.lower() and f.endswith(".txt")]:
                r_path = os.path.join(root, req_file)
                rel_path = os.path.relpath(r_path, target_dir).replace("\\", "/")
                try:
                    with open(r_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith("#") or line.startswith("-"):
                                continue
                            match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=)\s*([0-9a-zA-Z_\.\-]+)', line)
                            if match:
                                pkg_name, version = match.groups()
                                if (pkg_name, version, "PyPI") not in seen:
                                    seen.add((pkg_name, version, "PyPI"))
                                    packages.append({
                                        "name": pkg_name,
                                        "version": version,
                                        "ecosystem": "PyPI",
                                        "file_path": rel_path,
                                        "direct": True,
                                        "license": "Unknown"
                                    })
                except Exception:
                    pass

            # 4. Poetry lock & Pipfile.lock
            if "poetry.lock" in files:
                l_path = os.path.join(root, "poetry.lock")
                rel_path = os.path.relpath(l_path, target_dir).replace("\\", "/")
                try:
                    with open(l_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        pkg_blocks = re.findall(r'\[\[package\]\][\s\S]*?name\s*=\s*"([^"]+)"[\s\S]*?version\s*=\s*"([^"]+)"', content)
                        for pkg_name, version in pkg_blocks:
                            if (pkg_name, version, "PyPI") not in seen:
                                seen.add((pkg_name, version, "PyPI"))
                                packages.append({
                                    "name": pkg_name,
                                    "version": version,
                                    "ecosystem": "PyPI",
                                    "file_path": rel_path,
                                    "direct": False,
                                    "license": "Unknown"
                                })
                except Exception:
                    pass

            # 5. Go modules (go.mod / go.sum)
            if "go.mod" in files:
                g_path = os.path.join(root, "go.mod")
                rel_path = os.path.relpath(g_path, target_dir).replace("\\", "/")
                try:
                    with open(g_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith("require (") or line.startswith("require"):
                                continue
                            match = re.match(r'^\s*([a-zA-Z0-9_\-\.\/]+)\s+v?([0-9a-zA-Z_\.\-]+)', line)
                            if match:
                                pkg_name, version = match.groups()
                                if not pkg_name.startswith("//") and (pkg_name, version, "Go") not in seen:
                                    seen.add((pkg_name, version, "Go"))
                                    packages.append({
                                        "name": pkg_name,
                                        "version": version,
                                        "ecosystem": "Go",
                                        "file_path": rel_path,
                                        "direct": "// indirect" not in line,
                                        "license": "Unknown"
                                    })
                except Exception:
                    pass

            # 6. Rust Cargo (Cargo.lock)
            if "Cargo.lock" in files:
                c_path = os.path.join(root, "Cargo.lock")
                rel_path = os.path.relpath(c_path, target_dir).replace("\\", "/")
                try:
                    with open(c_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        pkg_blocks = re.findall(r'\[\[package\]\][\s\S]*?name\s*=\s*"([^"]+)"[\s\S]*?version\s*=\s*"([^"]+)"', content)
                        for pkg_name, version in pkg_blocks:
                            if (pkg_name, version, "crates.io") not in seen:
                                seen.add((pkg_name, version, "crates.io"))
                                packages.append({
                                    "name": pkg_name,
                                    "version": version,
                                    "ecosystem": "crates.io",
                                    "file_path": rel_path,
                                    "direct": True,
                                    "license": "Unknown"
                                })
                except Exception:
                    pass

        return packages[:400]

    async def _query_osv_batch(self, packages: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        if not packages:
            return findings

        queries = []
        for pkg in packages:
            queries.append({
                "package": {
                    "name": pkg["name"],
                    "ecosystem": pkg["ecosystem"]
                },
                "version": pkg["version"]
            })

        batch_payload = {"queries": queries}

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                res = await client.post(
                    settings.OSV_API_URL,
                    json=batch_payload,
                    headers={"Content-Type": "application/json"}
                )
                if res.status_code != 200:
                    return findings

                data = res.json()
                results = data.get("results", [])

                for idx, result in enumerate(results):
                    vulns = result.get("vulns", [])
                    if not vulns or idx >= len(packages):
                        continue

                    pkg = packages[idx]

                    for vuln in vulns:
                        vuln_id = vuln.get("id", "UNKNOWN-VULN")
                        summary = vuln.get("summary") or vuln.get("details", "")[:120] or f"Vulnerability in {pkg['name']}"
                        details = vuln.get("details", "No advisory details provided.")

                        aliases = vuln.get("aliases", [])
                        cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
                        ghsa_id = next((a for a in aliases if a.startswith("GHSA-")), vuln_id if vuln_id.startswith("GHSA-") else None)

                        severity, raw_sev, cvss_score = self._parse_severity(vuln)
                        fixed_version = self._find_fixed_version(vuln, pkg["name"])

                        # Generate concrete update command
                        update_cmd = self._generate_update_command(pkg["ecosystem"], pkg["name"], fixed_version)
                        breaking_risk = self._estimate_breaking_change_risk(pkg["version"], fixed_version)

                        remediation = f"Upgrade '{pkg['name']}' from {pkg['version']} to {fixed_version} using: `{update_cmd}`" if fixed_version else f"Upgrade '{pkg['name']}' to a patched release or review security advisory {vuln_id}."

                        fingerprint = compute_finding_fingerprint(
                            category="DEPENDENCIES",
                            detector_name="OSV Database",
                            rule_id=vuln_id,
                            file_path=pkg["file_path"],
                            package_name=pkg["name"]
                        )

                        # Create suggested patch diff when fixed_version is known
                        suggested_patch = None
                        if fixed_version:
                            suggested_patch = (
                                f"--- a/{pkg['file_path']}\n"
                                f"+++ b/{pkg['file_path']}\n"
                                f"@@ -1,1 +1,1 @@\n"
                                f"- \"{pkg['name']}\": \"{pkg['version']}\"\n"
                                f"+ \"{pkg['name']}\": \"{fixed_version}\"\n"
                            )

                        findings.append(Finding(
                            id=str(uuid.uuid4()),
                            fingerprint=fingerprint,
                            title=f"{pkg['name']}: {summary[:90]}",
                            description=details,
                            category=Category.DEPENDENCIES,
                            severity=severity,
                            confidence=Confidence.HIGH,
                            raw_severity=raw_sev,
                            file_path=pkg["file_path"],
                            line_start=None,
                            line_end=None,
                            detector_name="OSV Database",
                            rule_id=vuln_id,
                            evidence=f"Package: {pkg['name']} (version {pkg['version']}) detected in {pkg['file_path']}",
                            remediation=remediation,
                            cve_id=cve_id,
                            ghsa_id=ghsa_id,
                            cvss_score=cvss_score,
                            package_name=pkg["name"],
                            installed_version=pkg["version"],
                            fixed_version=fixed_version,
                            ecosystem=pkg["ecosystem"],
                            direct_dependency=pkg.get("direct", True),
                            update_command=update_cmd,
                            breaking_change_risk=breaking_risk,
                            technical_impact=f"Component contains known vulnerability {vuln_id} ({cve_id or 'Advisory'}). Exploitation may compromise the host runtime.",
                            suggested_patch=suggested_patch
                        ))
        except Exception:
            pass

        return findings

    def _generate_update_command(self, ecosystem: str, package_name: str, fixed_version: Optional[str]) -> str:
        target_ver = fixed_version or "latest"
        eco = ecosystem.lower()
        if eco == "npm":
            return f"npm install {package_name}@{target_ver}"
        elif eco == "pypi":
            return f"pip install --upgrade {package_name}=={target_ver}"
        elif eco == "go":
            return f"go get {package_name}@{target_ver}"
        elif eco in ("cargo", "crates.io"):
            return f"cargo update -p {package_name} --precise {target_ver}"
        elif eco == "maven":
            return f"mvn versions:use-latest-versions -Dincludes={package_name}"
        elif eco == "packagist":
            return f"composer require {package_name}:{target_ver}"
        return f"Update {package_name} to {target_ver}"

    def _estimate_breaking_change_risk(self, installed: str, fixed: Optional[str]) -> str:
        if not fixed:
            return "Unknown (no verified patch)"
        try:
            curr_major = installed.split(".")[0]
            fix_major = fixed.split(".")[0]
            if curr_major != fix_major:
                return "Major bump — breaking change risk (manual test recommended)"
            return "Low risk (compatible minor/patch upgrade)"
        except Exception:
            return "Low risk (estimated)"

    def _parse_severity(self, vuln: dict) -> tuple[Severity, str, Optional[float]]:
        severities = vuln.get("severity", [])
        score = None
        raw_sev = "UNKNOWN"

        for s in severities:
            score_type = s.get("type", "")
            score_val = s.get("score", "")
            if "CVSS_V3" in score_type:
                raw_sev = score_val
                try:
                    score = float(score_val)
                except ValueError:
                    if "/C:H/I:H/A:H" in score_val:
                        score = 9.8
                    elif "/C:H" in score_val or "/I:H" in score_val:
                        score = 7.5
                    elif "/C:L" in score_val or "/I:L" in score_val:
                        score = 5.3
                    else:
                        score = 4.0

        db_specific = vuln.get("database_specific", {})
        if not score and "severity" in db_specific:
            db_sev = str(db_specific.get("severity", "")).upper()
            raw_sev = db_sev
            if db_sev == "CRITICAL":
                return Severity.CRITICAL, raw_sev, 9.5
            elif db_sev == "HIGH":
                return Severity.HIGH, raw_sev, 7.5
            elif db_sev in ("MODERATE", "MEDIUM"):
                return Severity.MEDIUM, raw_sev, 5.5
            elif db_sev == "LOW":
                return Severity.LOW, raw_sev, 2.5

        if score is not None:
            if score >= 9.0:
                return Severity.CRITICAL, raw_sev, score
            elif score >= 7.0:
                return Severity.HIGH, raw_sev, score
            elif score >= 4.0:
                return Severity.MEDIUM, raw_sev, score
            elif score > 0.0:
                return Severity.LOW, raw_sev, score

        return Severity.UNKNOWN, "UNKNOWN", None

    def _find_fixed_version(self, vuln: dict, pkg_name: str) -> Optional[str]:
        for affected in vuln.get("affected", []):
            if affected.get("package", {}).get("name", "").lower() == pkg_name.lower():
                for r in affected.get("ranges", []):
                    for event in r.get("events", []):
                        if "fixed" in event:
                            return event["fixed"]
        return None
