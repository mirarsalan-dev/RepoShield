import asyncio
import json
import os
import re
import shutil
import tempfile
import time
import uuid
from typing import Optional
from app.models.finding import Finding, Severity, Category, Confidence, compute_finding_fingerprint
from app.models.scan import ScannerExecutionStatus
from app.scanners.base import BaseScanner
from app.utils.redaction import redact_secret_string, redact_text
from app.core.security import safe_run_subprocess

GITLEAKS_RULES = [
    {
        "id": "aws-access-token",
        "name": "AWS Access Key ID",
        "pattern": re.compile(r'\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b'),
        "severity": Severity.CRITICAL,
        "description": "Exposed AWS Access Key ID detected. An attacker can use this identifier with associated secret keys to access cloud infrastructure.",
        "remediation": "Revoke this access key immediately in the AWS IAM Console, audit CloudTrail logs for unauthorized API calls, and use AWS Secrets Manager or IAM Roles instead.",
        "cwe": "CWE-798",
        "impact": "Exposes AWS infrastructure to unauthorized resource provisioning, data exfiltration, and compute theft.",
        "secure_example": "import boto3\n# Use IAM Instance Roles or AWS Secrets Manager rather than static keys\nsession = boto3.Session()"
    },
    {
        "id": "aws-secret-key",
        "name": "AWS Secret Access Key",
        "pattern": re.compile(r'(?i)aws_?(?:secret)?_?(?:access)?_?(?:key)?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']'),
        "severity": Severity.CRITICAL,
        "description": "Potential AWS Secret Access Key discovered. Compromised secret keys grant programmatic control over AWS services.",
        "remediation": "Revoke the compromised credentials in AWS IAM immediately. Rotate all exposed credentials and implement least-privilege IAM policies.",
        "cwe": "CWE-798",
        "impact": "Full programmatic API access to AWS cloud resources matching IAM user privileges.",
        "secure_example": "import os\naws_secret = os.environ.get('AWS_SECRET_ACCESS_KEY')"
    },
    {
        "id": "github-pat",
        "name": "GitHub Personal Access Token",
        "pattern": re.compile(r'\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b'),
        "severity": Severity.CRITICAL,
        "description": "Exposed GitHub Personal Access Token. Can allow malicious actors to access private repositories, push malicious code, or modify workflow secrets.",
        "remediation": "Revoke the token immediately in GitHub Settings > Developer settings > Personal access tokens. Review audit logs for unauthorized repository activity.",
        "cwe": "CWE-798",
        "impact": "Grants unauthorized push access, source code theft, and CI/CD secret manipulation.",
        "secure_example": "import os\ngithub_token = os.environ.get('GITHUB_TOKEN')"
    },
    {
        "id": "github-fine-grained-pat",
        "name": "GitHub Fine-Grained Personal Access Token",
        "pattern": re.compile(r'\b(github_pat_[A-Za-z0-9_]{82})\b'),
        "severity": Severity.CRITICAL,
        "description": "Exposed GitHub Fine-Grained Personal Access Token with specific repository scopes.",
        "remediation": "Revoke this token immediately from GitHub Settings > Developer settings > Fine-grained tokens.",
        "cwe": "CWE-798",
        "impact": "Scoped access to selected GitHub repositories and organization actions.",
        "secure_example": "import os\npat = os.environ.get('GITHUB_PAT')"
    },
    {
        "id": "slack-token",
        "name": "Slack API / Bot Token",
        "pattern": re.compile(r'\b(xox[baprs]-[0-9A-Za-z]{10,48}-[0-9A-Za-z]{10,48}-[0-9A-Za-z]{24,48})\b'),
        "severity": Severity.HIGH,
        "description": "Exposed Slack API or bot token. Attackers can read private messages, impersonate bots, or exfiltrate workspace data.",
        "remediation": "Regenerate or revoke the token from the Slack App Management console. Store tokens in environment variables or a vault.",
        "cwe": "CWE-798",
        "impact": "Unauthorized reading and sending of team communications, file downloads, and workspace reconnaissance.",
        "secure_example": "import os\nslack_token = os.environ.get('SLACK_BOT_TOKEN')"
    },
    {
        "id": "stripe-secret-key",
        "name": "Stripe Live API Key",
        "pattern": re.compile(r'\b([sr]k_(?:live|test)_[0-9a-zA-Z]{24,34})\b'),
        "severity": Severity.CRITICAL,
        "description": "Exposed Stripe Live Secret Key. Allows unauthorized transactions, refund manipulation, and access to customer billing information.",
        "remediation": "Roll the secret key immediately in the Stripe Dashboard under Developers > API keys. Review recent charges and webhook endpoints.",
        "cwe": "CWE-798",
        "impact": "Financial loss through fraudulent charges, chargeback manipulation, and customer PII leakage.",
        "secure_example": "import os, stripe\nstripe.api_key = os.environ.get('STRIPE_SECRET_KEY')"
    },
    {
        "id": "openai-api-key",
        "name": "OpenAI API Key",
        "pattern": re.compile(r'\b(sk-[a-zA-Z0-9]{20,50}|sk-proj-[a-zA-Z0-9-_]{40,120})\b'),
        "severity": Severity.HIGH,
        "description": "Exposed OpenAI API key. Can lead to unauthorized resource exhaustion, financial billing spikes, and prompt leakage.",
        "remediation": "Revoke the key immediately in your OpenAI account dashboard under API Keys, and inject it via secured environment variables.",
        "cwe": "CWE-798",
        "impact": "Financial exhaustion on linked payment accounts and unauthorized LLM model queries.",
        "secure_example": "import os\nopenai_key = os.environ.get('OPENAI_API_KEY')"
    },
    {
        "id": "google-api-key",
        "name": "Google Cloud API Key",
        "pattern": re.compile(r'\b(AIza[0-9A-Za-z-_]{35})\b'),
        "severity": Severity.MEDIUM,
        "description": "Exposed Google Cloud API Key. Depending on API restrictions, may allow unauthorized access to Maps, Firebase, or Google Cloud APIs.",
        "remediation": "Restrict the key in Google Cloud Console > APIs & Services > Credentials (by HTTP referrer, IP, or specific API) or regenerate it.",
        "cwe": "CWE-798",
        "impact": "Quota theft, potential Firebase database queries, or Maps billing spikes.",
        "secure_example": "const gmapKey = process.env.NEXT_PUBLIC_GOOGLE_MAPS_KEY;"
    },
    {
        "id": "private-key",
        "name": "Asymmetric Private Key",
        "pattern": re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
        "severity": Severity.CRITICAL,
        "description": "Exposed cryptographic private key. Anyone with this key can decrypt sensitive communications or impersonate your servers or developers.",
        "remediation": "Immediately remove the private key from the repository, revoke the associated public certificate or authorized SSH keys, and issue new keypairs.",
        "cwe": "CWE-321",
        "impact": "Complete cryptographic compromise, TLS identity spoofing, and SSH server access.",
        "secure_example": "# Store private key in /etc/ssl/private/ or inject through SSH agent / Vault"
    },
    {
        "id": "generic-secret-assignment",
        "name": "Hardcoded Secret / Password",
        "pattern": re.compile(r'(?i)\b(?:password|passwd|api_secret|client_secret|db_password)\s*[:=]\s*["\']([^"\'\s]{8,64})["\']'),
        "severity": Severity.HIGH,
        "description": "Hardcoded password or application secret found in source code or configuration files.",
        "remediation": "Extract secrets into environment variables (.env files excluded via .gitignore) or use a dedicated secrets manager like HashiCorp Vault or AWS Secrets Manager.",
        "cwe": "CWE-798",
        "impact": "Unauthorized access to internal application components or databases.",
        "secure_example": "const dbPassword = process.env.DB_PASSWORD;"
    }
]

IGNORE_DIRS = {'.git', 'node_modules', 'dist', 'build', '.venv', 'venv', '__pycache__', '.next', 'vendor'}
IGNORE_EXTS = {'.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.tar', '.gz', '.woff', '.woff2', '.ttf', '.eot', '.exe', '.dll', '.so', '.dylib', '.pyc', '.class'}

class GitleaksScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "Gitleaks Secret Scanner"

    @property
    def tool_version(self) -> str:
        cli_path = shutil.which("gitleaks")
        if cli_path:
            return "Gitleaks CLI (native)"
        return "Gitleaks Engine v8.18 (Built-in)"

    async def is_available(self) -> tuple[bool, str]:
        cli_path = shutil.which("gitleaks")
        if cli_path:
            return True, f"Native Gitleaks binary discovered at {cli_path}"
        return True, "Built-in Gitleaks Rule Engine active (High-accuracy regex suite)"

    async def scan(self, target_dir: str) -> tuple[list[Finding], ScannerExecutionStatus]:
        start_time = time.time()
        findings: list[Finding] = []
        scanner_status = "SUCCESS"
        error_msg = None

        cli_path = shutil.which("gitleaks")
        if cli_path:
            try:
                findings = await self._run_native_gitleaks(cli_path, target_dir)
            except Exception as e:
                error_msg = f"Native Gitleaks error: {str(e)}. Falling back to built-in rules."
                findings = await self._run_builtin_rule_engine(target_dir)
                scanner_status = "PARTIAL"
        else:
            findings = await self._run_builtin_rule_engine(target_dir)

        duration = round(time.time() - start_time, 2)
        return findings, ScannerExecutionStatus(
            scanner_name="Gitleaks Scanner",
            tool_version=self.tool_version,
            status=scanner_status,
            duration_seconds=duration,
            findings_count=len(findings),
            error_message=error_msg
        )

    async def _run_native_gitleaks(self, cli_path: str, target_dir: str) -> list[Finding]:
        report_file = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        report_path = report_file.name
        report_file.close()

        try:
            cmd = [
                cli_path,
                "detect",
                "--source", target_dir,
                "--no-git",
                "--report-format", "json",
                "--report-path", report_path,
                "--redact"
            ]

            code, stdout, stderr = safe_run_subprocess(cmd, timeout=30)

            findings: list[Finding] = []
            if os.path.exists(report_path) and os.path.getsize(report_path) > 0:
                with open(report_path, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)

                if isinstance(data, list):
                    for item in data:
                        file_raw = item.get("File", "")
                        rel_path = os.path.relpath(os.path.join(target_dir, file_raw), target_dir).replace("\\", "/")
                        rule_id = item.get("RuleID", "generic-secret")
                        secret_val = item.get("Secret", "")
                        match_val = item.get("Match", "")
                        line_start = item.get("StartLine", 1)

                        fingerprint = compute_finding_fingerprint(
                            category="SECRETS",
                            detector_name="Gitleaks CLI",
                            rule_id=f"gitleaks:{rule_id}",
                            file_path=rel_path,
                            line_start=line_start
                        )

                        patch = (
                            f"--- a/{rel_path}\n"
                            f"+++ b/{rel_path}\n"
                            f"@@ -{line_start},1 +{line_start},1 @@\n"
                            f"- {redact_text(match_val if match_val else secret_val)}\n"
                            f"+ process.env.SECRET_KEY // Load securely from environment\n"
                        )

                        findings.append(Finding(
                            id=str(uuid.uuid4()),
                            fingerprint=fingerprint,
                            title=f"Exposed Credential: {item.get('Description', rule_id)}",
                            description=f"Secret detected by Gitleaks detector '{rule_id}'. Storing credentials in plain text poses critical security exposure.",
                            category=Category.SECRETS,
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            raw_severity="CRITICAL",
                            file_path=rel_path,
                            line_start=line_start,
                            line_end=item.get("EndLine"),
                            detector_name="Gitleaks CLI",
                            rule_id=f"gitleaks:{rule_id}",
                            evidence=redact_text(match_val if match_val else secret_val),
                            remediation="Revoke and rotate this secret immediately in the issuing service. Remove from repository history and inject via environment variables.",
                            cwe_id="CWE-798",
                            technical_impact="Compromised credentials permit unauthorized identity assumption, data exfiltration, and lateral infrastructure movement.",
                            secure_code_example="import os\napi_key = os.environ.get('SERVICE_API_KEY')",
                            suggested_patch=patch
                        ))
            return findings
        finally:
            if os.path.exists(report_path):
                try:
                    os.remove(report_path)
                except OSError:
                    pass

    async def _run_builtin_rule_engine(self, target_dir: str) -> list[Finding]:
        findings = []

        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith('.')]

            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in IGNORE_EXTS or file.startswith('.'):
                    continue

                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, target_dir).replace("\\", "/")

                try:
                    if os.path.getsize(file_path) > 2 * 1024 * 1024:
                        continue
                except OSError:
                    continue

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                except Exception:
                    continue

                content = "".join(lines)

                for rule in GITLEAKS_RULES:
                    if rule["id"] == "private-key":
                        if rule["pattern"].search(content):
                            line_num = 1
                            for idx, line in enumerate(lines, 1):
                                if "BEGIN" in line and "PRIVATE KEY" in line:
                                    line_num = idx
                                    break
                            
                            fingerprint = compute_finding_fingerprint(
                                category="SECRETS",
                                detector_name="Gitleaks Engine",
                                rule_id=f"gitleaks:{rule['id']}",
                                file_path=rel_path,
                                line_start=line_num
                            )

                            findings.append(Finding(
                                id=str(uuid.uuid4()),
                                fingerprint=fingerprint,
                                title=f"Exposed {rule['name']}",
                                description=rule["description"],
                                category=Category.SECRETS,
                                severity=rule["severity"],
                                confidence=Confidence.HIGH,
                                raw_severity="CRITICAL",
                                file_path=rel_path,
                                line_start=line_num,
                                line_end=line_num + 5,
                                detector_name="Gitleaks Engine",
                                rule_id=f"gitleaks:{rule['id']}",
                                evidence="-----BEGIN PRIVATE KEY-----\n*** REDACTED PRIVATE KEY CONTENT ***\n-----END PRIVATE KEY-----",
                                remediation=rule["remediation"],
                                cwe_id=rule.get("cwe", "CWE-321"),
                                technical_impact=rule.get("impact", "Private key exposure compromises encryption identity."),
                                secure_code_example=rule.get("secure_example", "Use filesystem keystore with restricted 0600 permissions.")
                            ))
                        continue

                    for line_idx, line in enumerate(lines, start=1):
                        match = rule["pattern"].search(line)
                        if match:
                            raw_val = match.group(1) if match.groups() else match.group(0)
                            if "EXAMPLE" in raw_val.upper() or "PLACEHOLDER" in raw_val.upper() or "YOUR_API_KEY" in raw_val.upper():
                                continue
                            if len(raw_val.strip()) < 8:
                                continue

                            redacted_evidence = redact_text(line.strip())

                            fingerprint = compute_finding_fingerprint(
                                category="SECRETS",
                                detector_name="Gitleaks Engine",
                                rule_id=f"gitleaks:{rule['id']}",
                                file_path=rel_path,
                                line_start=line_idx
                            )

                            patch = (
                                f"--- a/{rel_path}\n"
                                f"+++ b/{rel_path}\n"
                                f"@@ -{line_idx},1 +{line_idx},1 @@\n"
                                f"- {redacted_evidence}\n"
                                f"+ const apiKey = process.env.API_KEY; // Injected via environment variable\n"
                            )

                            findings.append(Finding(
                                id=str(uuid.uuid4()),
                                fingerprint=fingerprint,
                                title=f"Exposed Secret: {rule['name']}",
                                description=rule["description"],
                                category=Category.SECRETS,
                                severity=rule["severity"],
                                confidence=Confidence.HIGH,
                                raw_severity=rule["severity"].value,
                                file_path=rel_path,
                                line_start=line_idx,
                                line_end=line_idx,
                                detector_name="Gitleaks Engine",
                                rule_id=f"gitleaks:{rule['id']}",
                                evidence=redacted_evidence,
                                remediation=rule["remediation"],
                                cwe_id=rule.get("cwe", "CWE-798"),
                                technical_impact=rule.get("impact", "Permits unauthorized account access."),
                                secure_code_example=rule.get("secure_example", "const secret = process.env.SECRET;"),
                                suggested_patch=patch,
                                is_historical=False,
                                remains_in_head=True,
                                attack_path_node_type="CREDENTIAL_EXPOSURE",
                                beginner_explanation=f"This file exposes a secret credential ({rule['name']}). Anyone with repository read access can impersonate your system.",
                                developer_explanation=f"Hardcoded secret detected at line {line_idx}. Remove this credential, revoke it in your provider dashboard, and inject it via environment variables or a secrets manager.",
                                security_engineer_explanation=f"CWE-798: Static credential exposure in source code. Enables instant authentication bypass without requiring exploit delivery. Immediate revocation is mandatory."
                            ))

        # If .git exists, automatically scan commit history
        if os.path.isdir(os.path.join(target_dir, ".git")):
            history_findings = self.scan_git_history(target_dir)
            seen_fps = {f.fingerprint for f in findings}
            for hf in history_findings:
                if hf.fingerprint not in seen_fps:
                    findings.append(hf)
                    seen_fps.add(hf.fingerprint)

        return findings

    def scan_git_history(self, target_dir: str, max_commits: int = 40) -> list[Finding]:
        """
        Scans Git commit history for leaked secrets across commit diffs.
        Determines whether the secret is still present in HEAD or was deleted in subsequent commits.
        """
        git_dir = os.path.join(target_dir, ".git")
        if not os.path.isdir(git_dir):
            return []

        git_cmd = ["git", "log", f"-n{max_commits}", "--pretty=format:@@@COMMIT@@@%H|%an|%ad", "--date=short", "-p"]
        code, stdout, stderr = safe_run_subprocess(git_cmd, cwd=target_dir, timeout=45)
        if code != 0 or not stdout:
            return []

        return self._parse_git_commit_stream(target_dir, stdout)

    def scan_commit_diffs(self, target_dir: str, commits: list[dict]) -> list[Finding]:
        """
        Analyzes commit patches fetched via GitHub API for hosted repository scans.
        Commits list: [{'sha': str, 'author': str, 'date': str, 'patch': str, 'filename': str}]
        """
        findings: list[Finding] = []
        for c in commits:
            patch = c.get("patch", "")
            sha = c.get("sha", "")
            author = c.get("author", "Unknown Author")
            date = c.get("date", "")
            filename = c.get("filename", "")
            if not patch:
                continue

            lines = patch.splitlines()
            for line_idx, line in enumerate(lines, 1):
                if not line.startswith("+") or line.startswith("+++"):
                    continue
                added_line = line[1:].strip()
                for rule in GITLEAKS_RULES:
                    match = rule["pattern"].search(added_line)
                    if match:
                        raw_val = match.group(1) if match.groups() else match.group(0)
                        if "EXAMPLE" in raw_val.upper() or "PLACEHOLDER" in raw_val.upper() or len(raw_val.strip()) < 8:
                            continue

                        remains = self._check_if_in_head(target_dir, filename, rule["pattern"])
                        redacted = redact_text(added_line)
                        fp = compute_finding_fingerprint("SECRETS", "Gitleaks Git History", f"gitleaks:hist:{rule['id']}:{sha[:7]}", filename, line_idx)

                        findings.append(Finding(
                            id=str(uuid.uuid4()),
                            fingerprint=fp,
                            title=f"Git History Secret: {rule['name']} ({sha[:7]})",
                            description=f"Secret detected in commit {sha[:7]} by {author} on {date}. " +
                                        ("WARNING: Credential is STILL present in current HEAD!" if remains else "Credential was removed from HEAD, but permanently remains in Git history."),
                            category=Category.SECRETS,
                            severity=rule["severity"],
                            confidence=Confidence.HIGH,
                            raw_severity="CRITICAL",
                            file_path=filename or "git-history",
                            line_start=line_idx,
                            line_end=line_idx,
                            detector_name="Gitleaks Git History",
                            rule_id=f"gitleaks:hist:{rule['id']}",
                            evidence=redacted,
                            remediation=(
                                f"1) Revoke and rotate this credential immediately in the issuing service. "
                                f"2) Explain to team: removing from latest commit does not delete it from history. "
                                f"3) Rewrite repository history using 'git-filter-repo' or 'BFG Repo-Cleaner' if the repo is shared."
                            ),
                            cwe_id="CWE-798",
                            technical_impact="Compromised credentials remain perpetually retrievable via commit history.",
                            secure_code_example=rule.get("secure_example", "const secret = process.env.API_KEY;"),
                            is_historical=True,
                            commit_sha=sha,
                            commit_author=author,
                            commit_date=date,
                            remains_in_head=remains,
                            attack_path_node_type="CREDENTIAL_EXPOSURE",
                            beginner_explanation=f"A secret key was committed to this repository in the past by {author}. Even if deleted later, Git remembers every past commit.",
                            developer_explanation=f"Committed in {sha[:7]}. Attackers clone repos and parse commit logs. You must rotate this key immediately and purge it using git-filter-repo.",
                            security_engineer_explanation=f"Historical secret exposure in commit {sha}. Once published, consider credentials burned. Run BFG or git-filter-repo, force push, and immediately revoke credentials with the cloud provider."
                        ))
        return findings

    def _parse_git_commit_stream(self, target_dir: str, stream: str) -> list[Finding]:
        findings: list[Finding] = []
        commits = stream.split("@@@COMMIT@@@")

        for commit_block in commits:
            if not commit_block.strip():
                continue
            lines = commit_block.splitlines()
            header = lines[0].strip()
            header_parts = header.split("|")
            sha = header_parts[0] if len(header_parts) > 0 else "unknown"
            author = header_parts[1] if len(header_parts) > 1 else "unknown"
            date = header_parts[2] if len(header_parts) > 2 else ""

            current_file = ""
            for line in lines[1:]:
                if line.startswith("+++ b/"):
                    current_file = line[6:].strip()
                    continue
                if not line.startswith("+") or line.startswith("+++"):
                    continue

                added_code = line[1:].strip()
                for rule in GITLEAKS_RULES:
                    match = rule["pattern"].search(added_code)
                    if match:
                        raw_val = match.group(1) if match.groups() else match.group(0)
                        if "EXAMPLE" in raw_val.upper() or "PLACEHOLDER" in raw_val.upper() or len(raw_val.strip()) < 8:
                            continue

                        remains = self._check_if_in_head(target_dir, current_file, rule["pattern"])
                        redacted = redact_text(added_code)
                        fp = compute_finding_fingerprint("SECRETS", "Gitleaks Git History", f"gitleaks:hist:{rule['id']}:{sha[:7]}", current_file, 1)

                        findings.append(Finding(
                            id=str(uuid.uuid4()),
                            fingerprint=fp,
                            title=f"Git History Secret: {rule['name']} ({sha[:7]})",
                            description=f"Leaked secret in commit {sha[:7]} by {author} on {date}. " +
                                        ("STILL ACTIVE IN HEAD" if remains else "Purged from HEAD, but permanently present in Git history"),
                            category=Category.SECRETS,
                            severity=rule["severity"],
                            confidence=Confidence.HIGH,
                            raw_severity="CRITICAL",
                            file_path=current_file or "git-history",
                            line_start=1,
                            line_end=1,
                            detector_name="Gitleaks Git History",
                            rule_id=f"gitleaks:hist:{rule['id']}",
                            evidence=redacted,
                            remediation=(
                                f"Rotate this credential immediately. Git history preserves all deleted files. "
                                f"Use 'git-filter-repo' to rewrite commits."
                            ),
                            cwe_id="CWE-798",
                            technical_impact="Credential exposure in Git commit history.",
                            secure_code_example=rule.get("secure_example", "const secret = process.env.API_KEY;"),
                            is_historical=True,
                            commit_sha=sha,
                            commit_author=author,
                            commit_date=date,
                            remains_in_head=remains,
                            attack_path_node_type="CREDENTIAL_EXPOSURE",
                            beginner_explanation=f"A past commit by {author} on {date} added a secret. It remains in Git history forever until purged.",
                            developer_explanation=f"Committed in {sha[:7]}. Rotate the credential immediately, then use git-filter-repo to remove it from repository history.",
                            security_engineer_explanation=f"Historical credential exposure. CWE-798. Revocation required; git commits are immutable without force push."
                        ))
        return findings

    def _check_if_in_head(self, target_dir: str, file_path: str, pattern: re.Pattern) -> bool:
        if not file_path:
            return False
        full_path = os.path.join(target_dir, file_path)
        if not os.path.exists(full_path):
            return False
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                return bool(pattern.search(content))
        except Exception:
            return False
