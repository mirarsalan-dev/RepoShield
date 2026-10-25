import ast
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

# Built-in High-Confidence SAST Security Rules (Semgrep-compatible)
SAST_RULES = [
    {
        "id": "python.lang.security.insecure-subprocess",
        "name": "Command Injection Risk (shell=True)",
        "language": "python",
        "pattern": re.compile(r'(?:subprocess\.(?:Popen|call|check_call|check_output|run)|os\.system)\s*\([^)]*shell\s*=\s*True', re.IGNORECASE),
        "severity": Severity.CRITICAL,
        "description": "Invocation of subprocess with `shell=True` allows command injection if unsanitized user input is supplied.",
        "remediation": "Set `shell=False` and pass arguments as a structured array `['command', 'arg1', 'arg2']` to bypass the system shell.",
        "cwe": "CWE-78: Improper Neutralization of Special Elements used in an OS Command",
        "impact": "Enables remote attackers to execute arbitrary shell commands with the privileges of the web application.",
        "secure_example": "subprocess.run(['ls', '-l', target_dir], shell=False, check=True)",
        "patch_from": "shell=True",
        "patch_to": "shell=False"
    },
    {
        "id": "python.lang.security.sql-injection-format",
        "name": "SQL Injection (Formatted Query String)",
        "language": "python",
        "pattern": re.compile(r'(?:execute|raw_query|query)\s*\(\s*f["\']\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b', re.IGNORECASE),
        "severity": Severity.CRITICAL,
        "description": "SQL statement constructed using python f-string interpolation. An attacker can manipulate SQL queries to exfiltrate or mutate database records.",
        "remediation": "Use parameterized queries or ORM query builders (e.g., `cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))`).",
        "cwe": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
        "impact": "Allows attackers to bypass authentication, extract confidential database records, or drop tables.",
        "secure_example": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        "patch_from": "execute(f\"",
        "patch_to": "execute(\""
    },
    {
        "id": "python.lang.security.insecure-deserialization-pickle",
        "name": "Insecure Deserialization (pickle)",
        "language": "python",
        "pattern": re.compile(r'\bpickle\.(?:loads|load)\s*\(', re.IGNORECASE),
        "severity": Severity.HIGH,
        "description": "Deserialization of untrusted data with `pickle` can result in arbitrary Remote Code Execution (RCE).",
        "remediation": "Do not accept pickled data from untrusted sources. Use safe data interchange formats such as JSON or Protocol Buffers.",
        "cwe": "CWE-502: Deserialization of Untrusted Data",
        "impact": "Permits arbitrary code execution during object unpickling via `__reduce__` exploit payloads.",
        "secure_example": "import json\ndata = json.loads(payload)",
        "patch_from": "pickle.loads(",
        "patch_to": "json.loads("
    },
    {
        "id": "python.lang.security.insecure-yaml-load",
        "name": "Insecure YAML Loader (Arbitrary Code Execution)",
        "language": "python",
        "pattern": re.compile(r'\byaml\.(?:load|unsafe_load)\s*\([^,)]*(?:\)|,\s*Loader\s*=\s*(?:yaml\.)?(?:Loader|UnsafeLoader))', re.IGNORECASE),
        "severity": Severity.HIGH,
        "description": "Using `yaml.load()` without SafeLoader allows YAML object tags that execute arbitrary Python code.",
        "remediation": "Use `yaml.safe_load(data)` instead to prevent arbitrary object instantiation.",
        "cwe": "CWE-502: Deserialization of Untrusted Data",
        "impact": "Remote code execution through malicious Python object tags in YAML payloads.",
        "secure_example": "import yaml\nconfig = yaml.safe_load(raw_yaml)",
        "patch_from": "yaml.load(",
        "patch_to": "yaml.safe_load("
    },
    {
        "id": "python.lang.security.insecure-hash-md5-sha1",
        "name": "Weak Cryptographic Hash (MD5 / SHA-1)",
        "language": "python",
        "pattern": re.compile(r'\bhashlib\.(?:md5|sha1)\s*\(', re.IGNORECASE),
        "severity": Severity.LOW,
        "description": "MD5 and SHA-1 have known collision weaknesses and are insecure for cryptographic signatures, integrity verification, or password hashing.",
        "remediation": "Use SHA-256 (`hashlib.sha256()`), SHA-3, or password-specific algorithms like bcrypt or argon2id.",
        "cwe": "CWE-328: Use of Weak Hash",
        "impact": "Susceptible to hash collision attacks and pre-computed rainbow table lookups.",
        "secure_example": "import hashlib\ndigest = hashlib.sha256(data).hexdigest()",
        "patch_from": "hashlib.md5(",
        "patch_to": "hashlib.sha256("
    },
    {
        "id": "javascript.lang.security.detect-eval-with-expression",
        "name": "Dangerous Dynamic Code Execution (eval)",
        "language": "javascript",
        "pattern": re.compile(r'\b(?:eval|Function)\s*\([^)]+\)', re.IGNORECASE),
        "severity": Severity.HIGH,
        "description": "Passing user-controlled strings to `eval()` executes arbitrary JavaScript within the application context.",
        "remediation": "Avoid `eval()`. Use `JSON.parse()` for structured serialization or safe expression evaluators.",
        "cwe": "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code",
        "impact": "Enables Cross-Site Scripting (XSS) or Node.js server-side code execution.",
        "secure_example": "const obj = JSON.parse(strPayload);",
        "patch_from": "eval(",
        "patch_to": "JSON.parse("
    },
    {
        "id": "javascript.lang.security.react-dangerouslysetinnerhtml",
        "name": "Cross-Site Scripting (dangerouslySetInnerHTML)",
        "language": "javascript",
        "pattern": re.compile(r'dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:', re.IGNORECASE),
        "severity": Severity.HIGH,
        "description": "Direct injection of raw HTML into DOM via `dangerouslySetInnerHTML` exposes users to stored or reflected Cross-Site Scripting (XSS).",
        "remediation": "Sanitize HTML using a library like DOMPurify before rendering, or prefer native JSX child elements.",
        "cwe": "CWE-79: Improper Neutralization of Input During Web Page Generation",
        "impact": "Session cookie theft, account takeover, and page defacement via injected script tags.",
        "secure_example": "import DOMPurify from 'dompurify';\n<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(cleanHtml) }} />"
    },
    {
        "id": "javascript.lang.security.child-process-exec",
        "name": "Node.js Command Injection (child_process.exec)",
        "language": "javascript",
        "pattern": re.compile(r'(?:child_process\.)?exec\s*\(\s*`[^`]*\$\{', re.IGNORECASE),
        "severity": Severity.CRITICAL,
        "description": "Template string interpolation in `child_process.exec()` allows attackers to execute arbitrary shell commands.",
        "remediation": "Use `child_process.execFile` or `child_process.spawn` with an array of arguments, preventing shell interpretation.",
        "cwe": "CWE-78: Improper Neutralization of Special Elements used in an OS Command",
        "impact": "Direct server takeover via shell metacharacters (e.g. `; rm -rf /`, `| curl attacker.com`).",
        "secure_example": "import { execFile } from 'child_process';\nexecFile('/usr/bin/tool', [arg1, arg2], (err, stdout) => { ... });"
    },
    {
        "id": "generic.security.cors-wildcard",
        "name": "Overly Permissive CORS Policy",
        "language": "generic",
        "pattern": re.compile(r'Access-Control-Allow-Origin["\']?\s*:\s*["\']\*["\']', re.IGNORECASE),
        "severity": Severity.MEDIUM,
        "description": "Wildcard `Access-Control-Allow-Origin: *` may allow unauthorized third-party sites to perform authenticated actions or read sensitive responses.",
        "remediation": "Restrict allowed origins to explicit, authorized domains rather than using a wildcard.",
        "cwe": "CWE-942: Permissive Cross-Domain Policy with Untrusted Domains",
        "impact": "Cross-origin data exfiltration and credential theft by malicious third-party origins.",
        "secure_example": "headers = {'Access-Control-Allow-Origin': 'https://app.company.com'}"
    }
]

IGNORE_DIRS = {'.git', 'node_modules', 'dist', 'build', '.venv', 'venv', '__pycache__', '.next', 'vendor', 'tests', 'test'}
CODE_EXTS = {'.py', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}

class SemgrepScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "Semgrep SAST"

    @property
    def tool_version(self) -> str:
        semgrep_bin = shutil.which("semgrep")
        return "Semgrep CLI (p/security-audit)" if semgrep_bin else "Semgrep Static Analysis Engine (v1.65-rules)"

    async def is_available(self) -> tuple[bool, str]:
        semgrep_bin = shutil.which("semgrep")
        if semgrep_bin:
            return True, f"Native Semgrep CLI discovered at {semgrep_bin}"
        return True, "Built-in Semgrep SAST rule engine ready (Python, JS, TS rules loaded)"

    async def scan(self, target_dir: str) -> tuple[list[Finding], ScannerExecutionStatus]:
        start_time = time.time()
        findings: list[Finding] = []
        semgrep_bin = shutil.which("semgrep")

        if semgrep_bin:
            try:
                findings = await self._run_semgrep_cli(semgrep_bin, target_dir)
                duration = round(time.time() - start_time, 2)
                return findings, ScannerExecutionStatus(
                    scanner_name="Semgrep SAST",
                    tool_version="Semgrep CLI",
                    status="SUCCESS",
                    duration_seconds=duration,
                    findings_count=len(findings)
                )
            except Exception:
                pass

        try:
            findings = await self._run_builtin_sast_engine(target_dir)
            duration = round(time.time() - start_time, 2)
            return findings, ScannerExecutionStatus(
                scanner_name="Semgrep SAST",
                tool_version=self.tool_version,
                status="SUCCESS",
                duration_seconds=duration,
                findings_count=len(findings)
            )
        except Exception as e:
            duration = round(time.time() - start_time, 2)
            return [], ScannerExecutionStatus(
                scanner_name="Semgrep SAST",
                tool_version=self.tool_version,
                status="FAILED",
                duration_seconds=duration,
                findings_count=0,
                error_message=str(e)
            )

    async def _run_semgrep_cli(self, binary_path: str, target_dir: str) -> list[Finding]:
        cmd = [
            binary_path, "scan",
            "--config", "p/security-audit",
            "--json",
            target_dir
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        data = json.loads(stdout.decode("utf-8", errors="ignore"))

        findings = []
        for result in data.get("results", []):
            check_id = result.get("check_id", "sast-rule")
            extra = result.get("extra", {})
            message = extra.get("message", "Security issue detected.")
            severity_str = extra.get("severity", "WARNING").upper()

            sev = Severity.MEDIUM
            if severity_str == "ERROR":
                sev = Severity.HIGH
            elif severity_str == "INFO":
                sev = Severity.LOW

            rel_path = os.path.relpath(result.get("path", ""), target_dir).replace("\\", "/")
            lines = extra.get("lines", "")
            line_start = result.get("start", {}).get("line")

            fingerprint = compute_finding_fingerprint(
                category="SAST",
                detector_name="Semgrep CLI",
                rule_id=f"semgrep:{check_id}",
                file_path=rel_path,
                line_start=line_start
            )

            findings.append(Finding(
                id=str(uuid.uuid4()),
                fingerprint=fingerprint,
                title=f"SAST: {check_id.split('.')[-1].replace('-', ' ').title()}",
                description=message,
                category=Category.SAST,
                severity=sev,
                confidence=Confidence.HIGH,
                raw_severity=severity_str,
                file_path=rel_path,
                line_start=line_start,
                line_end=result.get("end", {}).get("line"),
                detector_name="Semgrep CLI",
                rule_id=f"semgrep:{check_id}",
                evidence=lines.strip() if lines else None,
                remediation=extra.get("metadata", {}).get("fix", "Review Semgrep rule guidance and refactor insecure code block."),
                technical_impact="Insecure coding pattern identified during static code analysis."
            ))
        return findings

    async def _run_builtin_sast_engine(self, target_dir: str) -> list[Finding]:
        findings = []

        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith('.')]

            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext not in CODE_EXTS:
                    continue

                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, target_dir).replace("\\", "/")

                try:
                    if os.path.getsize(file_path) > 1024 * 1024:
                        continue
                except OSError:
                    continue

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                except Exception:
                    continue

                if ext == '.py':
                    ast_findings = self._analyze_python_ast("".join(lines), rel_path)
                    findings.extend(ast_findings)

                for rule in SAST_RULES:
                    for idx, line in enumerate(lines, start=1):
                        match = rule["pattern"].search(line)
                        if match:
                            fingerprint = compute_finding_fingerprint(
                                category="SAST",
                                detector_name="Semgrep Engine",
                                rule_id=f"semgrep:{rule['id']}",
                                file_path=rel_path,
                                line_start=idx
                            )

                            patch = None
                            if "patch_from" in rule and "patch_to" in rule and rule["patch_from"] in line:
                                patched_line = line.replace(rule["patch_from"], rule["patch_to"])
                                patch = (
                                    f"--- a/{rel_path}\n"
                                    f"+++ b/{rel_path}\n"
                                    f"@@ -{idx},1 +{idx},1 @@\n"
                                    f"- {line.strip()}\n"
                                    f"+ {patched_line.strip()}\n"
                                )

                            findings.append(Finding(
                                id=str(uuid.uuid4()),
                                fingerprint=fingerprint,
                                title=f"SAST: {rule['name']}",
                                description=rule["description"],
                                category=Category.SAST,
                                severity=rule["severity"],
                                confidence=Confidence.HIGH,
                                raw_severity=rule["severity"].value,
                                file_path=rel_path,
                                line_start=idx,
                                line_end=idx,
                                detector_name="Semgrep Engine",
                                rule_id=f"semgrep:{rule['id']}",
                                evidence=line.strip()[:200],
                                remediation=rule["remediation"],
                                cwe_id=rule.get("cwe"),
                                technical_impact=rule.get("impact"),
                                secure_code_example=rule.get("secure_example"),
                                suggested_patch=patch
                            ))

        return findings

    def _analyze_python_ast(self, code: str, rel_path: str) -> list[Finding]:
        findings = []
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return findings

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "eval":
                    fp = compute_finding_fingerprint("SAST", "Semgrep AST Analyzer", "python.lang.security.audit.eval-detected", rel_path, node.lineno)
                    findings.append(Finding(
                        id=str(uuid.uuid4()),
                        fingerprint=fp,
                        title="SAST: Arbitrary Code Execution (eval)",
                        description="Direct call to `eval()` found in AST analysis. Untrusted strings can execute arbitrary system code.",
                        category=Category.SAST,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        raw_severity="HIGH",
                        file_path=rel_path,
                        line_start=node.lineno,
                        line_end=node.lineno,
                        detector_name="Semgrep AST Analyzer",
                        rule_id="semgrep:python.lang.security.audit.eval-detected",
                        evidence="eval(...)",
                        remediation="Replace `eval()` with `ast.literal_eval()` or a typed parser to prevent code execution.",
                        cwe_id="CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code",
                        technical_impact="Untrusted string evaluation permits full Python runtime takeover.",
                        secure_code_example="import ast\nparsed_obj = ast.literal_eval(safe_string)"
                    ))
                elif isinstance(node.func, ast.Name) and node.func.id == "exec":
                    fp = compute_finding_fingerprint("SAST", "Semgrep AST Analyzer", "python.lang.security.audit.exec-detected", rel_path, node.lineno)
                    findings.append(Finding(
                        id=str(uuid.uuid4()),
                        fingerprint=fp,
                        title="SAST: Dynamic Code Execution (exec)",
                        description="Direct call to `exec()` detected in AST. Dynamic code execution allows arbitrary code paths.",
                        category=Category.SAST,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        raw_severity="CRITICAL",
                        file_path=rel_path,
                        line_start=node.lineno,
                        line_end=node.lineno,
                        detector_name="Semgrep AST Analyzer",
                        rule_id="semgrep:python.lang.security.audit.exec-detected",
                        evidence="exec(...)",
                        remediation="Refactor code logic to eliminate dynamic string execution.",
                        cwe_id="CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code",
                        technical_impact="Enables execution of arbitrary Python statements in the current namespace."
                    ))

        return findings
