import os
import re
import time
import uuid
from typing import Optional
from app.models.finding import Finding, Severity, Category, Confidence, compute_finding_fingerprint
from app.models.scan import ScannerExecutionStatus
from app.scanners.base import BaseScanner

INFRA_RULES = [
    # Dockerfile rules
    {
        "id": "dockerfile.security.root-user",
        "name": "Container Running as Root",
        "file_match": lambda f: "dockerfile" in f.lower(),
        "pattern": re.compile(r'^\s*USER\s+(?:root|0)\b', re.IGNORECASE),
        "severity": Severity.MEDIUM,
        "description": "Container image explicitly sets USER to root. Running containers without a non-privileged user increases the blast radius of container escapes.",
        "remediation": "Create and specify an unprivileged application user using `USER nonroot` or `USER 10001` before the ENTRYPOINT/CMD instruction.",
        "cwe": "CWE-250: Execution with Unnecessary Privileges",
        "impact": "If a vulnerability is exploited inside the container, the attacker immediately possesses root capabilities within the container namespace.",
        "secure_example": "RUN groupadd -r appuser && useradd -r -g appuser appuser\nUSER appuser"
    },
    {
        "id": "dockerfile.security.curl-pipe-bash",
        "name": "Dangerous Remote Script Execution (curl | bash)",
        "file_match": lambda f: "dockerfile" in f.lower(),
        "pattern": re.compile(r'(?:curl|wget)\s+[^|]+\|\s*(?:bash|sh)\b', re.IGNORECASE),
        "severity": Severity.HIGH,
        "description": "Piping unverified remote scripts from `curl` or `wget` directly into `bash` or `sh` during container build opens the build pipeline to man-in-the-middle tampering and untrusted code execution.",
        "remediation": "Download installer artifacts separately, verify their SHA-256 checksums, and execute from local filesystem.",
        "cwe": "CWE-494: Download of Code Without Integrity Check",
        "impact": "Build pipeline compromise and potential supply chain injection into generated container images.",
        "secure_example": "RUN curl -fsSL -o installer.sh https://example.com/installer.sh && \\\n    echo 'sha256sum  installer.sh' | sha256sum -c - && \\\n    sh installer.sh"
    },
    {
        "id": "dockerfile.security.sudo-usage",
        "name": "Insecure sudo Package in Container",
        "file_match": lambda f: "dockerfile" in f.lower(),
        "pattern": re.compile(r'(?:apt-get|apk|yum)\s+install.*sudo\b', re.IGNORECASE),
        "severity": Severity.LOW,
        "description": "Installing `sudo` inside a container is unnecessary in isolated environments and can enable privilege escalation vectors.",
        "remediation": "Remove `sudo` from container image dependencies. Grant required permissions during build or use minimal distroless base images.",
        "cwe": "CWE-250: Execution with Unnecessary Privileges",
        "impact": "Provides privilege escalation pathways if container processes are hijacked.",
        "secure_example": "RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates"
    },

    # GitHub Actions Workflow rules (.github/workflows/*.yml)
    {
        "id": "github-actions.security.pull-request-target-checkout",
        "name": "Dangerous pull_request_target with Checkout",
        "file_match": lambda f: (".github/workflows" in f or ".github\\workflows" in f) and (f.endswith(".yml") or f.endswith(".yaml")),
        "pattern": re.compile(r'pull_request_target:', re.IGNORECASE),
        "severity": Severity.CRITICAL,
        "description": "Using `pull_request_target` grants repository write permissions and workflow secrets to untrusted pull request events from forks.",
        "remediation": "Use standard `pull_request` triggers for PR checks. If `pull_request_target` is strictly necessary, never checkout untrusted PR code (`ref: ${{ github.event.pull_request.head.sha }}`).",
        "cwe": "CWE-269: Improper Privilege Management",
        "impact": "Attackers can submit pull requests that exfiltrate repository secrets (GITHUB_TOKEN, deploy keys, API credentials) via modified workflow scripts.",
        "secure_example": "on:\n  pull_request:\n    branches: [main]"
    },
    {
        "id": "github-actions.security.unpinned-action",
        "name": "Unpinned Third-Party GitHub Action (@main or @master)",
        "file_match": lambda f: (".github/workflows" in f or ".github\\workflows" in f) and (f.endswith(".yml") or f.endswith(".yaml")),
        "pattern": re.compile(r'uses:\s*[^@\s]+@(main|master)\b', re.IGNORECASE),
        "severity": Severity.MEDIUM,
        "description": "GitHub Actions referenced using mutable branch tags like `@main` or `@master` can be tampered with or modified without notice.",
        "remediation": "Pin all third-party actions to an immutable full-length commit SHA (e.g. `uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11`).",
        "cwe": "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
        "impact": "Supply chain compromise if an upstream action repository is hijacked or tags are maliciously moved.",
        "secure_example": "uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1"
    },
    {
        "id": "github-actions.security.write-all-permissions",
        "name": "Overly Permissive GITHUB_TOKEN (permissions: write-all)",
        "file_match": lambda f: (".github/workflows" in f or ".github\\workflows" in f) and (f.endswith(".yml") or f.endswith(".yaml")),
        "pattern": re.compile(r'permissions:\s*(?:write-all|\{\s*contents:\s*write\s*\})', re.IGNORECASE),
        "severity": Severity.HIGH,
        "description": "Workflow grants broad write permissions to GITHUB_TOKEN across all scopes instead of enforcing least privilege.",
        "remediation": "Explicitly declare minimum required scopes (e.g. `permissions: { contents: read, pull-requests: write }`).",
        "cwe": "CWE-250: Execution with Unnecessary Privileges",
        "impact": "Leaked or exploited tokens during CI execution can push commits, delete releases, or overwrite repository assets.",
        "secure_example": "permissions:\n  contents: read\n  issues: write"
    },

    # Kubernetes Manifests (*.yaml / *.yml with k8s resources)
    {
        "id": "k8s.security.privileged-container",
        "name": "Kubernetes Pod Running in Privileged Mode",
        "file_match": lambda f: f.endswith((".yaml", ".yml")) and not (".github" in f),
        "pattern": re.compile(r'privileged:\s*true\b', re.IGNORECASE),
        "severity": Severity.CRITICAL,
        "description": "Container is configured with `securityContext.privileged: true`. Privileged containers disable isolation and grant direct access to host devices.",
        "remediation": "Remove `privileged: true`. Grant only required Linux capabilities using `capabilities: { add: [...] }` under securityContext.",
        "cwe": "CWE-250: Execution with Unnecessary Privileges",
        "impact": "Trivial node takeover and host escape from compromised container process.",
        "secure_example": "securityContext:\n  privileged: false\n  allowPrivilegeEscalation: false\n  readOnlyRootFilesystem: true"
    },
    {
        "id": "k8s.security.host-network",
        "name": "Kubernetes Pod Shares Host Network Namespace",
        "file_match": lambda f: f.endswith((".yaml", ".yml")) and not (".github" in f),
        "pattern": re.compile(r'hostNetwork:\s*true\b', re.IGNORECASE),
        "severity": Severity.HIGH,
        "description": "Setting `hostNetwork: true` allows the pod to access local host loopback adapters, snooping network traffic of adjacent pods on the node.",
        "remediation": "Remove `hostNetwork: true`. Use standard Kubernetes ClusterIP or Ingress services for network routing.",
        "cwe": "CWE-668: Exposure of Resource to Wrong Sphere",
        "impact": "Bypasses Kubernetes network policies and exposes node-internal listening services.",
        "secure_example": "spec:\n  hostNetwork: false"
    },
    {
        "id": "k8s.security.docker-socket-mount",
        "name": "Host Docker Socket Mounted into Pod",
        "file_match": lambda f: f.endswith((".yaml", ".yml")) or "docker-compose" in f.lower(),
        "pattern": re.compile(r'(?:path:\s*|[\s"\'])/var/run/docker\.sock\b', re.IGNORECASE),
        "severity": Severity.CRITICAL,
        "description": "Mounting `/var/run/docker.sock` grants the container full API control over the host Docker daemon, resulting in immediate host root escalation.",
        "remediation": "Never mount the Docker socket into containers. Use rootless Kaniko or Buildah for in-cluster container builds.",
        "cwe": "CWE-250: Execution with Unnecessary Privileges",
        "impact": "Root-level container escape and total cluster node compromise.",
        "secure_example": "# Avoid mounting docker.sock. Run unprivileged container builders."
    },

    # Terraform Rules (*.tf)
    {
        "id": "terraform.security.s3-public-read",
        "name": "Publicly Accessible S3 Bucket ACL in Terraform",
        "file_match": lambda f: f.endswith(".tf"),
        "pattern": re.compile(r'acl\s*=\s*["\']public-(?:read|read-write)["\']', re.IGNORECASE),
        "severity": Severity.HIGH,
        "description": "Terraform resource sets AWS S3 bucket ACL to public-read. All files uploaded to this bucket can be accessed anonymously over the Internet.",
        "remediation": "Set `acl = \"private\"` and attach `aws_s3_bucket_public_access_block` with all block settings enabled.",
        "cwe": "CWE-732: Incorrect Permission Assignment for Critical Resource",
        "impact": "Sensitive data leak and PII exposure to unauthorized web scrapers.",
        "secure_example": 'resource "aws_s3_bucket_acl" "example" {\n  bucket = aws_s3_bucket.b.id\n  acl    = "private"\n}'
    },
    {
        "id": "terraform.security.open-ssh-ingress",
        "name": "Security Group Ingress Allows Unrestricted SSH (0.0.0.0/0)",
        "file_match": lambda f: f.endswith(".tf"),
        "pattern": re.compile(r'(?:from_port|to_port)\s*=\s*22\b[^}]*cidr_blocks\s*=\s*\[\s*["\']0\.0\.0\.0/0["\']', re.DOTALL | re.IGNORECASE),
        "severity": Severity.HIGH,
        "description": "Security group ingress rule exposes SSH port 22 to the entire Internet (0.0.0.0/0).",
        "remediation": "Restrict SSH ingress to specific corporate VPN IP ranges or use AWS SSM Session Manager without open inbound ports.",
        "cwe": "CWE-284: Improper Access Control",
        "impact": "Brute-force SSH credential stuffing and automated bot exploitation.",
        "secure_example": 'cidr_blocks = ["10.0.0.0/16"] # Restricted internal subnet'
    }
]

class ConfigScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "Infrastructure & Configuration Auditor"

    @property
    def tool_version(self) -> str:
        return "ConfigAudit v1.2 (Docker & CI/CD Security)"

    async def is_available(self) -> tuple[bool, str]:
        return True, "Infrastructure configuration rules loaded"

    async def scan(self, target_dir: str) -> tuple[list[Finding], ScannerExecutionStatus]:
        start_time = time.time()
        findings: list[Finding] = []

        try:
            for root, dirs, files in os.walk(target_dir):
                # Prune common non-infra directories
                dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '.venv', 'dist', 'build'}]

                for file in files:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, target_dir).replace("\\", "/")

                    try:
                        if os.path.getsize(file_path) > 1024 * 1024:
                            continue
                    except OSError:
                        continue

                    applicable_rules = [r for r in INFRA_RULES if r["file_match"](rel_path)]
                    if not applicable_rules:
                        continue

                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            lines = f.readlines()
                    except Exception:
                        continue

                    for rule in applicable_rules:
                        for idx, line in enumerate(lines, start=1):
                            match = rule["pattern"].search(line)
                            if match:
                                fingerprint = compute_finding_fingerprint(
                                    category="INFRASTRUCTURE",
                                    detector_name="ConfigAudit",
                                    rule_id=rule["id"],
                                    file_path=rel_path,
                                    line_start=idx
                                )

                                findings.append(Finding(
                                    id=str(uuid.uuid4()),
                                    fingerprint=fingerprint,
                                    title=f"Configuration: {rule['name']}",
                                    description=rule["description"],
                                    category=Category.INFRASTRUCTURE,
                                    severity=rule["severity"],
                                    confidence=Confidence.HIGH,
                                    raw_severity=rule["severity"].value,
                                    file_path=rel_path,
                                    line_start=idx,
                                    line_end=idx,
                                    detector_name="ConfigAudit",
                                    rule_id=rule["id"],
                                    evidence=line.strip()[:200],
                                    remediation=rule["remediation"],
                                    cwe_id=rule.get("cwe"),
                                    technical_impact=rule.get("impact"),
                                    secure_code_example=rule.get("secure_example")
                                ))

            duration = round(time.time() - start_time, 2)
            return findings, ScannerExecutionStatus(
                scanner_name="Configuration Auditor",
                tool_version=self.tool_version,
                status="SUCCESS",
                duration_seconds=duration,
                findings_count=len(findings)
            )
        except Exception as e:
            duration = round(time.time() - start_time, 2)
            return [], ScannerExecutionStatus(
                scanner_name="Configuration Auditor",
                tool_version=self.tool_version,
                status="FAILED",
                duration_seconds=duration,
                findings_count=0,
                error_message=str(e)
            )
