"use client";

import React, { useState } from "react";
import Link from "next/link";
import {
  Key,
  Package,
  Code2,
  HardDrive,
  Network,
  Wrench,
  ArrowRight,
  CheckCircle2,
  Cpu,
  EyeOff,
  GitBranch,
  Sparkles,
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
} from "lucide-react";
import { ShieldLogo } from "@/components/common/Icons";

interface PipelineStage {
  id: string;
  step: string;
  title: string;
  badge: string;
  icon: any;
  summary: string;
  technicalDetails: string[];
  codeSnippet: string;
}

const PIPELINE_STAGES: PipelineStage[] = [
  {
    id: "ingestion",
    step: "01",
    title: "Secure Ephemeral Ingestion",
    badge: "Sandbox Isolation",
    icon: GitBranch,
    summary:
      "When a repository URL is provided, RepoShield streams the source tree archive into an ephemeral memory sandbox, enforcing strict SSRF and path traversal protections.",
    technicalDetails: [
      "URL validation blocks internal/private IP ranges (127.0.0.1, 10.0.0.0/8, 169.254.169.254, RFC1918) preventing Server-Side Request Forgery.",
      "Archive extraction utilizes strict Zip-Slip defenses, ensuring no relative paths break out of the ephemeral /tmp/reposhield_* mount.",
      "Memory and size limits prevent decompression bombs (Max 150MB archive, 5,000 files maximum).",
      "Automatic background garbage collection purges all repository code upon scan completion (TTL = 1,800 seconds).",
    ],
    codeSnippet: `# Ephemeral Ingestion Security Guard
def validate_and_extract(github_url: str) -> Path:
    # 1. Enforce strict GitHub domain allowlisting
    domain = urlparse(github_url).netloc.lower()
    if domain not in ("github.com", "www.github.com"):
        raise SecurityValidationError("Host not permitted")

    # 2. Extract into ephemeral RAM-only directory
    sandbox_dir = Path(tempfile.mkdtemp(prefix="reposhield_"))
    with zipfile.ZipFile(stream) as archive:
        for member in archive.infolist():
            target = (sandbox_dir / member.filename).resolve()
            if not str(target).startswith(str(sandbox_dir)):
                raise SecurityValidationError("Zip-Slip traversal detected")
            archive.extract(member, sandbox_dir)
    return sandbox_dir`,
  },
  {
    id: "tri-engine",
    step: "02",
    title: "Tri-Engine Security Analysis",
    badge: "Parallel Scanners",
    icon: Cpu,
    summary:
      "Three purpose-built security engines execute asynchronously against the working tree, detecting exposed secrets, vulnerable third-party dependencies, and application logic vulnerabilities.",
    technicalDetails: [
      "Gitleaks Engine: Scans commits and files with 160+ curated secret signatures, entropy calculators, and token regexes.",
      "Google OSV Engine: Inspects package manifests (package.json, requirements.txt, go.mod, pom.xml, Cargo.toml) against authoritative GHSA and CVE databases.",
      "Semgrep OSS SAST: AST-driven pattern matching detects SQL injection, XSS, SSRF, broken authentication, and dangerous cryptographic routines.",
      "Execution operates in non-blocking async sub-processes with 60-second timeouts per engine.",
    ],
    codeSnippet: `# Tri-Engine Concurrent Pipeline
async def run_tri_engine_pipeline(target_dir: Path) -> List[Finding]:
    gitleaks_task = asyncio.create_task(GitleaksScanner().scan(target_dir))
    semgrep_task = asyncio.create_task(SemgrepScanner().scan(target_dir))
    osv_task = asyncio.create_task(OSVScanner().scan(target_dir))

    # Concurrently aggregate all security findings
    results = await asyncio.gather(
        gitleaks_task, semgrep_task, osv_task, return_exceptions=True
    )
    return normalize_and_deduplicate(results)`,
  },
  {
    id: "intelligence",
    step: "03",
    title: "Active Risk Intelligence",
    badge: "Prioritization",
    icon: Sparkles,
    summary:
      "Raw findings are normalized, deduplicated, and enriched with threat intelligence to separate theoretical warnings from actively exploitable risks.",
    technicalDetails: [
      "CISA KEV Integration: Cross-references CVE IDs with CISA's Known Exploited Vulnerabilities catalog to elevate actively weaponized bugs.",
      "Ephemeral Secret Verification: Safely verifies whether leaked AWS, GitHub, or Stripe tokens are currently active or revoked (without persisting credentials).",
      "EPSS Exploit Prediction: Incorporates Exploit Prediction Scoring System probabilities to forecast exploitation likelihood.",
      "Secret Redaction: Pre-redacts all sensitive payloads using a 2-stage regex and entropy masking filter before findings leave the engine.",
    ],
    codeSnippet: `# Intelligence & Prioritization Logic
def enrich_finding_with_intel(finding: Finding) -> Finding:
    # Check CISA Known Exploited Vulnerabilities catalog
    if finding.cve_id and finding.cve_id in CISA_KEV_DATABASE:
        finding.is_cisa_kev = True
        finding.severity = Severity.CRITICAL
        finding.risk_score = min(100.0, finding.risk_score + 35.0)

    # Pre-redact secret evidence
    if finding.category == Category.SECRETS:
        finding.evidence = redact_secret_string(finding.evidence)
    return finding`,
  },
  {
    id: "attack-paths",
    step: "04",
    title: "Attack Path Graph Synthesis",
    badge: "Graph Correlation",
    icon: Network,
    summary:
      "RepoShield constructs a directed graph connecting leaked secrets, exposed API endpoints, and cloud infrastructure to identify chained exploitation paths.",
    technicalDetails: [
      "Graph nodes represent Attackers, Leaked Credentials, Vulnerable Endpoints, and Sensitive Cloud Assets.",
      "Graph edges map lateral movement pathways (e.g., Leaked AWS Key -> S3 Bucket Access -> Customer Data Exfiltration).",
      "Calculates shortest attack vectors and critical choke-points where a single remediation breaks multiple kill chains.",
      "Enables proactive defensive prioritization based on blast radius rather than isolated severity scores.",
    ],
    codeSnippet: `# Directed Attack Path Graph Generation
def synthesize_attack_paths(findings: List[Finding]) -> AttackGraph:
    graph = nx.DiGraph()
    graph.add_node("Attacker", type="threat_actor")

    for f in findings:
        if f.category == Category.SECRETS and "aws" in f.title.lower():
            graph.add_node("AWS_Credentials", type="credential", status="active")
            graph.add_node("S3_Production_Buckets", type="cloud_asset")
            graph.add_edge("Attacker", "AWS_Credentials", technique="Credential Harvest")
            graph.add_edge("AWS_Credentials", "S3_Production_Buckets", technique="Assume Role")
    return graph`,
  },
  {
    id: "remediation",
    step: "05",
    title: "Autonomous Fix Validation & CI Gates",
    badge: "Verification",
    icon: Wrench,
    summary:
      "Generates actionable remediation patches and validates whether fixes truly eliminate the vulnerability in an isolated re-scan environment.",
    technicalDetails: [
      "Code diff generation provides drop-in patch snippets for dependency bumps and code sanitization.",
      "Fix Validation Sandbox applies proposed patches to a fresh clone and re-runs the specific scanner to confirm finding resolution.",
      "Software Bill of Materials (SBOM) exported in standard CycloneDX 1.5 and SPDX 2.3 formats with VEX statements.",
      "CI/CD PR Gate checks enforce policy compliance (e.g. zero critical vulnerabilities, no active secrets).",
    ],
    codeSnippet: `# Fix Validation Execution
async def validate_remediation(finding_id: str, patch_diff: str) -> ValidationResult:
    # 1. Clone fresh ephemeral copy of target file
    sandbox = create_ephemeral_sandbox()
    apply_patch(sandbox, patch_diff)

    # 2. Re-execute specific scanner to verify elimination
    recheck_findings = await targeted_recheck(sandbox, finding_id)
    resolved = len(recheck_findings) == 0

    return ValidationResult(
        finding_id=finding_id,
        status="RESOLVED" if resolved else "STILL_DETECTED",
        verified_at=datetime.utcnow()
    )`,
  },
];

const FAQS = [
  {
    q: "Where is my repository code stored during a scan?",
    a: "RepoShield strictly enforces a zero-database architecture. When you scan a repository, the code is streamed into an ephemeral, temporary RAM mount on the local backend. Upon scan completion, all files and directories are completely wiped from disk. No repository files, AST caches, or source files are ever saved in a database, remote cloud storage, or persistent volume.",
  },
  {
    q: "How does RepoShield protect against accidental secret exposure?",
    a: "RepoShield features a mandatory 2-stage Redaction Pipeline. All secret evidence, token assignments, AWS keys, and private certificates detected by Gitleaks or SAST are immediately masked (e.g. ghp_••••••••••••••) before leaving the backend scanner. Unredacted keys are never transmitted over API responses, never stored in browser localStorage, and cannot be revealed via DOM inspection or clipboard copying.",
  },
  {
    q: "How does the zero-database architecture work with scan history?",
    a: "All scan metadata, vulnerability metrics, and pre-redacted findings reside exclusively inside your current browser's localStorage. The backend is completely stateless: it handles real-time execution in memory and returns the sanitized result. No PostgreSQL, MySQL, Redis, MongoDB, Supabase, or SQLite database is ever created or queried.",
  },
  {
    q: "How does RepoShield avoid GitHub API rate limits?",
    a: "Unauthenticated requests to the GitHub API are capped by GitHub at 60 requests/hr per IP. In the Settings page, you can optionally configure a GitHub Personal Access Token (read-only). This token is stored exclusively in your browser's localStorage and elevates your rate limit to 5,000 requests/hr. RepoShield never shares or transmits your token to any third party.",
  },
  {
    q: "What makes Fix Validation different from other scanners?",
    a: "Conventional scanners only tell you what is broken. RepoShield's Fix Validation feature allows you to generate or edit a patch and test it in an isolated ephemeral sandbox. The system re-executes the relevant security engine against the patched code and mathematically validates whether the finding is truly resolved before you commit it to your main branch.",
  },
];

export default function HowItWorksPage() {
  const [activeStage, setActiveStage] = useState<string>("ingestion");
  const [copiedCode, setCopiedCode] = useState(false);
  const [openFaq, setOpenFaq] = useState<number | null>(null);

  const currentStage = PIPELINE_STAGES.find((s) => s.id === activeStage) || PIPELINE_STAGES[0];

  const handleCopyCode = () => {
    navigator.clipboard.writeText(currentStage.codeSnippet);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  return (
    <div className="space-y-10 max-w-5xl mx-auto pb-12">
      {/* Hero Header */}
      <div className="text-center space-y-3 pt-2 pb-4">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[var(--primary-subtle)] border border-[var(--primary)]/20 text-[12px] font-medium text-[var(--primary-hover)]">
          <ShieldLogo className="w-3.5 h-3.5 text-[var(--primary)]" />
          <span>Security Architecture &amp; Methodology</span>
        </div>
        <h1 className="text-[32px] md:text-[38px] font-bold tracking-tight text-[var(--foreground-primary)]">
          How RepoShield Works
        </h1>
        <p className="text-[14px] md:text-[15px] text-[var(--foreground-secondary)] max-w-2xl mx-auto leading-relaxed">
          Inside the native macOS security intelligence platform — from ephemeral sandboxing and tri-engine analysis to active threat correlation and zero-database isolation.
        </p>
      </div>

      {/* Core Architectural Pillars */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="macos-panel p-5 space-y-2.5">
          <div className="w-9 h-9 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border)] flex items-center justify-center text-[var(--primary)]">
            <HardDrive className="w-4 h-4" />
          </div>
          <h2 className="text-[14px] font-semibold text-[var(--foreground-primary)]">
            Zero-Database Isolation
          </h2>
          <p className="text-[12.5px] text-[var(--foreground-secondary)] leading-relaxed">
            No customer code, API tokens, or scan reports are ever saved to persistent databases. Scans run in RAM-only ephemeral sandboxes with strict 1,800-second automatic deletion.
          </p>
        </div>

        <div className="macos-panel p-5 space-y-2.5">
          <div className="w-9 h-9 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border)] flex items-center justify-center text-[var(--success)]">
            <Cpu className="w-4 h-4" />
          </div>
          <h2 className="text-[14px] font-semibold text-[var(--foreground-primary)]">
            Tri-Engine Synergy
          </h2>
          <p className="text-[12.5px] text-[var(--foreground-secondary)] leading-relaxed">
            Simultaneously orchestrates Gitleaks (secrets &amp; entropy), Google OSV (package vulnerabilities &amp; CVEs), and Semgrep OSS (AST-based static application security).
          </p>
        </div>

        <div className="macos-panel p-5 space-y-2.5">
          <div className="w-9 h-9 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border)] flex items-center justify-center text-[var(--warning)]">
            <Network className="w-4 h-4" />
          </div>
          <h2 className="text-[14px] font-semibold text-[var(--foreground-primary)]">
            Graph Attack Paths
          </h2>
          <p className="text-[12.5px] text-[var(--foreground-secondary)] leading-relaxed">
            Synthesizes discovered vulnerabilities into contextual attack paths. Connects exposed secrets to cloud infrastructure and APIs to uncover realistic breach trajectories.
          </p>
        </div>
      </div>

      {/* Interactive 5-Stage Scanning Pipeline */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-1 border-b border-[var(--border-subtle)]">
          <div>
            <h2 className="text-[18px] font-semibold text-[var(--foreground-primary)] tracking-tight">
              Interactive Scanning Pipeline
            </h2>
            <p className="text-[12.5px] text-[var(--foreground-secondary)]">
              Explore each phase of the real-time security intelligence lifecycle.
            </p>
          </div>
          <span className="text-[11px] font-mono px-2 py-0.5 rounded-[4px] bg-[var(--surface-secondary)] border border-[var(--border-subtle)] text-[var(--foreground-tertiary)] self-start sm:self-auto">
            100% Client-Stateless
          </span>
        </div>

        {/* Stage Selector Navigation Tabs */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
          {PIPELINE_STAGES.map((stage) => {
            const Icon = stage.icon;
            const isSelected = activeStage === stage.id;
            return (
              <button
                key={stage.id}
                onClick={() => setActiveStage(stage.id)}
                className={`p-3 rounded-[var(--radius-md)] text-left transition-all ${
                  isSelected
                    ? "bg-[var(--surface)] border border-[var(--primary)] shadow-sm"
                    : "bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] border border-[var(--border)]"
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span
                    className={`font-mono text-[11px] font-bold ${
                      isSelected ? "text-[var(--primary)]" : "text-[var(--foreground-tertiary)]"
                    }`}
                  >
                    {stage.step}
                  </span>
                  <Icon
                    className={`w-4 h-4 ${
                      isSelected ? "text-[var(--primary)]" : "text-[var(--foreground-tertiary)]"
                    }`}
                  />
                </div>
                <div
                  className={`text-[12px] font-medium truncate ${
                    isSelected ? "text-[var(--foreground-primary)]" : "text-[var(--foreground-secondary)]"
                  }`}
                >
                  {stage.title}
                </div>
              </button>
            );
          })}
        </div>

        {/* Active Stage Technical Detail Card */}
        <div className="macos-panel p-6 space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-[var(--border-subtle)]">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-[var(--radius-sm)] bg-[var(--primary-subtle)] border border-[var(--primary)]/30 flex items-center justify-center text-[var(--primary-hover)]">
                {React.createElement(currentStage.icon, { className: "w-5 h-5" })}
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[11px] text-[var(--primary)] font-bold">
                    STAGE {currentStage.step}
                  </span>
                  <span className="text-[11px] px-2 py-0.5 rounded-[4px] bg-[var(--surface-secondary)] border border-[var(--border)] text-[var(--foreground-secondary)] font-medium">
                    {currentStage.badge}
                  </span>
                </div>
                <h3 className="text-[16px] font-semibold text-[var(--foreground-primary)] mt-0.5">
                  {currentStage.title}
                </h3>
              </div>
            </div>
          </div>

          <p className="text-[13px] text-[var(--foreground-primary)] leading-relaxed">
            {currentStage.summary}
          </p>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {/* Technical Specifications */}
            <div className="space-y-3">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--foreground-tertiary)] font-mono">
                Engine Specifications &amp; Defense Mechanisms
              </div>
              <ul className="space-y-2">
                {currentStage.technicalDetails.map((detail, idx) => (
                  <li key={idx} className="flex items-start gap-2.5 text-[12.5px] text-[var(--foreground-secondary)]">
                    <CheckCircle2 className="w-3.5 h-3.5 text-[var(--success)] mt-0.5 flex-shrink-0" />
                    <span>{detail}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Code / Logic Representation */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--foreground-tertiary)] font-mono">
                  Internal Engine Routine
                </span>
                <button
                  onClick={handleCopyCode}
                  className="flex items-center gap-1 text-[11px] font-mono text-[var(--foreground-secondary)] hover:text-[var(--foreground-primary)] transition-colors"
                >
                  {copiedCode ? (
                    <>
                      <Check className="w-3 h-3 text-[var(--success)]" />
                      <span>Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3 h-3" />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              </div>

              {/* Dedicated macOS Code Surface */}
              <div className="macos-code-surface max-h-[220px] overflow-auto text-[11.5px] font-mono">
                <pre>
                  <code>{currentStage.codeSnippet}</code>
                </pre>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Security Engines Breakdown Matrix */}
      <div className="space-y-3">
        <h2 className="text-[18px] font-semibold text-[var(--foreground-primary)] tracking-tight">
          Tri-Engine Capabilities Matrix
        </h2>
        <div className="macos-panel overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-[12.5px]">
              <thead className="bg-[var(--surface-secondary)] border-b border-[var(--border)] text-[11px] uppercase tracking-wider font-mono text-[var(--foreground-tertiary)]">
                <tr>
                  <th className="py-2.5 px-4 font-semibold">Engine</th>
                  <th className="py-2.5 px-4 font-semibold">Target Scope</th>
                  <th className="py-2.5 px-4 font-semibold">Analysis Method</th>
                  <th className="py-2.5 px-4 font-semibold">Intelligence Feeds</th>
                  <th className="py-2.5 px-4 font-semibold">Execution Mode</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-subtle)]">
                <tr className="hover:bg-[var(--surface-hover)] transition-colors">
                  <td className="py-3 px-4 font-medium text-[var(--foreground-primary)] flex items-center gap-2">
                    <Key className="w-3.5 h-3.5 text-[var(--danger)]" />
                    <span>Gitleaks</span>
                  </td>
                  <td className="py-3 px-4 text-[var(--foreground-secondary)]">
                    Git commits, git log, tree files, and configs
                  </td>
                  <td className="py-3 px-4 font-mono text-[11.5px] text-[var(--foreground-secondary)]">
                    Regex + Shannon Entropy Analysis
                  </td>
                  <td className="py-3 px-4 text-[var(--foreground-secondary)]">
                    160+ curated token &amp; credential rules
                  </td>
                  <td className="py-3 px-4 font-mono text-[11.5px] text-[var(--success)]">
                    Ephemeral CLI sub-process
                  </td>
                </tr>

                <tr className="hover:bg-[var(--surface-hover)] transition-colors">
                  <td className="py-3 px-4 font-medium text-[var(--foreground-primary)] flex items-center gap-2">
                    <Package className="w-3.5 h-3.5 text-[var(--warning)]" />
                    <span>Google OSV</span>
                  </td>
                  <td className="py-3 px-4 text-[var(--foreground-secondary)]">
                    package.json, requirements.txt, go.mod, pom.xml, Cargo
                  </td>
                  <td className="py-3 px-4 font-mono text-[11.5px] text-[var(--foreground-secondary)]">
                    Lockfile Parsing &amp; Version Matrix Query
                  </td>
                  <td className="py-3 px-4 text-[var(--foreground-secondary)]">
                    Google OSV, GHSA, CVE, NVD, PyPI
                  </td>
                  <td className="py-3 px-4 font-mono text-[11.5px] text-[var(--primary)]">
                    Asynchronous Batch REST API
                  </td>
                </tr>

                <tr className="hover:bg-[var(--surface-hover)] transition-colors">
                  <td className="py-3 px-4 font-medium text-[var(--foreground-primary)] flex items-center gap-2">
                    <Code2 className="w-3.5 h-3.5 text-[var(--info)]" />
                    <span>Semgrep OSS</span>
                  </td>
                  <td className="py-3 px-4 text-[var(--foreground-secondary)]">
                    Source code (Python, JS/TS, Go, Java, IaC)
                  </td>
                  <td className="py-3 px-4 font-mono text-[11.5px] text-[var(--foreground-secondary)]">
                    Semantic Abstract Syntax Tree (AST)
                  </td>
                  <td className="py-3 px-4 text-[var(--foreground-secondary)]">
                    OWASP Top 10, CWE-79, CWE-89, CWE-78
                  </td>
                  <td className="py-3 px-4 font-mono text-[11.5px] text-[var(--success)]">
                    Isolated local AST runner
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Secret Redaction Guarantee Card */}
      <div className="macos-panel p-6 space-y-3">
        <div className="flex items-center gap-2.5 text-[14px] font-semibold text-[var(--foreground-primary)]">
          <EyeOff className="w-4 h-4 text-[var(--danger)]" />
          <span>Zero-Data-Leakage &amp; Secret Redaction Guarantee</span>
        </div>
        <p className="text-[12.5px] text-[var(--foreground-secondary)] leading-relaxed">
          RepoShield is engineered under the assumption that scanners themselves must never become attack vectors.
          When sensitive credentials (such as AWS Access Keys, GitHub PATs, private keys, or database URLs) are identified,
          the engine executes an automatic two-pass redaction algorithm.
        </p>
        <div className="p-3.5 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border)] font-mono text-[11.5px] text-[var(--foreground-secondary)] space-y-1">
          <div className="text-[var(--danger)] line-through">
            - const AWS_SECRET = &quot;wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY&quot;;
          </div>
          <div className="text-[var(--success)]">
            + const AWS_SECRET = &quot;wJalr••••••••••••••••••••••••••••••••KEY&quot; [PRE-REDACTED BY REPOSHIELD];
          </div>
        </div>
      </div>

      {/* Frequently Asked Architecture Questions */}
      <div className="space-y-3">
        <h2 className="text-[18px] font-semibold text-[var(--foreground-primary)] tracking-tight">
          Architecture &amp; Security FAQ
        </h2>
        <div className="macos-panel divide-y divide-[var(--border-subtle)] overflow-hidden">
          {FAQS.map((faq, index) => {
            const isOpen = openFaq === index;
            return (
              <div key={index} className="transition-colors">
                <button
                  type="button"
                  onClick={() => setOpenFaq(isOpen ? null : index)}
                  className="w-full p-4 flex items-center justify-between text-left hover:bg-[var(--surface-hover)] transition-colors"
                >
                  <span className="text-[13px] font-medium text-[var(--foreground-primary)]">
                    {faq.q}
                  </span>
                  {isOpen ? (
                    <ChevronUp className="w-4 h-4 text-[var(--foreground-tertiary)] flex-shrink-0" />
                  ) : (
                    <ChevronDown className="w-4 h-4 text-[var(--foreground-tertiary)] flex-shrink-0" />
                  )}
                </button>
                {isOpen && (
                  <div className="px-4 pb-4 pt-1 text-[12.5px] text-[var(--foreground-secondary)] leading-relaxed border-t border-[var(--border-subtle)]/50 bg-[var(--surface-secondary)]/50">
                    {faq.a}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Bottom Call to Action */}
      <div className="p-6 rounded-[var(--radius-lg)] bg-[var(--surface)] border border-[var(--border)] flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="space-y-1 text-center sm:text-left">
          <h3 className="text-[15px] font-semibold text-[var(--foreground-primary)]">
            Ready to inspect your first repository?
          </h3>
          <p className="text-[12.5px] text-[var(--foreground-secondary)]">
            Execute a zero-database security scan in less than 30 seconds.
          </p>
        </div>
        <div className="flex items-center gap-2.5 flex-shrink-0">
          <Link
            href="/scan"
            className="btn-primary"
          >
            <span>Start a New Scan</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
          <Link
            href="/dashboard"
            className="btn-secondary"
          >
            <span>Overview Dashboard</span>
          </Link>
        </div>
      </div>
    </div>
  );
}
