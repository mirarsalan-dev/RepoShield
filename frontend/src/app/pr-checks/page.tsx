"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  GitPullRequest,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ArrowRight,
  ShieldAlert,
  Copy,
  Check,
  Download,
  FileCode,
  Sliders,
  RefreshCw,
  GitBranch,
  Terminal,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { api } from "@/lib/api";
import { ScanResult, PRCheckResult, Finding } from "@/lib/types";
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import { EmptyState } from "@/components/common/EmptyState";
import { FindingDetailModal } from "@/components/findings/FindingDetailModal";

const GITHUB_ACTIONS_WORKFLOW = `name: RepoShield Security Gate

on:
  pull_request:
    branches: [ "main", "master", "develop" ]
  push:
    branches: [ "main", "master" ]

jobs:
  security-gate:
    name: RepoShield Automated Analysis
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      security-events: write

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install RepoShield Scanner
        run: |
          pip install --upgrade pip
          pip install semgrep
          curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz | tar -xz -C /usr/local/bin gitleaks

      - name: Run RepoShield Gate Scan
        id: reposhield
        run: |
          python -m app.cli scan . --fail-on high --format sarif --output reposhield.sarif

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reposhield.sarif
          category: reposhield
`;

export default function PRChecksPage() {
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [baseScanId, setBaseScanId] = useState<string>("");
  const [headScanId, setHeadScanId] = useState<string>("");
  const [result, setResult] = useState<PRCheckResult | null>(null);
  const [isEvaluating, setIsEvaluating] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedWorkflow, setCopiedWorkflow] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  useEffect(() => {
    const saved = storage.getScanHistory();
    setHistory(saved);
    if (saved.length >= 2) {
      setBaseScanId(saved[1].scan_id);
      setHeadScanId(saved[0].scan_id);
    } else if (saved.length === 1) {
      setHeadScanId(saved[0].scan_id);
      setBaseScanId(saved[0].scan_id);
    }
  }, []);

  const handleRunGateCheck = async () => {
    const baseScan = history.find((s) => s.scan_id === baseScanId);
    const headScan = history.find((s) => s.scan_id === headScanId);

    if (!baseScan || !headScan) {
      setError("Please select both a base scan and a head scan to compare.");
      return;
    }

    setError(null);
    setIsEvaluating(true);

    try {
      const policy = storage.getPolicy();
      const prResult = await api.runPRCheck(baseScan, headScan, policy);
      const policyResult = prResult.policy_result || (prResult as any).policy_evaluation || {
        passed: prResult.passed,
        policy_name: policy.name || "Standard Developer Security Gate",
        violations: [],
        warnings: [],
        evaluated_at: new Date().toISOString(),
        suppressed_count: 0,
      };
      setResult({
        ...prResult,
        unchanged_findings: prResult.unchanged_findings || (prResult as any).recurring_findings || [],
        policy_result: policyResult,
        policy_evaluation: policyResult,
      });
    } catch {
      // Local evaluation fallback
      const baseFingerprints = new Set(baseScan.findings.map((f) => f.fingerprint || `${f.detector_name}:${f.rule_id}:${f.file_path}`));
      const headFingerprints = new Set(headScan.findings.map((f) => f.fingerprint || `${f.detector_name}:${f.rule_id}:${f.file_path}`));

      const newFindings = headScan.findings.filter(
        (f) => !baseFingerprints.has(f.fingerprint || `${f.detector_name}:${f.rule_id}:${f.file_path}`)
      );
      const resolvedFindings = baseScan.findings.filter(
        (f) => !headFingerprints.has(f.fingerprint || `${f.detector_name}:${f.rule_id}:${f.file_path}`)
      );
      const unchangedFindings = headScan.findings.filter(
        (f) => baseFingerprints.has(f.fingerprint || `${f.detector_name}:${f.rule_id}:${f.file_path}`)
      );

      const policy = storage.getPolicy();
      const violations: string[] = [];
      for (const f of newFindings) {
        if (policy.fail_on_new_critical && f.severity === "CRITICAL") {
          violations.push(`New CRITICAL finding introduced: ${f.title}`);
        }
        if (policy.fail_on_new_high && f.severity === "HIGH") {
          violations.push(`New HIGH finding introduced: ${f.title}`);
        }
        if (policy.fail_on_secrets && f.category === "SECRETS") {
          violations.push(`Exposed credential in PR: ${f.title}`);
        }
      }

      setResult({
        passed: violations.length === 0,
        base_branch: baseScan.branch,
        head_branch: headScan.branch,
        new_findings: newFindings,
        resolved_findings: resolvedFindings,
        unchanged_findings: unchangedFindings,
        policy_result: {
          passed: violations.length === 0,
          policy_name: policy.name,
          violations,
          warnings: [],
          evaluated_at: new Date().toISOString(),
          suppressed_count: 0,
        },
      });
    } finally {
      setIsEvaluating(false);
    }
  };

  const handleCopyWorkflow = () => {
    navigator.clipboard.writeText(GITHUB_ACTIONS_WORKFLOW);
    setCopiedWorkflow(true);
    setTimeout(() => setCopiedWorkflow(false), 2000);
  };

  const handleDownloadWorkflow = () => {
    const blob = new Blob([GITHUB_ACTIONS_WORKFLOW], { type: "text/yaml;charset=utf-8;" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "reposhield.yml";
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  };

  if (history.length === 0) {
    return (
      <EmptyState
        icon={GitPullRequest}
        title="No Scans Available for PR Checks"
        description="Run at least two scans (or scan a base and head branch) to evaluate PR security gate compliance."
        actionText="Run New Scan"
        actionHref="/scan"
      />
    );
  }

  const baseScan = history.find((s) => s.scan_id === baseScanId);
  const headScan = history.find((s) => s.scan_id === headScanId);

  return (
    <div className="space-y-6">
      {/* Title Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[var(--border-color)]">
        <div>
          <h1 className="macos-title flex items-center gap-2">
            <GitPullRequest className="w-5 h-5 text-[var(--accent)]" />
            <span>Pull Request Security Gate</span>
          </h1>
          <p className="macos-subtitle">
            Validate branch differentials against security policies before merging to production.
          </p>
        </div>

        <Link href="/policies" className="macos-button flex items-center gap-1.5 self-start sm:self-auto">
          <Sliders className="w-3.5 h-3.5 text-[var(--text-secondary)]" />
          <span>Configure Policies</span>
        </Link>
      </div>

      {/* Comparison Selector Card */}
      <div className="macos-card p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[var(--border-subtle)] pb-3">
          <div className="flex items-center gap-2">
            <GitBranch className="w-4 h-4 text-[var(--accent)]" />
            <h2 className="text-[14px] font-semibold text-[var(--text-primary)] tracking-tight">
              Compare Branches &amp; Scans
            </h2>
          </div>

          <button
            onClick={handleRunGateCheck}
            disabled={isEvaluating || !baseScanId || !headScanId}
            className="macos-button-primary flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isEvaluating ? "animate-spin" : ""}`} />
            <span>{isEvaluating ? "Evaluating..." : "Evaluate Gate"}</span>
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Target Branch */}
          <div className="p-3.5 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-semibold text-[var(--text-muted)] uppercase tracking-wider">
                Base Target Branch
              </span>
              {baseScan && (
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[var(--bg-surface)] border border-[var(--border-subtle)] text-[var(--text-secondary)]">
                  {baseScan.findings.length} findings
                </span>
              )}
            </div>

            <select
              value={baseScanId}
              onChange={(e) => setBaseScanId(e.target.value)}
              className="macos-select w-full font-mono text-[12px]"
            >
              {history.map((s) => (
                <option key={`base-${s.scan_id}`} value={s.scan_id}>
                  {s.owner}/{s.repo} [{s.branch}] - {new Date(s.started_at).toLocaleDateString()}
                </option>
              ))}
            </select>
          </div>

          {/* Proposed PR Branch */}
          <div className="p-3.5 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-semibold text-[var(--text-muted)] uppercase tracking-wider">
                Proposed PR Branch (Head)
              </span>
              {headScan && (
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[var(--bg-surface)] border border-[var(--border-subtle)] text-[var(--text-secondary)]">
                  {headScan.findings.length} findings
                </span>
              )}
            </div>

            <select
              value={headScanId}
              onChange={(e) => setHeadScanId(e.target.value)}
              className="macos-select w-full font-mono text-[12px]"
            >
              {history.map((s) => (
                <option key={`head-${s.scan_id}`} value={s.scan_id}>
                  {s.owner}/{s.repo} [{s.branch}] - {new Date(s.started_at).toLocaleDateString()}
                </option>
              ))}
            </select>
          </div>
        </div>

        {error && (
          <div className="text-[12px] text-[#FF3B30] bg-[#FF3B30]/10 border border-[#FF3B30]/20 rounded-[6px] p-2.5">
            {error}
          </div>
        )}
      </div>

      {/* Results View */}
      {result && (() => {
        const policyResult = result.policy_result || (result as any).policy_evaluation;
        const violations = policyResult?.violations || [];
        const policyName = policyResult?.policy_name || "Security Gate Policy";
        const unchangedCount = (result.unchanged_findings || (result as any).recurring_findings || []).length;

        return (
          <div className="space-y-5 animate-in fade-in duration-150">
            {/* Status Banner */}
            <div
              className={`p-4 rounded-[10px] border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 ${
                result.passed
                  ? "bg-[#34C759]/10 border-[#34C759]/30 text-[#1D1D1F] dark:text-[#F5F5F7]"
                  : "bg-[#FF3B30]/10 border-[#FF3B30]/30 text-[#1D1D1F] dark:text-[#F5F5F7]"
              }`}
            >
              <div className="flex items-start gap-3">
                {result.passed ? (
                  <CheckCircle2 className="w-6 h-6 text-[#34C759] flex-shrink-0 mt-0.5" />
                ) : (
                  <XCircle className="w-6 h-6 text-[#FF3B30] flex-shrink-0 mt-0.5" />
                )}
                <div>
                  <div className="text-[15px] font-semibold tracking-tight flex items-center gap-2">
                    <span>{result.passed ? "Security Gate: Passed" : "Security Gate: Blocked"}</span>
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded-[4px] bg-[var(--bg-surface)] border border-[var(--border-subtle)] text-[var(--text-secondary)]">
                      {policyName}
                    </span>
                  </div>
                  <p className="text-[12px] text-[var(--text-secondary)] mt-0.5">
                    {result.passed
                      ? "No policy-violating findings were introduced in this branch. Safe to merge."
                      : `${violations.length} policy violation(s) detected. Fix required prior to merge.`}
                  </p>
                </div>
              </div>

              {/* Metrics Chips */}
              <div className="flex items-center gap-2 text-[12px] font-mono">
                <span className="px-2.5 py-1 rounded-[6px] bg-[#FF3B30]/15 text-[#FF3B30] font-medium border border-[#FF3B30]/25">
                  +{(result.new_findings || []).length} New
                </span>
                <span className="px-2.5 py-1 rounded-[6px] bg-[#34C759]/15 text-[#34C759] font-medium border border-[#34C759]/25">
                  -{(result.resolved_findings || []).length} Resolved
                </span>
                <span className="px-2.5 py-1 rounded-[6px] bg-[var(--bg-surface)] text-[var(--text-secondary)] border border-[var(--border-subtle)]">
                  {unchangedCount} Unchanged
                </span>
              </div>
            </div>

            {/* Policy Violations List */}
            {violations.length > 0 && (
              <div className="macos-card p-4 space-y-2 border-[#FF3B30]/30">
                <div className="text-[13px] font-semibold text-[#FF3B30] flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4" />
                  <span>Blocking Violations</span>
                </div>
                <ul className="space-y-1.5 text-[12px] text-[var(--text-primary)]">
                  {violations.map((v: string, i: number) => (
                    <li key={i} className="flex items-center gap-2 p-2 rounded-[6px] bg-[#FF3B30]/5 border border-[#FF3B30]/15">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#FF3B30]" />
                      <span>{v}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

          {/* Findings Differential Section */}
          <div className="space-y-4">
            <h2 className="text-[14px] font-semibold text-[var(--text-primary)] tracking-tight">
              Branch Findings Differential
            </h2>

            {/* Newly Introduced Findings */}
            <div className="macos-card p-4 space-y-3">
              <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-2">
                <span className="text-[13px] font-medium text-[var(--text-primary)] flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-[#FF3B30]" />
                  <span>Newly Introduced Findings ({result.new_findings.length})</span>
                </span>
                <span className="text-[11px] text-[var(--text-muted)]">
                  Must be addressed or suppressed prior to merge
                </span>
              </div>

              {result.new_findings.length === 0 ? (
                <div className="text-[12px] text-[var(--text-muted)] py-3 text-center">
                  Clean! No new vulnerabilities or credentials found in this branch.
                </div>
              ) : (
                <div className="space-y-2">
                  {result.new_findings.map((f) => (
                    <div
                      key={f.id}
                      onClick={() => setSelectedFinding(f)}
                      className="p-2.5 rounded-[6px] bg-[var(--bg-secondary)] hover:bg-[var(--bg-hover)] border border-[var(--border-subtle)] cursor-pointer flex items-center justify-between transition-colors text-[12px]"
                    >
                      <div className="flex items-center gap-2.5 overflow-hidden">
                        <SeverityBadge severity={f.severity} />
                        <span className="font-mono text-[11px] text-[var(--text-secondary)] truncate">
                          {f.file_path}:{f.line_start || 1}
                        </span>
                        <span className="font-medium text-[var(--text-primary)] truncate">
                          {f.title}
                        </span>
                      </div>
                      <span className="text-[11px] text-[var(--accent)] hover:underline flex-shrink-0">
                        View Fix &rarr;
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Resolved Findings */}
            <div className="macos-card p-4 space-y-3">
              <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-2">
                <span className="text-[13px] font-medium text-[var(--text-primary)] flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-[#34C759]" />
                  <span>Resolved in PR ({result.resolved_findings.length})</span>
                </span>
                <span className="text-[11px] text-[#34C759] font-medium">
                  Verified fixed
                </span>
              </div>

              {result.resolved_findings.length === 0 ? (
                <div className="text-[12px] text-[var(--text-muted)] py-3 text-center">
                  No existing findings were resolved by this branch.
                </div>
              ) : (
                <div className="space-y-2">
                  {result.resolved_findings.map((f) => (
                    <div
                      key={f.id}
                      className="p-2.5 rounded-[6px] bg-[#34C759]/5 border border-[#34C759]/20 flex items-center justify-between text-[12px]"
                    >
                      <div className="flex items-center gap-2.5 overflow-hidden">
                        <CheckCircle2 className="w-4 h-4 text-[#34C759] flex-shrink-0" />
                        <span className="font-mono text-[11px] text-[var(--text-secondary)] truncate">
                          {f.file_path}
                        </span>
                        <span className="font-medium text-[var(--text-primary)] line-through opacity-75 truncate">
                          {f.title}
                        </span>
                      </div>
                      <span className="text-[11px] text-[#34C759] font-mono font-medium">
                        Fixed
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
        );
      })()}

      {/* GitHub Actions Integration Card */}
      <div className="macos-card p-5 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[var(--border-subtle)] pb-3">
          <div>
            <div className="text-[14px] font-semibold text-[var(--text-primary)] flex items-center gap-2 tracking-tight">
              <Terminal className="w-4 h-4 text-[var(--accent)]" />
              <span>Automate in GitHub Actions</span>
            </div>
            <p className="text-[12px] text-[var(--text-secondary)] mt-0.5">
              Add this workflow to <code className="font-mono text-[var(--text-primary)]">.github/workflows/reposhield.yml</code> to run PR security gates and upload SARIF automatically.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopyWorkflow}
              className="macos-button flex items-center gap-1.5 text-[12px]"
            >
              {copiedWorkflow ? <Check className="w-3.5 h-3.5 text-[#34C759]" /> : <Copy className="w-3.5 h-3.5 text-[var(--text-secondary)]" />}
              <span>{copiedWorkflow ? "Copied" : "Copy Workflow"}</span>
            </button>
            <button
              onClick={handleDownloadWorkflow}
              className="macos-button flex items-center gap-1.5 text-[12px]"
            >
              <Download className="w-3.5 h-3.5 text-[var(--text-secondary)]" />
              <span>Download .yml</span>
            </button>
          </div>
        </div>

        <pre className="macos-code-block max-h-72">
          {GITHUB_ACTIONS_WORKFLOW}
        </pre>
      </div>

      {/* Finding Detail Modal */}
      <FindingDetailModal
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
}
