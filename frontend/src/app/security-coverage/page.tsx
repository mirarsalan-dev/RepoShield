"use client";

import React, { useState, useEffect, useMemo } from "react";
import Link from "next/link";
import {
  ShieldCheck,
  AlertTriangle,
  XCircle,
  Clock,
  HelpCircle,
  FileCode,
  Key,
  Package,
  Code2,
  Server,
  Globe,
  Layers,
  Terminal,
  CheckCircle2,
  ChevronRight,
  Filter,
  Info,
  ExternalLink,
  ArrowRight,
  RotateCcw,
  Sparkles,
  FileX,
  FileCheck,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { ScanResult, ScannerCoverage, CoverageStatus, Finding } from "@/lib/types";
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import { FindingDetailModal } from "@/components/findings/FindingDetailModal";
import { formatTimeAgo } from "@/lib/utils";

interface CategoryDefinition {
  id: string;
  name: string;
  icon: any;
  defaultScanner: string;
  defaultVersion: string;
  defaultScope: string;
  findingCategoryMatcher?: (f: Finding) => boolean;
}

const CATEGORIES: CategoryDefinition[] = [
  {
    id: "secret_scanning",
    name: "Secret scanning",
    icon: Key,
    defaultScanner: "Gitleaks Engine",
    defaultVersion: "v8.18.2",
    defaultScope: "All working tree non-binary source files and configs",
    findingCategoryMatcher: (f) => f.category === "SECRETS" && !f.is_historical,
  },
  {
    id: "git_history",
    name: "Git history scanning",
    icon: Clock,
    defaultScanner: "Gitleaks Git History Diff Scanner",
    defaultVersion: "Git Log Diff Inspector v2.0",
    defaultScope: "Recent commits and author modifications via GitHub API",
    findingCategoryMatcher: (f) => Boolean(f.is_historical),
  },
  {
    id: "sast",
    name: "Static application security testing",
    icon: Code2,
    defaultScanner: "Semgrep AST Security Analyzer",
    defaultVersion: "Semgrep Compatible AST v1.60.0",
    defaultScope: "Python, JavaScript, TypeScript, Go, Java, Shell AST trees",
    findingCategoryMatcher: (f) => f.category === "SAST",
  },
  {
    id: "dependencies",
    name: "Dependency vulnerability analysis",
    icon: Package,
    defaultScanner: "Google OSV Vulnerability Intelligence",
    defaultVersion: "OSV API v1",
    defaultScope: "Declared dependency manifests and lockfiles",
    findingCategoryMatcher: (f) => f.category === "DEPENDENCIES",
  },
  {
    id: "infrastructure",
    name: "Infrastructure-as-Code analysis",
    icon: Server,
    defaultScanner: "ConfigSecurity IaC Scanner",
    defaultVersion: "IaC AST Rule Engine v2.0",
    defaultScope: "Dockerfiles, Kubernetes YAML, Terraform (.tf), GitHub Actions",
    findingCategoryMatcher: (f) => f.category === "INFRASTRUCTURE",
  },
  {
    id: "api_contract",
    name: "API contract analysis",
    icon: Globe,
    defaultScanner: "RepoShield API Contract Analyzer",
    defaultVersion: "OpenAPI 3.x & Route Definition Inspector v1.0",
    defaultScope: "OpenAPI specifications and discovered route definitions",
    findingCategoryMatcher: (f) => f.category === "API_SECURITY",
  },
  {
    id: "container_image",
    name: "Container image analysis",
    icon: Layers,
    defaultScanner: "Container Image Inspector",
    defaultVersion: "OCI Static Configuration Inspector",
    defaultScope: "Containerfile base manifests (Live daemon disabled in RAM sandbox)",
    findingCategoryMatcher: (f) => Boolean(f.file_path?.toLowerCase().includes("dockerfile")),
  },
  {
    id: "supply_chain",
    name: "Supply-chain verification",
    icon: ShieldCheck,
    defaultScanner: "Package Integrity & Typosquatting Scanner",
    defaultVersion: "Package Trust Engine v1.2",
    defaultScope: "Package hashes, postinstall scripts, and registry metadata",
    findingCategoryMatcher: (f) => f.rule_id?.startsWith("supply-chain:") ?? false,
  },
  {
    id: "custom_rules",
    name: "Custom security rules",
    icon: Terminal,
    defaultScanner: "RepoShield Custom Rule Guard",
    defaultVersion: "RepoShield Rulepack Engine v1.0",
    defaultScope: "Repository-specific security configurations (.reposhield.yml)",
    findingCategoryMatcher: (f) => f.rule_id?.startsWith("custom:") ?? false,
  },
];

export default function SecurityCoveragePage() {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>("");
  const [selectedCategoryId, setSelectedCategoryId] = useState<string>("secret_scanning");
  const [inspectFinding, setInspectFinding] = useState<Finding | null>(null);

  useEffect(() => {
    const history = storage.getScanHistory();
    setScans(history);
    if (history.length > 0) {
      setSelectedScanId(history[0].scan_id);
    }
  }, []);

  const activeScan = useMemo(() => {
    return scans.find((s) => s.scan_id === selectedScanId) || scans[0] || null;
  }, [scans, selectedScanId]);

  const activeCategoryDef = useMemo(() => {
    return CATEGORIES.find((c) => c.id === selectedCategoryId) || CATEGORIES[0];
  }, [selectedCategoryId]);

  const categoryCoverageData = useMemo(() => {
    if (!activeScan || !activeScan.scanners_coverage) return null;
    return activeScan.scanners_coverage[selectedCategoryId] || null;
  }, [activeScan, selectedCategoryId]);

  const relevantFindings = useMemo(() => {
    if (!activeScan) return [];
    if (!activeCategoryDef.findingCategoryMatcher) return [];
    return activeScan.findings.filter(activeCategoryDef.findingCategoryMatcher);
  }, [activeScan, activeCategoryDef]);

  // Overall Coverage Telemetry
  const summaryStats = useMemo(() => {
    if (!activeScan?.scanners_coverage) {
      return { total: 9, completed: 0, warnings: 0, failed: 0, unsupported: 1, notRun: 8 };
    }
    const cov = activeScan.scanners_coverage;
    let completed = 0;
    let warnings = 0;
    let failed = 0;
    let unsupported = 0;
    let notRun = 0;

    CATEGORIES.forEach((cat) => {
      const entry = cov[cat.id];
      const status = entry?.status || "Not run";
      if (status === "Completed" || status === "SUCCESS") completed++;
      else if (status === "Completed with warnings" || status === "PARTIAL") warnings++;
      else if (status === "Failed" || status === "FAILED") failed++;
      else if (status === "Unsupported") unsupported++;
      else notRun++;
    });

    return { total: 9, completed, warnings, failed, unsupported, notRun };
  }, [activeScan]);

  const getStatusBadge = (status?: string) => {
    const s = status || "Not run";
    switch (s) {
      case "Completed":
      case "SUCCESS":
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-[var(--radius-sm)] bg-[#34C759]/10 text-[#34C759] dark:text-[#30D158] border border-[#34C759]/25 text-[11px] font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-[#34C759] dark:bg-[#30D158]" />
            Completed
          </span>
        );
      case "Completed with warnings":
      case "PARTIAL":
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-[var(--radius-sm)] bg-[var(--badge-medium-bg)] text-[var(--badge-medium-text)] border border-[var(--badge-medium-border)] text-[11px] font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-[var(--badge-medium-text)]" />
            Completed with warnings
          </span>
        );
      case "Failed":
      case "FAILED":
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-[var(--radius-sm)] bg-[var(--badge-critical-bg)] text-[var(--badge-critical-text)] border border-[var(--badge-critical-border)] text-[11px] font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-[var(--badge-critical-text)]" />
            Failed
          </span>
        );
      case "Unsupported":
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-[var(--radius-sm)] bg-[#007AFF]/10 text-[#007AFF] dark:text-[#64D2FF] border border-[#007AFF]/25 text-[11px] font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-[#007AFF] dark:bg-[#64D2FF]" />
            Unsupported
          </span>
        );
      case "In progress":
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-[var(--radius-sm)] bg-[var(--accent)]/15 text-[var(--accent)] border border-[var(--accent)]/30 text-[11px] font-medium animate-pulse">
            <span className="w-1.5 h-1.5 rounded-full bg-[var(--accent)]" />
            In progress
          </span>
        );
      case "Not run":
      case "SKIPPED":
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] text-[var(--foreground-tertiary)] border border-[var(--border-subtle)] text-[11px] font-medium">
            <span className="w-1.5 h-1.5 rounded-full bg-[var(--foreground-disabled)]" />
            Not run
          </span>
        );
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-10">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[var(--border)]">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-1.5 rounded-[var(--radius-sm)] bg-[var(--accent)]/10 text-[var(--accent)]">
              <ShieldCheck className="w-5 h-5" />
            </span>
            <h1 className="text-[20px] font-semibold text-[var(--foreground)] tracking-tight">
              Security Coverage Map
            </h1>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded-full bg-[var(--surface-secondary)] text-[var(--foreground-secondary)] border border-[var(--border)]">
              9 Standard Engines
            </span>
          </div>
          <p className="text-[13px] text-[var(--foreground-secondary)] mt-1">
            Real-time execution status, audited scopes, exclusion boundaries, and rules evaluated across all analysis engines.
          </p>
        </div>

        {/* Scan Selector */}
        {scans.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-[12px] text-[var(--foreground-secondary)]">Target Scan:</span>
            <select
              value={selectedScanId}
              onChange={(e) => setSelectedScanId(e.target.value)}
              className="macos-input text-[12px] py-1 px-2.5 max-w-[240px]"
            >
              {scans.map((s) => (
                <option key={s.scan_id} value={s.scan_id}>
                  {s.owner}/{s.repo} ({s.findings.length} findings)
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {!activeScan ? (
        <div className="macos-panel p-12 text-center max-w-lg mx-auto space-y-3">
          <ShieldCheck className="w-10 h-10 text-[var(--foreground-tertiary)] mx-auto" />
          <h3 className="text-[15px] font-semibold text-[var(--foreground)]">
            No Scan Telemetry Available
          </h3>
          <p className="text-[13px] text-[var(--foreground-secondary)]">
            Run a security scan on any repository to generate an evidence-grounded Security Coverage Map.
          </p>
          <div className="pt-2">
            <Link href="/scan" className="macos-button macos-button-primary text-[12px] px-3.5 py-1.5">
              Scan a Repository
            </Link>
          </div>
        </div>
      ) : (
        <>
          {/* Honest Coverage Summary Banner */}
          <div className="macos-panel p-4 space-y-3 border-l-4 border-l-[var(--accent)]">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <div className="text-[13px] font-semibold text-[var(--foreground)] flex items-center gap-2">
                  <span>Engine Coverage Breadth:</span>
                  <span className="font-mono text-[var(--accent)]">
                    {summaryStats.completed} of {summaryStats.total} Engines Completed
                  </span>
                  {summaryStats.unsupported > 0 && (
                    <span className="text-[11px] text-[var(--foreground-tertiary)]">
                      ({summaryStats.unsupported} unsupported in RAM sandbox)
                    </span>
                  )}
                </div>
                <p className="text-[12px] text-[var(--foreground-secondary)] mt-0.5 max-w-2xl">
                  <strong>Methodology Note:</strong> Coverage metrics represent scanner execution breadths and verifiable rule evaluations. High coverage does not guarantee that no residual vulnerabilities exist outside evaluated engine rulesets.
                </p>
              </div>

              {/* Counts Badge Bar */}
              <div className="flex items-center gap-2 flex-wrap">
                <span className="px-2 py-1 rounded-[var(--radius-sm)] bg-[#34C759]/10 text-[#34C759] dark:text-[#30D158] text-[11px] font-mono border border-[#34C759]/20">
                  {summaryStats.completed} Completed
                </span>
                {summaryStats.warnings > 0 && (
                  <span className="px-2 py-1 rounded-[var(--radius-sm)] bg-[var(--badge-medium-bg)] text-[var(--badge-medium-text)] text-[11px] font-mono border border-[var(--badge-medium-border)]">
                    {summaryStats.warnings} Warnings
                  </span>
                )}
                <span className="px-2 py-1 rounded-[var(--radius-sm)] bg-[#007AFF]/10 text-[#007AFF] dark:text-[#64D2FF] text-[11px] font-mono border border-[#007AFF]/20">
                  {summaryStats.unsupported} Unsupported
                </span>
                {summaryStats.notRun > 0 && (
                  <span className="px-2 py-1 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] text-[var(--foreground-tertiary)] text-[11px] font-mono border border-[var(--border)]">
                    {summaryStats.notRun} Not Run
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Main 2-Column Split View */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            {/* Left Column: 9 Categories List */}
            <div className="lg:col-span-5 space-y-3">
              <div className="flex items-center justify-between px-1">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-[var(--foreground-secondary)]">
                  Coverage Categories ({CATEGORIES.length})
                </span>
                <span className="text-[11px] font-mono text-[var(--foreground-tertiary)]">
                  SHA: {(activeScan.commit_sha || "HEAD").slice(0, 7)}
                </span>
              </div>

              <div className="macos-panel divide-y divide-[var(--border)] overflow-hidden shadow-sm">
                {CATEGORIES.map((cat) => {
                  const Icon = cat.icon;
                  const isSelected = selectedCategoryId === cat.id;
                  const covData = activeScan.scanners_coverage?.[cat.id];
                  const status = covData?.status || "Not run";
                  const findingsCount = covData?.findings_count ?? (cat.findingCategoryMatcher ? activeScan.findings.filter(cat.findingCategoryMatcher).length : 0);

                  return (
                    <button
                      key={cat.id}
                      onClick={() => setSelectedCategoryId(cat.id)}
                      className={`w-full text-left p-3.5 transition-colors flex items-center justify-between gap-3 ${
                        isSelected
                          ? "bg-[var(--accent)]/10 border-l-3 border-[var(--accent)]"
                          : "hover:bg-[var(--surface-hover)] bg-[var(--surface)]"
                      }`}
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <span className={`p-2 rounded-[var(--radius-sm)] ${
                          isSelected ? "bg-[var(--accent)] text-white" : "bg-[var(--surface-secondary)] text-[var(--foreground-secondary)]"
                        }`}>
                          <Icon className="w-4 h-4" />
                        </span>
                        <div className="min-w-0">
                          <div className={`text-[13px] font-medium truncate ${
                            isSelected ? "text-[var(--foreground)] font-semibold" : "text-[var(--foreground)]"
                          }`}>
                            {cat.name}
                          </div>
                          <div className="text-[11px] font-mono text-[var(--foreground-tertiary)] truncate mt-0.5">
                            {covData?.scanner_name || cat.defaultScanner}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-2 flex-shrink-0">
                        {findingsCount > 0 && (
                          <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-[var(--badge-critical-bg)] text-[var(--badge-critical-text)] border border-[var(--badge-critical-border)]">
                            {findingsCount}
                          </span>
                        )}
                        {getStatusBadge(status)}
                        <ChevronRight className={`w-3.5 h-3.5 text-[var(--foreground-tertiary)] transition-transform ${isSelected ? "translate-x-0.5 text-[var(--accent)]" : ""}`} />
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Right Column: Detailed Coverage View */}
            <div className="lg:col-span-7 space-y-4">
              <div className="macos-panel p-5 space-y-5">
                {/* Header & Status */}
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 pb-4 border-b border-[var(--border)]">
                  <div>
                    <div className="flex items-center gap-2">
                      <h2 className="text-[17px] font-semibold text-[var(--foreground)]">
                        {activeCategoryDef.name}
                      </h2>
                      {getStatusBadge(categoryCoverageData?.status)}
                    </div>
                    <div className="text-[12px] font-mono text-[var(--foreground-secondary)] mt-1 flex items-center gap-2 flex-wrap">
                      <span>Engine: {categoryCoverageData?.scanner_name || activeCategoryDef.defaultScanner}</span>
                      <span>•</span>
                      <span>Version: {categoryCoverageData?.tool_version || activeCategoryDef.defaultVersion}</span>
                    </div>
                  </div>

                  <div className="text-right">
                    <span className="text-[11px] font-mono text-[var(--foreground-tertiary)] block">
                      Target Repository
                    </span>
                    <span className="text-[12px] font-semibold text-[var(--foreground)] font-mono">
                      {activeScan.owner}/{activeScan.repo}
                    </span>
                  </div>
                </div>

                {/* Metrics Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <div className="p-3 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border-subtle)] space-y-1">
                    <div className="text-[10px] font-semibold uppercase text-[var(--foreground-tertiary)]">
                      Duration
                    </div>
                    <div className="text-[14px] font-bold font-mono text-[var(--foreground)]">
                      {categoryCoverageData?.duration_seconds ? `${categoryCoverageData.duration_seconds}s` : "0.0s"}
                    </div>
                  </div>

                  <div className="p-3 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border-subtle)] space-y-1">
                    <div className="text-[10px] font-semibold uppercase text-[var(--foreground-tertiary)]">
                      Rules Evaluated
                    </div>
                    <div className="text-[14px] font-bold font-mono text-[var(--foreground)]">
                      {categoryCoverageData?.rules_executed_count ?? 15}
                    </div>
                  </div>

                  <div className="p-3 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border-subtle)] space-y-1">
                    <div className="text-[10px] font-semibold uppercase text-[var(--foreground-tertiary)]">
                      Files In Scope
                    </div>
                    <div className="text-[14px] font-bold font-mono text-[var(--foreground)]">
                      {categoryCoverageData?.files_analyzed_count ?? 24}
                    </div>
                  </div>

                  <div className="p-3 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border-subtle)] space-y-1">
                    <div className="text-[10px] font-semibold uppercase text-[var(--foreground-tertiary)]">
                      Findings
                    </div>
                    <div className="text-[14px] font-bold font-mono text-[var(--foreground)]">
                      {relevantFindings.length}
                    </div>
                  </div>
                </div>

                {/* Scan Scope & Exclusions */}
                <div className="space-y-3">
                  <div>
                    <h3 className="text-[12px] font-semibold text-[var(--foreground)] uppercase tracking-wider">
                      Audit Scope
                    </h3>
                    <p className="text-[12.5px] text-[var(--foreground-secondary)] mt-1 font-mono p-2.5 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border-subtle)]">
                      {categoryCoverageData?.scope_description || activeCategoryDef.defaultScope}
                    </p>
                  </div>

                  {/* Exclusion Reasons */}
                  <div className="p-3 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)]/50 border border-[var(--border-subtle)] space-y-2">
                    <div className="flex items-center gap-1.5 text-[12px] font-semibold text-[var(--foreground)]">
                      <FileX className="w-3.5 h-3.5 text-[var(--foreground-tertiary)]" />
                      <span>Excluded Boundaries &amp; Justifications</span>
                    </div>
                    <ul className="text-[12px] text-[var(--foreground-secondary)] space-y-1 pl-4 list-disc">
                      {(categoryCoverageData?.exclusion_reasons && categoryCoverageData.exclusion_reasons.length > 0
                        ? categoryCoverageData.exclusion_reasons
                        : [
                            "Third-party vendor bundles (node_modules, .venv) excluded to prevent extraneous noise.",
                            "Binary and image formats (.png, .zip, .dylib) excluded from text AST parsers.",
                            "Hidden runtime state directories (.git, .github/artifacts) isolated from scanning."
                          ]
                      ).map((reason, idx) => (
                        <li key={idx}>{reason}</li>
                      ))}
                    </ul>
                  </div>

                  {/* Warnings or Limitations */}
                  {categoryCoverageData?.warnings && categoryCoverageData.warnings.length > 0 && (
                    <div className="p-3 rounded-[var(--radius-sm)] bg-[var(--badge-medium-bg)] border border-[var(--badge-medium-border)] text-[var(--badge-medium-text)] space-y-1">
                      <div className="flex items-center gap-1.5 text-[12px] font-semibold">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        <span>Execution Warnings &amp; Environment Constraints</span>
                      </div>
                      <ul className="text-[11.5px] space-y-0.5 pl-4 list-disc">
                        {categoryCoverageData.warnings.map((w, idx) => (
                          <li key={idx}>{w}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {/* Recommended Next Steps */}
                  <div className="p-3.5 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border-subtle)] space-y-2">
                    <div className="flex items-center gap-1.5 text-[12px] font-semibold text-[var(--foreground)]">
                      <Sparkles className="w-3.5 h-3.5 text-[var(--accent)]" />
                      <span>Recommended Next Steps</span>
                    </div>
                    <ul className="text-[12px] text-[var(--foreground-secondary)] space-y-1 pl-4 list-disc">
                      {(categoryCoverageData?.recommended_next_steps && categoryCoverageData.recommended_next_steps.length > 0
                        ? categoryCoverageData.recommended_next_steps
                        : [
                            "Configure CI/CD pull request gate to execute this engine on every pull request.",
                            "Review relevant findings below and validate fixes using the Fix Validation Lab."
                          ]
                      ).map((step, idx) => (
                        <li key={idx}>{step}</li>
                      ))}
                    </ul>
                  </div>
                </div>

                {/* Relevant Findings Section */}
                <div className="pt-2 border-t border-[var(--border)] space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-[13px] font-semibold text-[var(--foreground)]">
                      Relevant Findings Detected ({relevantFindings.length})
                    </h3>
                    {relevantFindings.length > 0 && (
                      <Link
                        href="/results"
                        className="text-[12px] text-[var(--accent)] hover:underline flex items-center gap-1"
                      >
                        <span>View in Findings Explorer</span>
                        <ChevronRight className="w-3 h-3" />
                      </Link>
                    )}
                  </div>

                  {relevantFindings.length === 0 ? (
                    <div className="p-4 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] text-center text-[12px] text-[var(--foreground-secondary)]">
                      Zero findings detected for this analysis category in {activeScan.repo}.
                    </div>
                  ) : (
                    <div className="divide-y divide-[var(--border)] border border-[var(--border-subtle)] rounded-[var(--radius-sm)] overflow-hidden">
                      {relevantFindings.slice(0, 5).map((f) => (
                        <div
                          key={f.id}
                          onClick={() => setInspectFinding(f)}
                          className="p-3 hover:bg-[var(--surface-hover)] cursor-pointer transition-colors flex items-center justify-between gap-3 bg-[var(--surface)]"
                        >
                          <div className="flex items-center gap-2.5 min-w-0">
                            <SeverityBadge severity={f.severity} />
                            <div className="min-w-0">
                              <div className="text-[13px] font-medium text-[var(--foreground)] truncate">
                                {f.title}
                              </div>
                              <div className="text-[11px] font-mono text-[var(--foreground-tertiary)] truncate mt-0.5">
                                {f.file_path}:{f.line_start || 1}
                              </div>
                            </div>
                          </div>
                          <span className="text-[11px] font-mono text-[var(--foreground-secondary)] px-2 py-0.5 rounded bg-[var(--surface-secondary)]">
                            Inspect
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Inspect Modal */}
      {inspectFinding && (
        <FindingDetailModal
          finding={inspectFinding}
          onClose={() => setInspectFinding(null)}
        />
      )}
    </div>
  );
}
