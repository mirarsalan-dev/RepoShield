"use client";

import React, { useState, useEffect, useMemo, Suspense } from "react";
import Link from "next/link";
import {
  TrendingDown,
  Clock,
  AlertTriangle,
  CheckCircle2,
  Calendar,
  Layers,
  ArrowRight,
  GitCompare,
  Trash2,
  Download,
  Info,
  Package,
  FileCode,
  ShieldAlert,
  Flame,
  Check,
  ExternalLink,
  ChevronRight,
  Sparkles,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { ScanResult, Finding, Severity } from "@/lib/types";
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import { formatTimeAgo } from "@/lib/utils";

export default function SecurityDebtPage() {
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>("");
  const [baseScanId, setBaseScanId] = useState<string>("");
  const [activeTab, setActiveTab] = useState<"planner" | "rootcause" | "snapshots">("planner");

  useEffect(() => {
    const scans = storage.getScanHistory();
    setHistory(scans);
    if (scans.length >= 2) {
      setSelectedScanId(scans[0].scan_id);
      setBaseScanId(scans[1].scan_id);
    } else if (scans.length === 1) {
      setSelectedScanId(scans[0].scan_id);
    }
  }, []);

  const selectedScan = history.find((s) => s.scan_id === selectedScanId) || history[0];
  const baseScan = history.find((s) => s.scan_id === baseScanId);
  const findings = selectedScan?.findings || [];

  // Configurable transparent effort calculation rules (heuristic developer hours)
  const calculateEffortHours = (f: Finding): { hours: number; rule: string } => {
    if (f.category === "DEPENDENCIES") {
      if (f.fixed_version) {
        return { hours: 0.5, rule: "Standard package bump to verified upstream version" };
      }
      return { hours: 2.5, rule: "Manual transitive dependency investigation / major breaking change review" };
    }
    if (f.category === "SECRETS") {
      return { hours: 2.0, rule: "Credential revocation, provider token re-generation, and secrets vault migration" };
    }
    if (f.category === "SAST") {
      if (f.severity === "CRITICAL" || f.severity === "HIGH") {
        return { hours: 4.0, rule: "Source-to-sink code refactor, parameterization, and integration test verification" };
      }
      return { hours: 1.5, rule: "Local sanitization / defensive programming adjustment" };
    }
    if (f.category === "INFRASTRUCTURE") {
      return { hours: 1.0, rule: "Dockerfile instruction hardening or workflow permission adjustment" };
    }
    return { hours: 1.0, rule: "General code or configuration adjustment" };
  };

  const totalEstimatedHours = useMemo(() => {
    return findings.reduce((acc, f) => acc + calculateEffortHours(f).hours, 0);
  }, [findings]);

  // Suggested Remediation Order (Ranked by severity, exploitability, CISA KEV, and fixed version availability)
  const prioritizedRemediation = useMemo(() => {
    return [...findings].sort((a, b) => {
      // 1. CISA KEV
      if (a.cisa_kev && !b.cisa_kev) return -1;
      if (!a.cisa_kev && b.cisa_kev) return 1;

      // 2. High EPSS
      const epssA = a.epss_score || 0;
      const epssB = b.epss_score || 0;
      if (epssA !== epssB) return epssB - epssA;

      // 3. Severity
      const sevOrder: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
      const sevDiff = (sevOrder[b.severity] || 0) - (sevOrder[a.severity] || 0);
      if (sevDiff !== 0) return sevDiff;

      // 4. Easy fix availability (fixed_version present)
      if (a.fixed_version && !b.fixed_version) return -1;
      if (!a.fixed_version && b.fixed_version) return 1;

      return 0;
    });
  }, [findings]);

  // Root Cause Grouping 1: By Dependency Package
  const packageGroups = useMemo(() => {
    const map = new Map<string, Finding[]>();
    findings
      .filter((f) => f.category === "DEPENDENCIES" && f.package_name)
      .forEach((f) => {
        const pkg = f.package_name!;
        if (!map.has(pkg)) map.set(pkg, []);
        map.get(pkg)!.push(f);
      });
    return Array.from(map.entries()).sort((a, b) => b[1].length - a[1].length);
  }, [findings]);

  // Root Cause Grouping 2: By File Location
  const fileGroups = useMemo(() => {
    const map = new Map<string, Finding[]>();
    findings.forEach((f) => {
      if (!map.has(f.file_path)) map.set(f.file_path, []);
      map.get(f.file_path)!.push(f);
    });
    return Array.from(map.entries())
      .filter(([_, list]) => list.length > 1)
      .sort((a, b) => b[1].length - a[1].length);
  }, [findings]);

  // Target SLA Dates
  const getSlaDate = (severity: Severity): { label: string; days: number; isOverdue: boolean } => {
    const days = severity === "CRITICAL" ? 7 : severity === "HIGH" ? 30 : severity === "MEDIUM" ? 90 : 180;
    return { label: `${days}d SLA`, days, isOverdue: false };
  };

  // Compare scans if two are selected
  let newFindings: Finding[] = [];
  let resolvedFindings: Finding[] = [];
  if (baseScan && selectedScan && baseScan.scan_id !== selectedScan.scan_id) {
    const baseFps = new Set(baseScan.findings.map((f) => f.fingerprint || f.id));
    const targetFps = new Set(selectedScan.findings.map((f) => f.fingerprint || f.id));
    newFindings = selectedScan.findings.filter((f) => !baseFps.has(f.fingerprint || f.id));
    resolvedFindings = baseScan.findings.filter((f) => !targetFps.has(f.fingerprint || f.id));
  }

  const handleClearHistory = () => {
    if (window.confirm("Are you sure you want to clear your local browser scan history?")) {
      storage.clearAllHistory();
      setHistory([]);
      setSelectedScanId("");
      setBaseScanId("");
    }
  };

  if (!selectedScan && history.length === 0) {
    return (
      <div className="macos-panel p-12 text-center max-w-lg mx-auto space-y-3">
        <Clock className="w-10 h-10 text-[var(--text-muted)] mx-auto" />
        <h3 className="text-[15px] font-semibold text-[var(--text-primary)]">
          No Historical Scan Snapshots
        </h3>
        <p className="text-[13px] text-[var(--text-secondary)] leading-relaxed">
          Run your first security scan from &ldquo;New Scan&rdquo;. Snapshots are stored securely in your browser&apos;s local storage without any remote database persistence.
        </p>
        <Link href="/scan" className="macos-button macos-button-primary inline-flex text-[12px] mt-2">
          Start First Scan
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[var(--border-color)]">
        <div>
          <h1 className="text-[22px] font-semibold tracking-tight text-[var(--text-primary)]">
            Security Debt &amp; Remediation Planner
          </h1>
          <p className="text-[13px] text-[var(--text-secondary)] mt-0.5">
            Transparent effort estimation, multi-finding root cause grouping, and evidence-ordered remediation planning.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {history.length > 1 && (
            <select
              value={selectedScanId}
              onChange={(e) => setSelectedScanId(e.target.value)}
              className="macos-input h-7 text-[12px] cursor-pointer"
            >
              {history.map((s) => (
                <option key={s.scan_id} value={s.scan_id}>
                  {s.owner}/{s.repo} ({formatTimeAgo(s.completed_at || s.started_at)})
                </option>
              ))}
            </select>
          )}

          <button
            onClick={handleClearHistory}
            className="macos-button h-7 text-[12px] px-2 text-[#FF453A] hover:bg-red-500/10 flex items-center gap-1"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear History</span>
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="macos-panel p-3.5 grid grid-cols-2 sm:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-[var(--border-subtle)] text-[12px]">
        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Unresolved Findings</div>
          <div className="text-xl font-semibold text-[var(--text-primary)]">
            {findings.length}
          </div>
        </div>

        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Estimated Remediation Effort</div>
          <div className="text-xl font-semibold text-[#FF9500]">
            ~{Math.round(totalEstimatedHours)} hrs <span className="text-[11px] font-normal text-[var(--text-muted)]">(est.)</span>
          </div>
        </div>

        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Multi-Finding Packages</div>
          <div className="text-xl font-semibold text-[#0A84FF]">
            {packageGroups.filter(([_, list]) => list.length > 1).length}
          </div>
        </div>

        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Local Snapshots</div>
          <div className="text-xl font-semibold text-[var(--text-primary)]">
            {history.length}
          </div>
        </div>
      </div>

      {/* Effort Methodology Disclosure Banner */}
      <div className="p-3.5 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] flex items-start gap-3">
        <Info className="w-4 h-4 text-[#0A84FF] shrink-0 mt-0.5" />
        <div className="text-[12px] text-[var(--text-secondary)] space-y-1">
          <div className="font-medium text-[var(--text-primary)]">
            Remediation Effort Estimation Methodology
          </div>
          <p>
            Effort hours are heuristic approximations based on finding classification: Standard package updates (~0.5h), credential revocation &amp; vault rotation (~2h), and AST injection code refactoring (~4h). All hours are estimates to assist engineering sprint planning and do not represent measured historical time.
          </p>
        </div>
      </div>

      {/* Tab Selector */}
      <div className="flex items-center gap-2 border-b border-[var(--border-subtle)] pb-2 text-[12px]">
        <button
          onClick={() => setActiveTab("planner")}
          className={`px-3 py-1.5 rounded-[6px] font-medium transition-colors ${
            activeTab === "planner"
              ? "bg-[var(--accent)] text-white"
              : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
          }`}
        >
          Suggested Remediation Order ({prioritizedRemediation.length})
        </button>
        <button
          onClick={() => setActiveTab("rootcause")}
          className={`px-3 py-1.5 rounded-[6px] font-medium transition-colors ${
            activeTab === "rootcause"
              ? "bg-[var(--accent)] text-white"
              : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
          }`}
        >
          Multi-Finding Root Causes ({packageGroups.length + fileGroups.length})
        </button>
        <button
          onClick={() => setActiveTab("snapshots")}
          className={`px-3 py-1.5 rounded-[6px] font-medium transition-colors ${
            activeTab === "snapshots"
              ? "bg-[var(--accent)] text-white"
              : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
          }`}
        >
          Snapshot Comparison ({history.length} Saved)
        </button>
      </div>

      {/* Tab 1: Suggested Remediation Order */}
      {activeTab === "planner" && (
        <div className="space-y-3">
          {prioritizedRemediation.length === 0 ? (
            <div className="macos-panel p-8 text-center text-[12px] text-[var(--text-secondary)]">
              Zero findings in active scan. Repository is free of open security debt.
            </div>
          ) : (
            prioritizedRemediation.map((finding, idx) => {
              const effort = calculateEffortHours(finding);
              const sla = getSlaDate(finding.severity);

              return (
                <div
                  key={finding.id}
                  className="macos-panel p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 border border-[var(--border-color)] hover:border-[var(--border-subtle)] transition-colors"
                >
                  <div className="flex items-start sm:items-center gap-3">
                    <span className="font-mono text-[12px] font-bold text-[var(--text-muted)] w-6 text-center">
                      #{idx + 1}
                    </span>
                    <SeverityBadge severity={finding.severity} />
                    <div>
                      <div className="text-[13px] font-semibold text-[var(--text-primary)] flex items-center gap-2">
                        <span>{finding.title}</span>
                        {finding.cisa_kev && (
                          <span className="text-[10px] font-medium px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
                            CISA KEV
                          </span>
                        )}
                        {finding.epss_score && finding.epss_score > 0.3 && (
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-red-500/10 text-red-500">
                            EPSS: {(finding.epss_score * 100).toFixed(0)}%
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-[var(--text-secondary)] font-mono mt-0.5">
                        {finding.file_path}{finding.line_start ? `:L${finding.line_start}` : ""} • Category: {finding.category}
                      </div>
                      <div className="text-[11px] text-[var(--text-muted)] mt-1">
                        Effort Rationale: {effort.rule}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 self-end sm:self-auto">
                    <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[var(--surface)] text-[var(--text-secondary)] border border-[var(--border-subtle)]">
                      {sla.label}
                    </span>
                    <span className="text-[11px] font-mono font-medium px-2 py-0.5 rounded bg-[var(--bg-secondary)] text-[#FF9500] border border-[var(--border-subtle)]">
                      ~{effort.hours}h (est.)
                    </span>
                    <Link
                      href="/review-workbench"
                      className="macos-button h-6 text-[11px] px-2 flex items-center gap-1"
                    >
                      <span>Triage</span>
                      <ChevronRight className="w-3 h-3 text-[var(--text-muted)]" />
                    </Link>
                  </div>
                </div>
              );
            })
          )}
        </div>
      )}

      {/* Tab 2: Root Cause Grouping */}
      {activeTab === "rootcause" && (
        <div className="space-y-4">
          {/* Dependency Multi-Fixes */}
          <div className="space-y-2">
            <h3 className="text-[13px] font-semibold text-[var(--text-primary)] flex items-center gap-1.5">
              <Package className="w-4 h-4 text-[#0A84FF]" />
              <span>Multi-Finding Dependencies (Single Update Resolves Multiple Advisories)</span>
            </h3>

            {packageGroups.length === 0 ? (
              <div className="macos-panel p-6 text-center text-[12px] text-[var(--text-secondary)]">
                No third-party dependencies with multiple security advisories identified.
              </div>
            ) : (
              packageGroups.map(([pkg, list]) => (
                <div
                  key={pkg}
                  className="macos-panel p-3.5 border border-[var(--border-color)] space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-[13px] text-[var(--text-primary)]">
                        {pkg}
                      </span>
                      <span className="text-[11px] px-2 py-0.5 rounded bg-blue-500/10 text-blue-500 border border-blue-500/20 font-medium">
                        {list.length} Vulnerabilities Resolved by 1 Upgrade
                      </span>
                    </div>
                    {list[0].fixed_version && (
                      <span className="text-[11px] font-mono text-[#34C759] font-medium">
                        Target Version: {list[0].fixed_version}
                      </span>
                    )}
                  </div>

                  <div className="space-y-1 pl-2 border-l-2 border-[var(--border-subtle)]">
                    {list.map((f) => (
                      <div key={f.id} className="text-[12px] text-[var(--text-secondary)] flex items-center gap-2">
                        <SeverityBadge severity={f.severity} />
                        <span className="font-medium text-[var(--text-primary)]">{f.title}</span>
                        {f.cve_id && <span className="font-mono text-[11px] text-[var(--text-muted)]">({f.cve_id})</span>}
                      </div>
                    ))}
                  </div>
                </div>
              ))
            )}
          </div>

          {/* File-Level Multi-Flaws */}
          <div className="space-y-2 pt-2">
            <h3 className="text-[13px] font-semibold text-[var(--text-primary)] flex items-center gap-1.5">
              <FileCode className="w-4 h-4 text-[#FF9500]" />
              <span>Clustered Source Files (Multiple Flaws in Single Module)</span>
            </h3>

            {fileGroups.length === 0 ? (
              <div className="macos-panel p-6 text-center text-[12px] text-[var(--text-secondary)]">
                No individual files containing clustered flaws.
              </div>
            ) : (
              fileGroups.map(([filePath, list]) => (
                <div
                  key={filePath}
                  className="macos-panel p-3.5 border border-[var(--border-color)] space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[12px] font-semibold text-[var(--text-primary)]">
                      {filePath}
                    </span>
                    <span className="text-[11px] px-2 py-0.5 rounded bg-amber-500/10 text-amber-500 font-medium">
                      {list.length} Flaws
                    </span>
                  </div>

                  <div className="space-y-1 pl-2 border-l-2 border-[var(--border-subtle)]">
                    {list.map((f) => (
                      <div key={f.id} className="text-[12px] text-[var(--text-secondary)] flex items-center gap-2">
                        <SeverityBadge severity={f.severity} />
                        <span className="text-[var(--text-primary)]">{f.title}</span>
                        {f.line_start && (
                          <span className="font-mono text-[11px] text-[var(--text-muted)]">
                            :L{f.line_start}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Tab 3: Snapshots Comparison */}
      {activeTab === "snapshots" && (
        <div className="space-y-4">
          {history.length < 2 ? (
            <div className="macos-panel p-8 text-center text-[12px] text-[var(--text-secondary)] space-y-2">
              <GitCompare className="w-6 h-6 text-[var(--text-muted)] mx-auto" />
              <div>At least two scans are required to compare snapshot diffs.</div>
              <p className="text-[11px] text-[var(--text-muted)]">
                Run another scan to track newly introduced or resolved security findings across git commits.
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="macos-panel p-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-[11px] font-semibold uppercase text-[var(--text-secondary)]">
                    Base Scan (Earlier Snapshot)
                  </label>
                  <select
                    value={baseScanId}
                    onChange={(e) => setBaseScanId(e.target.value)}
                    className="macos-input w-full mt-1 text-[12px]"
                  >
                    {history.map((s) => (
                      <option key={s.scan_id} value={s.scan_id}>
                        {s.owner}/{s.repo} @ {s.commit_sha ? s.commit_sha.slice(0, 7) : "HEAD"} ({s.started_at.slice(0, 10)})
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="text-[11px] font-semibold uppercase text-[var(--text-secondary)]">
                    Target Scan (Current Snapshot)
                  </label>
                  <select
                    value={selectedScanId}
                    onChange={(e) => setSelectedScanId(e.target.value)}
                    className="macos-input w-full mt-1 text-[12px]"
                  >
                    {history.map((s) => (
                      <option key={s.scan_id} value={s.scan_id}>
                        {s.owner}/{s.repo} @ {s.commit_sha ? s.commit_sha.slice(0, 7) : "HEAD"} ({s.started_at.slice(0, 10)})
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Comparison Summary KPIs */}
              <div className="grid grid-cols-2 gap-4">
                <div className="macos-panel p-3.5 space-y-1 border-l-4 border-[#FF453A]">
                  <div className="text-[11px] uppercase font-mono text-[#FF453A]">
                    Newly Introduced Flaws
                  </div>
                  <div className="text-2xl font-bold text-[var(--text-primary)]">
                    {newFindings.length}
                  </div>
                </div>

                <div className="macos-panel p-3.5 space-y-1 border-l-4 border-[#34C759]">
                  <div className="text-[11px] uppercase font-mono text-[#34C759]">
                    Resolved Flaws in Target
                  </div>
                  <div className="text-2xl font-bold text-[var(--text-primary)]">
                    {resolvedFindings.length}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
