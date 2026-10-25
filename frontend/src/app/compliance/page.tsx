"use client";

import React, { useState, useEffect, useMemo } from "react";
import Link from "next/link";
import {
  FileCheck2,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Info,
  Download,
  Copy,
  Check,
  ExternalLink,
  Filter,
  RotateCcw,
  BookOpen,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { api } from "@/lib/api";
import { ScanResult, ComplianceEvidenceReport, ComplianceControlMapping } from "@/lib/types";
import { EmptyState } from "@/components/common/EmptyState";
import { formatTimeAgo } from "@/lib/utils";

export default function CompliancePage() {
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [report, setReport] = useState<ComplianceEvidenceReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [frameworkFilter, setFrameworkFilter] = useState<string>("ALL");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [copiedMd, setCopiedMd] = useState(false);

  useEffect(() => {
    const saved = storage.getScanHistory();
    setHistory(saved);
    if (saved.length > 0) {
      setSelectedScan(saved[0]);
    }
  }, []);

  useEffect(() => {
    if (!selectedScan) return;

    let mounted = true;
    async function loadCompliance() {
      if (!selectedScan) return;
      setLoading(true);
      try {
        let rep: ComplianceEvidenceReport;
        try {
          rep = await api.getScanCompliance(selectedScan.scan_id);
        } catch {
          rep = await api.generateCustomCompliance(selectedScan);
        }
        if (mounted) {
          setReport(rep);
        }
      } catch (err) {
        console.warn("Failed to load compliance report:", err);
      } finally {
        if (mounted) setLoading(false);
      }
    }

    loadCompliance();
    return () => {
      mounted = false;
    };
  }, [selectedScan]);

  const filteredControls = useMemo(() => {
    if (!report) return [];
    return report.controls.filter((c) => {
      if (frameworkFilter !== "ALL") {
        if (frameworkFilter === "ASVS" && !c.control_id.startsWith("ASVS")) return false;
        if (frameworkFilter === "SSDF" && !c.control_id.startsWith("SSDF")) return false;
      }
      if (statusFilter !== "ALL") {
        if (statusFilter === "PASS" && c.status !== "PASS_WITH_EVIDENCE") return false;
        if (statusFilter === "FAIL" && c.status !== "FAIL_DETECTED_FLAWS") return false;
        if (statusFilter === "PARTIAL" && c.status !== "PARTIAL_EVIDENCE") return false;
      }
      return true;
    });
  }, [report, frameworkFilter, statusFilter]);

  const exportJSON = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `compliance-evidence-${selectedScan?.owner}-${selectedScan?.repo}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyMarkdown = () => {
    if (!report || !selectedScan) return;
    let md = `# RepoShield Compliance Evidence Pack\n`;
    md += `Repository: ${selectedScan.owner}/${selectedScan.repo}\n`;
    md += `Evaluated At: ${new Date().toISOString()}\n\n`;
    md += `## Legal & Audit Disclaimer\n${report.disclaimer}\n\n`;
    md += `## Summary\n`;
    md += `- Total Controls Evaluated: ${report.total_controls}\n`;
    md += `- Passing with Evidence: ${report.passed_controls_count}\n`;
    md += `- Failing (Flaws Detected): ${report.failing_controls_count}\n\n`;
    md += `## Controls Mapping\n\n`;

    report.controls.forEach((c) => {
      md += `### ${c.control_id}: ${c.title} (${c.framework})\n`;
      md += `- **Status**: ${c.status_label}\n`;
      md += `- **Requirement**: ${c.description}\n`;
      md += `- **Evidence Summary**: ${c.evidence_summary}\n`;
      md += `- **Scope Limitation**: ${c.limitations_note}\n\n`;
    });

    navigator.clipboard.writeText(md);
    setCopiedMd(true);
    setTimeout(() => setCopiedMd(false), 2000);
  };

  if (!selectedScan && history.length === 0) {
    return (
      <EmptyState
        icon={FileCheck2}
        title="No Compliance Evidence Packs Available"
        description="Scan any repository to generate automated evidence mappings for OWASP ASVS and NIST SSDF controls."
        actionText="Scan a Repository"
        actionHref="/scan"
      />
    );
  }

  return (
    <div className="space-y-4">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[var(--border-color)]">
        <div>
          <h1 className="text-[22px] font-semibold tracking-tight text-[var(--text-primary)]">
            Compliance Evidence Pack
          </h1>
          <p className="text-[13px] text-[var(--text-secondary)] mt-0.5">
            Automated control-to-evidence mappings for OWASP ASVS v4.0 and NIST SSDF SP 800-218.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {history.length > 1 && (
            <select
              value={selectedScan?.scan_id}
              onChange={(e) => {
                const found = history.find((s) => s.scan_id === e.target.value);
                if (found) setSelectedScan(found);
              }}
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
            onClick={copyMarkdown}
            className="macos-button h-7 text-[12px] px-2.5 flex items-center gap-1.5"
            title="Copy Markdown Report"
          >
            {copiedMd ? <Check className="w-3.5 h-3.5 text-[#34C759]" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedMd ? "Copied" : "Copy Report"}</span>
          </button>

          <button
            onClick={exportJSON}
            className="macos-button h-7 text-[12px] px-2.5 flex items-center gap-1.5"
            title="Download JSON Evidence Pack"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* KPI Summary Inset */}
      <div className="macos-panel p-3.5 grid grid-cols-2 sm:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-[var(--border-subtle)] text-[12px]">
        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Controls Evaluated</div>
          <div className="text-xl font-semibold text-[var(--text-primary)]">
            {report?.total_controls ?? 0}
          </div>
        </div>
        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Pass (Evidence Supported)</div>
          <div className="text-xl font-semibold text-[#34C759]">
            {report?.passed_controls_count ?? 0}
          </div>
        </div>
        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Failing (Flaws Detected)</div>
          <div className="text-xl font-semibold text-[#FF453A]">
            {report?.failing_controls_count ?? 0}
          </div>
        </div>
        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Partial / Missing Evidence</div>
          <div className="text-xl font-semibold text-[#FF9500]">
            {report?.partial_controls_count ?? 0}
          </div>
        </div>
      </div>

      {/* Mandatory Audit Disclaimer Banner */}
      <div className="p-3.5 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] flex items-start gap-3">
        <Info className="w-4 h-4 text-[#0A84FF] shrink-0 mt-0.5" />
        <div className="text-[12px] text-[var(--text-secondary)] space-y-1">
          <div className="font-semibold text-[var(--text-primary)]">
            Audit Integrity &amp; Legal Disclaimer
          </div>
          <p>{report?.disclaimer}</p>
        </div>
      </div>

      {/* Filters Toolbar */}
      <div className="flex flex-col sm:flex-row gap-2.5 items-stretch sm:items-center justify-between">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setFrameworkFilter("ALL")}
            className={`px-3 py-1 rounded-[5px] text-[12px] font-medium transition-colors ${
              frameworkFilter === "ALL"
                ? "bg-[var(--accent)] text-white"
                : "bg-[var(--surface)] text-[var(--text-secondary)] border border-[var(--border-subtle)] hover:text-[var(--text-primary)]"
            }`}
          >
            All Frameworks
          </button>
          <button
            onClick={() => setFrameworkFilter("ASVS")}
            className={`px-3 py-1 rounded-[5px] text-[12px] font-medium transition-colors ${
              frameworkFilter === "ASVS"
                ? "bg-[var(--accent)] text-white"
                : "bg-[var(--surface)] text-[var(--text-secondary)] border border-[var(--border-subtle)] hover:text-[var(--text-primary)]"
            }`}
          >
            OWASP ASVS v4.0
          </button>
          <button
            onClick={() => setFrameworkFilter("SSDF")}
            className={`px-3 py-1 rounded-[5px] text-[12px] font-medium transition-colors ${
              frameworkFilter === "SSDF"
                ? "bg-[var(--accent)] text-white"
                : "bg-[var(--surface)] text-[var(--text-secondary)] border border-[var(--border-subtle)] hover:text-[var(--text-primary)]"
            }`}
          >
            NIST SSDF SP 800-218
          </button>
        </div>

        <div className="flex items-center gap-2">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="macos-input h-7 text-[12px] cursor-pointer"
          >
            <option value="ALL">All Statuses</option>
            <option value="PASS">Pass with Evidence</option>
            <option value="FAIL">Failing Violations</option>
            <option value="PARTIAL">Partial Evidence</option>
          </select>

          {(frameworkFilter !== "ALL" || statusFilter !== "ALL") && (
            <button
              onClick={() => {
                setFrameworkFilter("ALL");
                setStatusFilter("ALL");
              }}
              className="macos-button h-7 text-[12px] px-2 text-[var(--text-secondary)]"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Reset</span>
            </button>
          )}
        </div>
      </div>

      {/* Controls List */}
      {loading ? (
        <div className="macos-panel p-10 text-center text-[12px] text-[var(--text-secondary)]">
          Synthesizing compliance mappings across OWASP ASVS and NIST SSDF...
        </div>
      ) : filteredControls.length === 0 ? (
        <div className="macos-panel p-10 text-center space-y-2">
          <ShieldCheck className="w-8 h-8 text-[#34C759] mx-auto" />
          <div className="text-[14px] font-medium text-[var(--text-primary)]">
            No Controls Match Active Filters
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          {filteredControls.map((ctrl) => (
            <div
              key={ctrl.control_id}
              className="macos-panel p-4 space-y-3 border border-[var(--border-color)]"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-[var(--border-subtle)] pb-2.5">
                <div className="flex items-center gap-2.5">
                  <span className="font-mono text-[12px] font-bold px-2 py-0.5 rounded bg-[var(--surface)] text-[var(--text-primary)] border border-[var(--border-subtle)]">
                    {ctrl.control_id}
                  </span>
                  <span className="text-[11px] text-[var(--text-secondary)] font-medium">
                    {ctrl.section}
                  </span>
                  <span className="text-[11px] px-2 py-0.5 rounded bg-[var(--bg-secondary)] text-[var(--text-muted)] border border-[var(--border-subtle)]">
                    {ctrl.framework.replace("_", " ")}
                  </span>
                </div>

                <span
                  className={`text-[11px] font-semibold px-2 py-0.5 rounded self-start sm:self-auto ${
                    ctrl.status === "PASS_WITH_EVIDENCE"
                      ? "bg-emerald-500/10 text-emerald-500 border border-emerald-500/20"
                      : ctrl.status === "FAIL_DETECTED_FLAWS"
                      ? "bg-red-500/10 text-red-500 border border-red-500/20"
                      : "bg-amber-500/10 text-amber-500 border border-amber-500/20"
                  }`}
                >
                  {ctrl.status_label}
                </span>
              </div>

              <div>
                <h3 className="text-[14px] font-semibold text-[var(--text-primary)]">
                  {ctrl.title}
                </h3>
                <p className="text-[12px] text-[var(--text-secondary)] mt-1 leading-relaxed">
                  {ctrl.description}
                </p>
              </div>

              {/* Supporting Evidence Inset */}
              <div className="p-3 rounded-[6px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] space-y-1.5 text-[12px]">
                <div className="font-semibold text-[var(--text-primary)] flex items-center justify-between">
                  <span>Audit Evidence Telemetry:</span>
                  {ctrl.finding_count > 0 && (
                    <span className="font-mono text-[11px] text-[#FF453A]">
                      {ctrl.finding_count} Associated Findings
                    </span>
                  )}
                </div>
                <p className="text-[var(--text-primary)]">{ctrl.evidence_summary}</p>
                <div className="text-[11px] text-[var(--text-muted)] flex items-start gap-1.5 pt-1">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-500 shrink-0 mt-0.5" />
                  <span>Scope Limitation: {ctrl.limitations_note}</span>
                </div>
              </div>

              {/* Findings Links if Failing */}
              {ctrl.supporting_finding_ids.length > 0 && (
                <div className="flex items-center justify-between pt-1 text-[11px] text-[var(--text-muted)]">
                  <span>Linked Findings: {ctrl.supporting_finding_ids.length} entries</span>
                  <Link
                    href="/results"
                    className="macos-button h-6 text-[11px] px-2 flex items-center gap-1"
                  >
                    <span>Inspect in Findings Explorer</span>
                    <ExternalLink className="w-3 h-3 text-[var(--text-muted)]" />
                  </Link>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
