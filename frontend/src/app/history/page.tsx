"use client";

import React, { useState, useEffect, useRef } from "react";
import Link from "next/link";
import {
  History,
  Trash2,
  GitBranch,
  Clock,
  HardDrive,
  Download,
  Upload,
  GitCompare,
  X,
  ArrowRight,
  ShieldAlert,
  FileText,
  CheckCircle2,
  AlertTriangle,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { api } from "@/lib/api";
import { ScanResult, Finding } from "@/lib/types";
import { formatDate, formatTimeAgo } from "@/lib/utils";
import { EmptyState } from "@/components/common/EmptyState";
import { MacTrafficLights } from "@/components/common/Icons";
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import { FindingDetailModal } from "@/components/findings/FindingDetailModal";
import { AnimatedDialog } from "@/components/motion";

export default function HistoryPage() {
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [selectedForCompare, setSelectedForCompare] = useState<string[]>([]);
  const [isCompareModalOpen, setIsCompareModalOpen] = useState(false);
  const [downloadingScanId, setDownloadingScanId] = useState<string | null>(null);
  const [inspectFinding, setInspectFinding] = useState<Finding | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setHistory(storage.getScanHistory());
  }, []);

  const handleDelete = (scanId: string) => {
    if (confirm("Remove this scan from local browser storage?")) {
      storage.deleteScan(scanId);
      setHistory(storage.getScanHistory());
      setSelectedForCompare((prev) => prev.filter((id) => id !== scanId));
    }
  };

  const handleClearAll = () => {
    if (
      confirm(
        "Clear all local scan history? This action cannot be undone as RepoShield operates without any backend database."
      )
    ) {
      storage.clearAllHistory();
      setHistory([]);
      setSelectedForCompare([]);
    }
  };

  const handleExportSession = () => {
    const sessionJson = storage.exportSession();
    const blob = new Blob([sessionJson], { type: "application/json" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `reposhield-session-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  };

  const handleImportSession = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        const result = storage.importSession(content);
        if (result.success) {
          alert(result.message);
          setHistory(storage.getScanHistory());
        } else {
          alert(`Import failed: ${result.message}`);
        }
      }
    };
    reader.readAsText(file);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const handleDownloadPdf = async (scan: ScanResult) => {
    setDownloadingScanId(scan.scan_id);
    try {
      const blob = await api.downloadReportPdf(scan);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `reposhield-${scan.repo}-${scan.scan_id.slice(0, 8)}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(err.message || "Failed to download PDF report.");
    } finally {
      setDownloadingScanId(null);
    }
  };

  const toggleSelectForCompare = (scanId: string) => {
    if (selectedForCompare.includes(scanId)) {
      setSelectedForCompare(selectedForCompare.filter((id) => id !== scanId));
    } else {
      if (selectedForCompare.length >= 2) {
        setSelectedForCompare([selectedForCompare[1], scanId]);
      } else {
        setSelectedForCompare([...selectedForCompare, scanId]);
      }
    }
  };

  if (history.length === 0) {
    return (
      <EmptyState
        icon={History}
        title="No Scan History"
        description="Completed security scans are retained strictly in your browser's localStorage. Zero database persistence."
        actionText="Scan a Repository"
        actionHref="/scan"
      />
    );
  }

  const compareScanA = history.find((s) => s.scan_id === selectedForCompare[0]);
  const compareScanB = history.find((s) => s.scan_id === selectedForCompare[1]);

  // Compute fine-grained diff between Scan A (Baseline) and Scan B (Candidate)
  let newFindings: Finding[] = [];
  let resolvedFindings: Finding[] = [];
  let unchangedFindings: Finding[] = [];
  let severityChangedFindings: { finding: Finding; oldSeverity: string; newSeverity: string }[] = [];

  if (compareScanA && compareScanB) {
    const aMap = new Map<string, Finding>();
    compareScanA.findings.forEach((f) => {
      const fp = f.fingerprint || `${f.detector_name}:${f.rule_id}:${f.file_path}`;
      aMap.set(fp, f);
    });

    const bMap = new Map<string, Finding>();
    compareScanB.findings.forEach((f) => {
      const fp = f.fingerprint || `${f.detector_name}:${f.rule_id}:${f.file_path}`;
      bMap.set(fp, f);
    });

    compareScanB.findings.forEach((f) => {
      const fp = f.fingerprint || `${f.detector_name}:${f.rule_id}:${f.file_path}`;
      const old = aMap.get(fp);
      if (!old) {
        newFindings.push(f);
      } else {
        if (old.severity !== f.severity) {
          severityChangedFindings.push({ finding: f, oldSeverity: old.severity, newSeverity: f.severity });
        } else {
          unchangedFindings.push(f);
        }
      }
    });

    compareScanA.findings.forEach((f) => {
      const fp = f.fingerprint || `${f.detector_name}:${f.rule_id}:${f.file_path}`;
      if (!bMap.has(fp)) {
        resolvedFindings.push(f);
      }
    });
  }

  return (
    <div className="space-y-6 max-w-6xl">
      {/* Hidden File Input for Importing Sessions */}
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleImportSession}
        accept=".json"
        className="hidden"
      />

      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[var(--border-subtle)]">
        <div>
          <h1 className="macos-title flex items-center gap-2">
            <History className="w-5 h-5 text-[var(--accent)]" />
            <span>Scan History &amp; Diff Timeline</span>
          </h1>
          <p className="macos-subtitle">
            {history.length} {history.length === 1 ? "record" : "records"} stored strictly in local browser memory. No data stored on remote servers.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {selectedForCompare.length === 2 && (
            <button
              onClick={() => setIsCompareModalOpen(true)}
              className="macos-button-primary flex items-center gap-1.5 text-[12px]"
            >
              <GitCompare className="w-3.5 h-3.5" />
              <span>Compare Selected (2)</span>
            </button>
          )}

          <button
            onClick={handleExportSession}
            className="macos-button flex items-center gap-1.5 text-[12px]"
            title="Export full session as portable JSON"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Session</span>
          </button>

          <button
            onClick={() => fileInputRef.current?.click()}
            className="macos-button flex items-center gap-1.5 text-[12px]"
            title="Import session file"
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Import Session</span>
          </button>

          <button
            onClick={handleClearAll}
            className="macos-button hover:text-[#FF3B30] flex items-center gap-1.5 text-[12px]"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear History</span>
          </button>
        </div>
      </div>

      {/* Privacy Notice Banner */}
      <div className="macos-panel p-3.5 flex items-start gap-3 text-[12px] text-[var(--text-secondary)]">
        <HardDrive className="w-4 h-4 text-[var(--accent)] flex-shrink-0 mt-0.5" />
        <div>
          <span className="font-medium text-[var(--text-primary)]">Client-Side Persistence Only: </span>
          Locally stored scan records belong solely to this browser&apos;s <code className="font-mono text-[var(--text-primary)]">localStorage</code> and never synchronize across remote devices or external servers. Use &quot;Export Session&quot; to transfer sessions between machines.
        </div>
      </div>

      {/* History Table */}
      <div className="macos-panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-[13px]">
            <thead>
              <tr className="border-b border-[var(--border-subtle)] bg-[var(--bg-secondary)] text-[11px] font-medium text-[var(--text-secondary)] uppercase tracking-wider">
                <th className="py-2.5 px-3 w-8">
                  <span className="sr-only">Select</span>
                </th>
                <th className="py-2.5 px-3">Repository &amp; Branch</th>
                <th className="py-2.5 px-3">Commit SHA</th>
                <th className="py-2.5 px-3">Scan Date</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Severity Breakdown</th>
                <th className="py-2.5 px-3 text-right">Findings</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-subtle)] font-normal text-[var(--text-primary)]">
              {history.map((scan) => {
                const isSelected = selectedForCompare.includes(scan.scan_id);
                const findings = scan.findings || [];
                const critCount = findings.filter((f) => f.severity === "CRITICAL").length;
                const highCount = findings.filter((f) => f.severity === "HIGH").length;
                const medCount = findings.filter((f) => f.severity === "MEDIUM").length;
                const lowCount = findings.filter((f) => f.severity === "LOW").length;

                return (
                  <tr
                    key={scan.scan_id}
                    className={`hover:bg-[var(--bg-secondary)] transition-colors ${
                      isSelected ? "bg-[var(--bg-secondary)]" : ""
                    }`}
                  >
                    <td className="py-3 px-3">
                      <input
                        type="checkbox"
                        checked={isSelected}
                        onChange={() => toggleSelectForCompare(scan.scan_id)}
                        className="rounded border-[var(--border-color)] text-[var(--accent)] accent-[var(--accent)] cursor-pointer"
                        title="Select for comparison (max 2)"
                      />
                    </td>
                    <td className="py-3 px-3 font-medium">
                      <div className="flex items-center gap-2">
                        <span>{scan.owner}/{scan.repo}</span>
                        <span className="inline-flex items-center gap-1 text-[11px] font-mono text-[var(--text-secondary)] px-1.5 py-0.5 rounded bg-[var(--bg-secondary)] border border-[var(--border-subtle)]">
                          <GitBranch className="w-2.5 h-2.5" />
                          {scan.branch}
                        </span>
                      </div>
                    </td>
                    <td className="py-3 px-3 font-mono text-[12px] text-[var(--text-secondary)]">
                      {scan.commit_sha ? scan.commit_sha.slice(0, 7) : "HEAD"}
                    </td>
                    <td className="py-3 px-3 text-[12px] text-[var(--text-secondary)]">
                      <div>{formatDate(scan.completed_at || scan.started_at)}</div>
                      <div className="text-[11px] text-[var(--text-muted)]">
                        {formatTimeAgo(scan.completed_at || scan.started_at)} ({scan.duration_seconds}s)
                      </div>
                    </td>
                    <td className="py-3 px-3 text-[12px]">
                      <span className="inline-flex items-center gap-1.5 font-medium text-[#34C759]">
                        <span className="w-1.5 h-1.5 rounded-full bg-[#34C759]" />
                        Completed
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-2 text-[11px] font-mono">
                        {critCount > 0 && (
                          <span className="text-[#FF3B30] font-semibold" title={`${critCount} Critical`}>
                            {critCount}C
                          </span>
                        )}
                        {highCount > 0 && (
                          <span className="text-[#FF9500] font-semibold" title={`${highCount} High`}>
                            {highCount}H
                          </span>
                        )}
                        {medCount > 0 && (
                          <span className="text-amber-500 font-semibold" title={`${medCount} Medium`}>
                            {medCount}M
                          </span>
                        )}
                        {lowCount > 0 && (
                          <span className="text-[#34C759]" title={`${lowCount} Low`}>
                            {lowCount}L
                          </span>
                        )}
                        {critCount === 0 && highCount === 0 && medCount === 0 && lowCount === 0 && (
                          <span className="text-[var(--text-muted)]">Clean</span>
                        )}
                      </div>
                    </td>
                    <td className="py-3 px-3 text-right font-mono text-[12px] font-medium">
                      {findings.length}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Link
                          href={`/results`}
                          className="macos-button px-2 py-1 text-[11px]"
                          title="View findings"
                        >
                          <span>View</span>
                          <ArrowRight className="w-3 h-3 ml-0.5" />
                        </Link>
                        <button
                          onClick={() => handleDownloadPdf(scan)}
                          disabled={downloadingScanId === scan.scan_id}
                          className="macos-button px-2 py-1 text-[11px]"
                          title="Download PDF report"
                        >
                          <Download className="w-3 h-3" />
                        </button>
                        <button
                          onClick={() => handleDelete(scan.scan_id)}
                          className="macos-button px-2 py-1 text-[11px] hover:text-[#FF3B30]"
                          title="Delete from local history"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Comparison Sheet Modal */}
      <AnimatedDialog
        isOpen={isCompareModalOpen && !!compareScanA && !!compareScanB}
        onClose={() => setIsCompareModalOpen(false)}
        className="w-full max-w-3xl macos-panel p-6 space-y-5 shadow-2xl max-h-[90vh] overflow-y-auto"
        ariaLabel="Scan Diff & Timeline Comparator"
      >
        {compareScanA && compareScanB && (
          <div className="space-y-5">
            {/* Header */}
            <div className="flex items-center justify-between pb-3 border-b border-[var(--border-subtle)]">
              <div className="flex items-center gap-3">
                <MacTrafficLights />
                <h2 className="text-[15px] font-semibold text-[var(--text-primary)]">
                  Scan Diff &amp; Timeline Comparator
                </h2>
              </div>
              <button
                onClick={() => setIsCompareModalOpen(false)}
                className="p-1 rounded-[6px] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-secondary)]"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Baseline Columns */}
            <div className="grid grid-cols-2 gap-4">
              <div className="p-3.5 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] space-y-1 text-[12px]">
                <div className="text-[11px] font-medium text-[var(--text-secondary)] uppercase tracking-wider">
                  Scan A (Baseline)
                </div>
                <div className="font-semibold text-[13px] text-[var(--text-primary)]">
                  {compareScanA.owner}/{compareScanA.repo}
                </div>
                <div className="font-mono text-[var(--text-muted)] text-[11px]">
                  Branch: {compareScanA.branch} ({compareScanA.commit_sha ? compareScanA.commit_sha.slice(0, 7) : "HEAD"})
                </div>
                <div className="pt-1 text-[18px] font-semibold text-[var(--text-primary)]">
                  {compareScanA.findings.length} findings
                </div>
              </div>

              <div className="p-3.5 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] space-y-1 text-[12px]">
                <div className="text-[11px] font-medium text-[var(--text-secondary)] uppercase tracking-wider">
                  Scan B (Target)
                </div>
                <div className="font-semibold text-[13px] text-[var(--text-primary)]">
                  {compareScanB.owner}/{compareScanB.repo}
                </div>
                <div className="font-mono text-[var(--text-muted)] text-[11px]">
                  Branch: {compareScanB.branch} ({compareScanB.commit_sha ? compareScanB.commit_sha.slice(0, 7) : "HEAD"})
                </div>
                <div className="pt-1 text-[18px] font-semibold text-[var(--text-primary)]">
                  {compareScanB.findings.length} findings
                </div>
              </div>
            </div>

            {/* Diff Summary Chips */}
            <div className="flex flex-wrap gap-2 text-[12px] font-mono">
              <span className="px-2.5 py-1 rounded-[6px] bg-[#FF3B30]/15 text-[#FF3B30] border border-[#FF3B30]/30 font-medium">
                +{newFindings.length} New Findings
              </span>
              <span className="px-2.5 py-1 rounded-[6px] bg-[#34C759]/15 text-[#34C759] border border-[#34C759]/30 font-medium">
                -{resolvedFindings.length} Resolved Findings
              </span>
              <span className="px-2.5 py-1 rounded-[6px] bg-[var(--bg-secondary)] text-[var(--text-secondary)] border border-[var(--border-subtle)]">
                {unchangedFindings.length} Unchanged
              </span>
              {severityChangedFindings.length > 0 && (
                <span className="px-2.5 py-1 rounded-[6px] bg-amber-500/15 text-amber-600 border border-amber-500/30">
                  {severityChangedFindings.length} Severity Shifted
                </span>
              )}
            </div>

            {/* Detailed Diff Sections */}
            <div className="space-y-4">
              {/* New Findings in B */}
              {newFindings.length > 0 && (
                <div className="space-y-2">
                  <div className="text-[12px] font-semibold text-[#FF3B30] flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>New Findings Introduced in Scan B ({newFindings.length})</span>
                  </div>
                  <div className="space-y-1.5 max-h-40 overflow-y-auto">
                    {newFindings.map((f) => (
                      <div
                        key={f.id}
                        onClick={() => setInspectFinding(f)}
                        className="p-2 rounded-[6px] bg-[var(--bg-secondary)] hover:bg-[var(--bg-hover)] border border-[var(--border-subtle)] cursor-pointer flex items-center justify-between text-[11px]"
                      >
                        <div className="flex items-center gap-2 overflow-hidden">
                          <SeverityBadge severity={f.severity} />
                          <span className="font-mono text-[var(--text-muted)] truncate">{f.file_path}</span>
                          <span className="text-[var(--text-primary)] font-medium truncate">{f.title}</span>
                        </div>
                        <span className="text-[var(--accent)] flex-shrink-0">Inspect &rarr;</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Resolved Findings */}
              {resolvedFindings.length > 0 && (
                <div className="space-y-2">
                  <div className="text-[12px] font-semibold text-[#34C759] flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Resolved in Scan B ({resolvedFindings.length})</span>
                  </div>
                  <div className="space-y-1.5 max-h-40 overflow-y-auto">
                    {resolvedFindings.map((f) => (
                      <div
                        key={f.id}
                        className="p-2 rounded-[6px] bg-[#34C759]/5 border border-[#34C759]/20 flex items-center justify-between text-[11px]"
                      >
                        <div className="flex items-center gap-2 overflow-hidden">
                          <CheckCircle2 className="w-3 h-3 text-[#34C759] flex-shrink-0" />
                          <span className="font-mono text-[var(--text-muted)] truncate">{f.file_path}</span>
                          <span className="text-[var(--text-primary)] line-through opacity-75 truncate">{f.title}</span>
                        </div>
                        <span className="text-[#34C759] font-mono">Fixed</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="flex justify-end pt-2 border-t border-[var(--border-subtle)]">
              <button
                onClick={() => setIsCompareModalOpen(false)}
                className="macos-button"
              >
                Close
              </button>
            </div>
          </div>
        )}
      </AnimatedDialog>

      {/* Inspector Modal */}
      <FindingDetailModal
        finding={inspectFinding}
        onClose={() => setInspectFinding(null)}
      />
    </div>
  );
}
