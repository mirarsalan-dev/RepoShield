"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  FileCheck2,
  Download,
  FileSpreadsheet,
  FileCode,
  FileText,
  GitBranch,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { api } from "@/lib/api";
import { ScanResult } from "@/lib/types";
import { PageHeader } from "@/components/common/PageHeader";
import { FindingsTable } from "@/components/findings/FindingsTable";
import { EmptyState } from "@/components/common/EmptyState";
import { formatTimeAgo } from "@/lib/utils";
import { useToast } from "@/components/common/ToastProvider";

export default function ResultsPage() {
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [downloadingFormat, setDownloadingFormat] = useState<string | null>(null);
  const toast = useToast();

  useEffect(() => {
    const saved = storage.getScanHistory();
    setHistory(saved);
    if (saved.length > 0) {
      setSelectedScan(saved[0]);
    }
  }, []);

  if (!selectedScan && history.length === 0) {
    return (
      <EmptyState
        icon={FileCheck2}
        title="No findings available"
        description="Scan any GitHub repository to discover exposed credentials, dependencies, and code vulnerabilities."
        actionText="Scan Repository"
        actionHref="/scan"
      />
    );
  }

  const handleDownloadPdf = async () => {
    if (!selectedScan) return;
    setDownloadingFormat("PDF");
    try {
      const blob = await api.downloadReportPdf(selectedScan);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `reposhield-${selectedScan.repo}-${selectedScan.scan_id.slice(0, 8)}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      toast.success("Report Exported", "PDF downloaded successfully.");
    } catch (err: any) {
      toast.error("Export Failed", err.message || "Failed to generate PDF report.");
    } finally {
      setDownloadingFormat(null);
    }
  };

  const handleDownloadCsv = async () => {
    if (!selectedScan) return;
    setDownloadingFormat("CSV");
    try {
      const csvStr = await api.downloadReportCsv(selectedScan);
      const blob = new Blob([csvStr], { type: "text/csv;charset=utf-8;" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `reposhield-${selectedScan.repo}-${selectedScan.scan_id.slice(0, 8)}.csv`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      toast.success("Report Exported", "CSV downloaded successfully.");
    } catch (err: any) {
      toast.error("Export Failed", err.message || "Failed to generate CSV export.");
    } finally {
      setDownloadingFormat(null);
    }
  };

  const handleDownloadJson = () => {
    if (!selectedScan) return;
    try {
      const jsonStr = JSON.stringify(selectedScan, null, 2);
      const blob = new Blob([jsonStr], { type: "application/json" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `reposhield-${selectedScan.repo}-${selectedScan.scan_id.slice(0, 8)}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      toast.success("Report Exported", "JSON report downloaded.");
    } catch (err: any) {
      toast.error("Export Failed", "Failed to compile JSON export.");
    }
  };

  const findings = selectedScan?.findings || [];
  const criticalCount = findings.filter((f) => f.severity === "CRITICAL").length;
  const highCount = findings.filter((f) => f.severity === "HIGH").length;
  const mediumCount = findings.filter((f) => f.severity === "MEDIUM").length;
  const lowCount = findings.filter((f) => f.severity === "LOW").length;

  return (
    <div className="space-y-5">
      {/* Page Header */}
      <PageHeader
        title="Findings"
        description="Security audit findings with line-numbered redacted evidence and remediation guidance."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {history.length > 1 && (
              <select
                value={selectedScan?.scan_id}
                onChange={(e) => {
                  const found = history.find((s) => s.scan_id === e.target.value);
                  if (found) setSelectedScan(found);
                }}
                className="macos-select h-9 text-[12px] cursor-pointer"
              >
                {history.map((s) => (
                  <option key={s.scan_id} value={s.scan_id}>
                    {s.owner}/{s.repo} ({formatTimeAgo(s.completed_at || s.started_at)})
                  </option>
                ))}
              </select>
            )}

            <div className="flex items-center gap-1.5">
              <button
                onClick={handleDownloadPdf}
                disabled={downloadingFormat === "PDF"}
                className="btn-secondary h-9 px-3 text-[12px]"
                title="Export as PDF"
              >
                <FileText className="w-3.5 h-3.5 text-[var(--foreground-secondary)]" />
                <span>{downloadingFormat === "PDF" ? "Exporting..." : "PDF"}</span>
              </button>
              <button
                onClick={handleDownloadCsv}
                disabled={downloadingFormat === "CSV"}
                className="btn-secondary h-9 px-3 text-[12px]"
                title="Export as CSV"
              >
                <FileSpreadsheet className="w-3.5 h-3.5 text-[var(--foreground-secondary)]" />
                <span>CSV</span>
              </button>
              <button
                onClick={handleDownloadJson}
                className="btn-secondary h-9 px-3 text-[12px]"
                title="Export as JSON"
              >
                <FileCode className="w-3.5 h-3.5 text-[var(--foreground-secondary)]" />
                <span>JSON</span>
              </button>
            </div>
          </div>
        }
      />

      {selectedScan && (
        <>
          {/* Target Metadata Banner */}
          <div className="macos-panel p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 border border-[var(--border)] rounded-[var(--radius-md)] bg-[var(--surface-secondary)]">
            <div className="flex items-center gap-2.5 text-[13px]">
              <GitBranch className="w-4 h-4 text-[var(--foreground-secondary)]" />
              <span className="font-semibold text-[var(--foreground)]">
                {selectedScan.owner}/{selectedScan.repo}
              </span>
              <span className="text-[12px] font-mono px-2 py-0.5 rounded-[var(--radius-sm)] bg-[var(--surface)] border border-[var(--border)] text-[var(--foreground-secondary)]">
                {selectedScan.branch}
              </span>
              <span className="text-[11px] font-mono text-[var(--foreground-tertiary)] hidden md:inline">
                ({selectedScan.commit_sha ? selectedScan.commit_sha.slice(0, 7) : "HEAD"})
              </span>
            </div>

            {/* Severity Summary Dots */}
            <div className="flex items-center gap-3.5 text-[12px] font-medium text-[var(--foreground-secondary)]">
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-[var(--danger)]" />
                <span className="font-semibold text-[var(--foreground)]">{criticalCount}</span> Critical
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-[var(--warning)]" />
                <span className="font-semibold text-[var(--foreground)]">{highCount}</span> High
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-amber-500" />
                <span className="font-semibold text-[var(--foreground)]">{mediumCount}</span> Medium
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-[var(--success)]" />
                <span className="font-semibold text-[var(--foreground)]">{lowCount}</span> Low
              </span>
            </div>
          </div>

          {/* Findings Table */}
          <FindingsTable findings={selectedScan.findings} />
        </>
      )}
    </div>
  );
}
