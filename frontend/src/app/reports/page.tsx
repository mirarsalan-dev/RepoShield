"use client";

import React, { useState, useEffect, useMemo } from "react";
import {
  FileSpreadsheet,
  Download,
  FileText,
  FileCode,
  ShieldCheck,
  Lock,
  Package,
  Layers,
  Search,
  ExternalLink,
  AlertTriangle,
  CheckCircle2,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { api } from "@/lib/api";
import { ScanResult, SBOMComponent } from "@/lib/types";
import { formatDate, formatTimeAgo } from "@/lib/utils";
import { EmptyState } from "@/components/common/EmptyState";
import { MacTrafficLights } from "@/components/common/Icons";

export default function ReportsPage() {
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [isExporting, setIsExporting] = useState<string | null>(null);
  const [componentSearch, setComponentSearch] = useState("");

  useEffect(() => {
    const saved = storage.getScanHistory();
    setHistory(saved);
    if (saved.length > 0) {
      setSelectedScan(saved[0]);
    }
  }, []);

  const handleDownloadPdf = async () => {
    if (!selectedScan) return;
    setIsExporting("PDF");
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
    } catch (err: any) {
      alert(err.message || "Failed to generate PDF report.");
    } finally {
      setIsExporting(null);
    }
  };

  const handleDownloadCsv = async () => {
    if (!selectedScan) return;
    setIsExporting("CSV");
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
    } catch (err: any) {
      alert(err.message || "Failed to generate CSV report.");
    } finally {
      setIsExporting(null);
    }
  };

  const handleDownloadJson = () => {
    if (!selectedScan) return;
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
  };

  const handleDownloadSarif = async () => {
    if (!selectedScan) return;
    setIsExporting("SARIF");
    try {
      const sarifObj = await api.downloadReportSarif(selectedScan);
      const jsonStr = JSON.stringify(sarifObj, null, 2);
      const blob = new Blob([jsonStr], { type: "application/json" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `reposhield-${selectedScan.repo}-${selectedScan.scan_id.slice(0, 8)}.sarif`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(err.message || "Failed to generate SARIF report.");
    } finally {
      setIsExporting(null);
    }
  };

  const handleDownloadCycloneDx = async () => {
    if (!selectedScan) return;
    setIsExporting("CycloneDX");
    try {
      const cyclonedxObj = await api.downloadReportCycloneDx(selectedScan);
      const jsonStr = JSON.stringify(cyclonedxObj, null, 2);
      const blob = new Blob([jsonStr], { type: "application/json" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `cyclonedx-sbom-${selectedScan.repo}-${selectedScan.scan_id.slice(0, 8)}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(err.message || "Failed to generate CycloneDX SBOM.");
    } finally {
      setIsExporting(null);
    }
  };

  const handleDownloadSpdx = async () => {
    if (!selectedScan) return;
    setIsExporting("SPDX");
    try {
      const spdxObj = await api.downloadReportSpdx(selectedScan);
      const jsonStr = JSON.stringify(spdxObj, null, 2);
      const blob = new Blob([jsonStr], { type: "application/json" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `spdx-sbom-${selectedScan.repo}-${selectedScan.scan_id.slice(0, 8)}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(err.message || "Failed to generate SPDX SBOM.");
    } finally {
      setIsExporting(null);
    }
  };

  const handleDownloadVex = async () => {
    if (!selectedScan) return;
    setIsExporting("VEX");
    try {
      const vexObj = await api.downloadReportVex(selectedScan);
      const jsonStr = JSON.stringify(vexObj, null, 2);
      const blob = new Blob([jsonStr], { type: "application/json" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `cyclonedx-vex-${selectedScan.repo}-${selectedScan.scan_id.slice(0, 8)}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(err.message || "Failed to generate CycloneDX VEX document.");
    } finally {
      setIsExporting(null);
    }
  };

  const sbomComponents = selectedScan?.sbom_components || [];
  const filteredComponents = useMemo(() => {
    if (!componentSearch.trim()) return sbomComponents;
    const q = componentSearch.toLowerCase();
    return sbomComponents.filter(
      (c) =>
        c.name.toLowerCase().includes(q) ||
        c.ecosystem.toLowerCase().includes(q) ||
        c.version.toLowerCase().includes(q) ||
        (c.license && c.license.toLowerCase().includes(q))
    );
  }, [sbomComponents, componentSearch]);

  const vulnerableCount = sbomComponents.filter((c) => c.vulnerable).length;
  const directCount = sbomComponents.filter((c) => c.direct).length;
  const transitiveCount = sbomComponents.length - directCount;

  if (!selectedScan && history.length === 0) {
    return (
      <EmptyState
        icon={FileSpreadsheet}
        title="No Reports Available"
        description="Run a repository security scan to generate executive PDF, SARIF, CycloneDX SBOM, JSON, and CSV audit reports."
        actionText="Scan a Repository"
        actionHref="/scan"
      />
    );
  }

  return (
    <div className="space-y-6 max-w-6xl">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[var(--border-subtle)]">
        <div>
          <h1 className="macos-title flex items-center gap-2">
            <FileSpreadsheet className="w-5 h-5 text-[var(--accent)]" />
            <span>SBOM &amp; Security Reports</span>
          </h1>
          <p className="macos-subtitle">
            Generate standards-compliant exports: SARIF v2.1.0, CycloneDX 1.5, SPDX 2.3, executive PDF, CSV, and JSON.
          </p>
        </div>

        {history.length > 1 && (
          <div className="flex items-center gap-2">
            <span className="text-[12px] text-[var(--text-secondary)]">Target:</span>
            <select
              value={selectedScan?.scan_id}
              onChange={(e) => {
                const found = history.find((s) => s.scan_id === e.target.value);
                if (found) setSelectedScan(found);
              }}
              className="macos-input py-1 px-2.5 text-[12px]"
            >
              {history.map((s) => (
                <option key={s.scan_id} value={s.scan_id}>
                  {s.owner}/{s.repo} ({formatTimeAgo(s.completed_at || s.started_at)})
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {selectedScan && (
        <>
          {/* Format Export Cards Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
            {/* SARIF Export */}
            <div className="macos-panel p-4 flex flex-col justify-between space-y-3">
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <div className="w-7 h-7 rounded-[6px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] flex items-center justify-center text-[var(--accent)]">
                    <FileCode className="w-3.5 h-3.5" />
                  </div>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--bg-secondary)] text-[var(--text-secondary)]">
                    OASIS v2.1.0
                  </span>
                </div>
                <h3 className="text-[13px] font-semibold text-[var(--text-primary)] tracking-tight">
                  GitHub Code Scanning (SARIF)
                </h3>
                <p className="text-[11px] text-[var(--text-secondary)]">
                  Upload directly to GitHub Security tab or CI/CD CodeQL scanning workflows.
                </p>
              </div>
              <button
                onClick={handleDownloadSarif}
                disabled={isExporting === "SARIF"}
                className="macos-button w-full flex items-center justify-center gap-1.5 text-[12px]"
              >
                <Download className="w-3.5 h-3.5" />
                <span>{isExporting === "SARIF" ? "Generating..." : "Download SARIF"}</span>
              </button>
            </div>

            {/* CycloneDX SBOM */}
            <div className="macos-panel p-4 flex flex-col justify-between space-y-3">
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <div className="w-7 h-7 rounded-[6px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] flex items-center justify-center text-[var(--accent)]">
                    <Layers className="w-3.5 h-3.5" />
                  </div>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--bg-secondary)] text-[var(--text-secondary)]">
                    CycloneDX 1.5
                  </span>
                </div>
                <h3 className="text-[13px] font-semibold text-[var(--text-primary)] tracking-tight">
                  Software Bill of Materials (SBOM)
                </h3>
                <p className="text-[11px] text-[var(--text-secondary)]">
                  OWASP CycloneDX JSON specification with component purls and vulnerability records.
                </p>
              </div>
              <button
                onClick={handleDownloadCycloneDx}
                disabled={isExporting === "CycloneDX"}
                className="macos-button w-full flex items-center justify-center gap-1.5 text-[12px]"
              >
                <Download className="w-3.5 h-3.5" />
                <span>{isExporting === "CycloneDX" ? "Generating..." : "Download CycloneDX"}</span>
              </button>
            </div>

            {/* SPDX SBOM */}
            <div className="macos-panel p-4 flex flex-col justify-between space-y-3">
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <div className="w-7 h-7 rounded-[6px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] flex items-center justify-center text-[var(--accent)]">
                    <Package className="w-3.5 h-3.5" />
                  </div>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--bg-secondary)] text-[var(--text-secondary)]">
                    SPDX 2.3
                  </span>
                </div>
                <h3 className="text-[13px] font-semibold text-[var(--text-primary)] tracking-tight">
                  ISO/IEC 5962 SPDX SBOM
                </h3>
                <p className="text-[11px] text-[var(--text-secondary)]">
                  Linux Foundation SPDX 2.3 standard package inventory for supply-chain compliance.
                </p>
              </div>
              <button
                onClick={handleDownloadSpdx}
                disabled={isExporting === "SPDX"}
                className="macos-button w-full flex items-center justify-center gap-1.5 text-[12px]"
              >
                <Download className="w-3.5 h-3.5" />
                <span>{isExporting === "SPDX" ? "Generating..." : "Download SPDX"}</span>
              </button>
            </div>

            {/* CycloneDX VEX */}
            <div className="macos-panel p-4 flex flex-col justify-between space-y-3">
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <div className="w-7 h-7 rounded-[6px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] flex items-center justify-center text-[var(--system-green)]">
                    <ShieldCheck className="w-3.5 h-3.5" />
                  </div>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--bg-secondary)] text-[var(--text-secondary)]">
                    CycloneDX 1.5
                  </span>
                </div>
                <h3 className="text-[13px] font-semibold text-[var(--text-primary)] tracking-tight">
                  CycloneDX VEX Document
                </h3>
                <p className="text-[11px] text-[var(--text-secondary)]">
                  Vulnerability Exploitability eXchange (VEX) statements detailing exploitability status.
                </p>
              </div>
              <button
                onClick={handleDownloadVex}
                disabled={isExporting === "VEX"}
                className="macos-button w-full flex items-center justify-center gap-1.5 text-[12px]"
              >
                <Download className="w-3.5 h-3.5" />
                <span>{isExporting === "VEX" ? "Generating..." : "Download VEX"}</span>
              </button>
            </div>

            {/* PDF Report */}
            <div className="macos-panel p-4 flex flex-col justify-between space-y-3">
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <div className="w-7 h-7 rounded-[6px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] flex items-center justify-center text-[var(--accent)]">
                    <FileText className="w-3.5 h-3.5" />
                  </div>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--bg-secondary)] text-[var(--text-secondary)]">
                    Executive
                  </span>
                </div>
                <h3 className="text-[13px] font-semibold text-[var(--text-primary)] tracking-tight">
                  Executive PDF Report
                </h3>
                <p className="text-[11px] text-[var(--text-secondary)]">
                  Print-ready security review for stakeholders, compliance officers, and dev leads.
                </p>
              </div>
              <button
                onClick={handleDownloadPdf}
                disabled={isExporting === "PDF"}
                className="macos-button w-full flex items-center justify-center gap-1.5 text-[12px]"
              >
                <Download className="w-3.5 h-3.5" />
                <span>{isExporting === "PDF" ? "Generating..." : "Download PDF"}</span>
              </button>
            </div>

            {/* CSV Report */}
            <div className="macos-panel p-4 flex flex-col justify-between space-y-3">
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <div className="w-7 h-7 rounded-[6px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] flex items-center justify-center text-[var(--accent)]">
                    <FileSpreadsheet className="w-3.5 h-3.5" />
                  </div>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--bg-secondary)] text-[var(--text-secondary)]">
                    RFC 4180
                  </span>
                </div>
                <h3 className="text-[13px] font-semibold text-[var(--text-primary)] tracking-tight">
                  Tabular CSV Export
                </h3>
                <p className="text-[11px] text-[var(--text-secondary)]">
                  Raw findings spreadsheet with sanitized evidence, CWE tags, and line references.
                </p>
              </div>
              <button
                onClick={handleDownloadCsv}
                disabled={isExporting === "CSV"}
                className="macos-button w-full flex items-center justify-center gap-1.5 text-[12px]"
              >
                <Download className="w-3.5 h-3.5" />
                <span>{isExporting === "CSV" ? "Generating..." : "Download CSV"}</span>
              </button>
            </div>

            {/* JSON Export */}
            <div className="macos-panel p-4 flex flex-col justify-between space-y-3">
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <div className="w-7 h-7 rounded-[6px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] flex items-center justify-center text-[var(--accent)]">
                    <FileCode className="w-3.5 h-3.5" />
                  </div>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--bg-secondary)] text-[var(--text-secondary)]">
                    Full Session
                  </span>
                </div>
                <h3 className="text-[13px] font-semibold text-[var(--text-primary)] tracking-tight">
                  Normalized JSON Report
                </h3>
                <p className="text-[11px] text-[var(--text-secondary)]">
                  Complete machine-readable payload containing all findings, coverage, and logs.
                </p>
              </div>
              <button
                onClick={handleDownloadJson}
                className="macos-button w-full flex items-center justify-center gap-1.5 text-[12px]"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download JSON</span>
              </button>
            </div>
          </div>

          {/* Software Supply Chain & SBOM Inventory Table */}
          <div className="macos-card p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[var(--border-subtle)] pb-3">
              <div>
                <h2 className="text-[14px] font-semibold text-[var(--text-primary)] tracking-tight flex items-center gap-2">
                  <Package className="w-4 h-4 text-[var(--accent)]" />
                  <span>Software Supply Chain Inventory</span>
                </h2>
                <p className="text-[12px] text-[var(--text-secondary)]">
                  Bill of Materials extracted directly from scanned lockfiles and dependency manifests.
                </p>
              </div>

              {/* Metrics Chips */}
              <div className="flex flex-wrap items-center gap-2 text-[11px] font-mono">
                <span className="px-2.5 py-1 rounded-[6px] bg-[var(--bg-secondary)] text-[var(--text-primary)] border border-[var(--border-subtle)]">
                  {sbomComponents.length} Components
                </span>
                <span className="px-2.5 py-1 rounded-[6px] bg-[var(--bg-secondary)] text-[var(--text-secondary)] border border-[var(--border-subtle)]">
                  {directCount} Direct / {transitiveCount} Transitive
                </span>
                {vulnerableCount > 0 ? (
                  <span className="px-2.5 py-1 rounded-[6px] bg-[#FF3B30]/15 text-[#FF3B30] border border-[#FF3B30]/30 font-medium">
                    {vulnerableCount} Vulnerable
                  </span>
                ) : (
                  <span className="px-2.5 py-1 rounded-[6px] bg-[#34C759]/15 text-[#34C759] border border-[#34C759]/30 font-medium">
                    0 Vulnerabilities
                  </span>
                )}
              </div>
            </div>

            {/* Search Filter */}
            <div className="relative max-w-sm">
              <Search className="w-3.5 h-3.5 text-[var(--text-muted)] absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={componentSearch}
                onChange={(e) => setComponentSearch(e.target.value)}
                placeholder="Search packages, ecosystems, licenses..."
                className="macos-input w-full pl-8 text-[12px]"
              />
            </div>

            {/* Inventory Table */}
            {sbomComponents.length === 0 ? (
              <div className="text-[12px] text-[var(--text-muted)] py-8 text-center">
                No dependency manifests detected in this scan. Supported manifests include package.json, requirements.txt, go.mod, Cargo.lock, pom.xml, and composer.json.
              </div>
            ) : (
              <div className="macos-panel overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-[12px]">
                    <thead>
                      <tr className="border-b border-[var(--border-color)] bg-[var(--bg-secondary)] text-[var(--text-secondary)] text-[11px] font-medium">
                        <th className="py-2 px-3">Component</th>
                        <th className="py-2 px-3">Version</th>
                        <th className="py-2 px-3">Ecosystem</th>
                        <th className="py-2 px-3">License</th>
                        <th className="py-2 px-3">Type</th>
                        <th className="py-2 px-3 text-right">Security Posture</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[var(--border-subtle)]">
                      {filteredComponents.map((c, i) => (
                        <tr key={i} className="hover:bg-[var(--bg-hover)] transition-colors">
                          <td className="py-2.5 px-3 font-medium text-[var(--text-primary)] font-mono">
                            {c.name}
                          </td>
                          <td className="py-2.5 px-3 text-[var(--text-secondary)] font-mono">
                            {c.version}
                          </td>
                          <td className="py-2.5 px-3 text-[var(--text-secondary)] font-mono uppercase text-[10px]">
                            {c.ecosystem}
                          </td>
                          <td className="py-2.5 px-3 text-[var(--text-muted)] font-mono text-[11px]">
                            {c.license || "Not Specified"}
                          </td>
                          <td className="py-2.5 px-3">
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--bg-secondary)] text-[var(--text-secondary)] border border-[var(--border-subtle)]">
                              {c.direct ? "Direct" : "Transitive"}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-right">
                            {c.vulnerable ? (
                              <span className="inline-flex items-center gap-1 text-[11px] font-mono text-[#FF3B30] bg-[#FF3B30]/10 px-2 py-0.5 rounded border border-[#FF3B30]/20 font-medium">
                                <AlertTriangle className="w-3 h-3" />
                                <span>{c.vulnerabilities.length} Advisory</span>
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 text-[11px] font-mono text-[#34C759] bg-[#34C759]/10 px-2 py-0.5 rounded border border-[#34C759]/20 font-medium">
                                <CheckCircle2 className="w-3 h-3" />
                                <span>Clean</span>
                              </span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
