"use client";

import React, { useState, useEffect, useMemo } from "react";
import {
  Layers,
  FileCode,
  Package,
  Download,
  Search,
  Filter,
  CheckCircle2,
  AlertTriangle,
  HelpCircle,
  ShieldCheck,
  ShieldAlert,
  ArrowRight,
  Plus,
  ExternalLink,
  Info,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { api } from "@/lib/api";
import { ScanResult, SBOMComponent, Finding } from "@/lib/types";
import { formatTimeAgo } from "@/lib/utils";
import { EmptyState } from "@/components/common/EmptyState";
import { MacTrafficLights } from "@/components/common/Icons";

interface VexStatement {
  vulnerabilityId: string;
  componentPurl: string;
  componentName: string;
  status: "affected" | "not_affected" | "fixed" | "under_investigation";
  justification?: string;
  impact?: string;
  timestamp: string;
}

export default function SbomVexPage() {
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [activeTab, setActiveTab] = useState<"sbom" | "vex">("sbom");

  const [searchQuery, setSearchQuery] = useState("");
  const [ecosystemFilter, setEcosystemFilter] = useState<string>("ALL");
  const [isExporting, setIsExporting] = useState<string | null>(null);

  // VEX statements stored in client-side state / localStorage (strict zero-database requirement)
  const [vexStatements, setVexStatements] = useState<VexStatement[]>([]);
  const [selectedFindingForVex, setSelectedFindingForVex] = useState<Finding | null>(null);
  const [vexStatus, setVexStatus] = useState<"affected" | "not_affected" | "fixed" | "under_investigation">("under_investigation");
  const [vexJustification, setVexJustification] = useState("code_not_reachable");
  const [vexImpact, setVexImpact] = useState("");

  useEffect(() => {
    const saved = storage.getScanHistory();
    setHistory(saved);
    if (saved.length > 0) {
      setSelectedScan(saved[0]);
    }
  }, []);

  const components = selectedScan?.sbom_components || [];
  const findings = selectedScan?.findings || [];

  // Seed default VEX statements based on vulnerable components
  useEffect(() => {
    if (!selectedScan) return;
    const initial: VexStatement[] = [];
    for (const f of findings) {
      if (f.category === "DEPENDENCIES" && f.package_name) {
        const purl = `pkg:${f.package_name.startsWith("@") ? "npm" : "generic"}/${f.package_name}@${f.installed_version || "latest"}`;
        initial.push({
          vulnerabilityId: f.cve_id || f.ghsa_id || f.rule_id,
          componentPurl: purl,
          componentName: f.package_name,
          status: f.reachability_status === "CONFIRMED" ? "affected" : "under_investigation",
          justification: f.reachability_status === "NO_EVIDENCE" ? "code_not_reachable" : undefined,
          impact: f.title,
          timestamp: new Date().toISOString(),
        });
      }
    }
    setVexStatements(initial);
  }, [selectedScan]);

  const ecosystems = useMemo(() => {
    const set = new Set<string>();
    components.forEach((c) => {
      if (c.ecosystem) set.add(c.ecosystem.toLowerCase());
    });
    return Array.from(set);
  }, [components]);

  const filteredComponents = useMemo(() => {
    return components.filter((c) => {
      const matchesSearch =
        !searchQuery.trim() ||
        c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        c.version.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (c.license && c.license.toLowerCase().includes(searchQuery.toLowerCase()));

      const matchesEco =
        ecosystemFilter === "ALL" || c.ecosystem.toLowerCase() === ecosystemFilter.toLowerCase();

      return matchesSearch && matchesEco;
    });
  }, [components, searchQuery, ecosystemFilter]);

  const handleDownloadCycloneDx = async () => {
    if (!selectedScan) return;
    setIsExporting("CycloneDX");
    try {
      const data = await api.downloadReportCycloneDx(selectedScan);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `cyclonedx-sbom-${selectedScan.repo}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(err.message || "Failed to export CycloneDX SBOM");
    } finally {
      setIsExporting(null);
    }
  };

  const handleDownloadSpdx = async () => {
    if (!selectedScan) return;
    setIsExporting("SPDX");
    try {
      const data = await api.downloadReportSpdx(selectedScan);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `spdx-sbom-${selectedScan.repo}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(err.message || "Failed to export SPDX SBOM");
    } finally {
      setIsExporting(null);
    }
  };

  const handleDownloadVex = async () => {
    if (!selectedScan) return;
    setIsExporting("VEX");
    try {
      const data = await api.downloadReportVex(selectedScan);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `cyclonedx-vex-${selectedScan.repo}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(err.message || "Failed to export CycloneDX VEX document");
    } finally {
      setIsExporting(null);
    }
  };

  const handleSaveVexStatement = () => {
    if (!selectedFindingForVex) return;
    const purl = `pkg:${selectedFindingForVex.package_name?.startsWith("@") ? "npm" : "generic"}/${selectedFindingForVex.package_name}@${selectedFindingForVex.installed_version || "latest"}`;
    const newStmt: VexStatement = {
      vulnerabilityId: selectedFindingForVex.cve_id || selectedFindingForVex.ghsa_id || selectedFindingForVex.rule_id,
      componentPurl: purl,
      componentName: selectedFindingForVex.package_name || "unknown",
      status: vexStatus,
      justification: vexStatus === "not_affected" ? vexJustification : undefined,
      impact: vexImpact || selectedFindingForVex.title,
      timestamp: new Date().toISOString(),
    };

    setVexStatements((prev) => [
      ...prev.filter(
        (s) =>
          !(
            s.vulnerabilityId === newStmt.vulnerabilityId &&
            s.componentPurl === newStmt.componentPurl
          )
      ),
      newStmt,
    ]);
    setSelectedFindingForVex(null);
    setVexImpact("");
  };

  if (!selectedScan && history.length === 0) {
    return (
      <EmptyState
        icon={Layers}
        title="No SBOM Data Available"
        description="Run a repository security scan to generate software supply chain manifests and CycloneDX VEX documentation."
        actionText="Scan a Repository"
        actionHref="/scan"
      />
    );
  }

  return (
    <div className="space-y-6 max-w-6xl">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[var(--border-subtle)]">
        <div>
          <h1 className="macos-title flex items-center gap-2">
            <Layers className="w-5 h-5 text-[var(--accent)]" />
            <span>SBOM &amp; VEX Intelligence</span>
          </h1>
          <p className="macos-subtitle">
            CycloneDX 1.5, SPDX 2.3, and Vulnerability Exploitability eXchange (VEX) management.
          </p>
        </div>

        {/* Target Switcher & Export buttons */}
        <div className="flex flex-wrap items-center gap-2">
          {history.length > 1 && (
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
          )}

          <button
            onClick={handleDownloadCycloneDx}
            disabled={isExporting === "CycloneDX"}
            className="macos-button text-[12px] flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5 text-[var(--accent)]" />
            <span>CycloneDX</span>
          </button>

          <button
            onClick={handleDownloadSpdx}
            disabled={isExporting === "SPDX"}
            className="macos-button text-[12px] flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5 text-[var(--accent)]" />
            <span>SPDX 2.3</span>
          </button>

          <button
            onClick={handleDownloadVex}
            disabled={isExporting === "VEX"}
            className="macos-button macos-button-primary text-[12px] flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export VEX</span>
          </button>
        </div>
      </div>

      {/* Tabs Switcher */}
      <div className="flex items-center gap-2 border-b border-[var(--border-subtle)] pb-2 text-[13px]">
        <button
          onClick={() => setActiveTab("sbom")}
          className={`px-3 py-1.5 rounded-[6px] font-medium transition-colors flex items-center gap-2 ${
            activeTab === "sbom"
              ? "bg-[var(--accent)] text-white"
              : "text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-secondary)]"
          }`}
        >
          <Package className="w-4 h-4" />
          <span>SBOM Components ({components.length})</span>
        </button>

        <button
          onClick={() => setActiveTab("vex")}
          className={`px-3 py-1.5 rounded-[6px] font-medium transition-colors flex items-center gap-2 ${
            activeTab === "vex"
              ? "bg-[var(--accent)] text-white"
              : "text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-secondary)]"
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          <span>VEX Statements ({vexStatements.length})</span>
        </button>
      </div>

      {/* Tab Content: SBOM Components */}
      {activeTab === "sbom" && (
        <div className="space-y-4">
          {/* Filter Bar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="relative flex-1 max-w-sm">
              <Search className="w-3.5 h-3.5 text-[var(--text-muted)] absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search packages, versions, licenses..."
                className="macos-input w-full pl-8 text-[12px]"
              />
            </div>

            <div className="flex items-center gap-2">
              <span className="text-[12px] text-[var(--text-secondary)]">Ecosystem:</span>
              <select
                value={ecosystemFilter}
                onChange={(e) => setEcosystemFilter(e.target.value)}
                className="macos-input py-1 px-2.5 text-[12px]"
              >
                <option value="ALL">All Ecosystems</option>
                {ecosystems.map((eco) => (
                  <option key={eco} value={eco}>
                    {eco.toUpperCase()}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Components Table */}
          {filteredComponents.length === 0 ? (
            <div className="macos-panel p-8 text-center text-[12px] text-[var(--text-muted)]">
              No components matching search criteria.
            </div>
          ) : (
            <div className="macos-panel overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-[12px]">
                  <thead>
                    <tr className="border-b border-[var(--border-color)] bg-[var(--bg-secondary)] text-[var(--text-secondary)] text-[11px] font-medium">
                      <th className="py-2.5 px-3">Package Name</th>
                      <th className="py-2.5 px-3">Installed Version</th>
                      <th className="py-2.5 px-3">Ecosystem</th>
                      <th className="py-2.5 px-3">License</th>
                      <th className="py-2.5 px-3">Dependency Scope</th>
                      <th className="py-2.5 px-3 text-right">Advisories</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--border-subtle)]">
                    {filteredComponents.map((c, i) => (
                      <tr key={i} className="hover:bg-[var(--bg-hover)] transition-colors">
                        <td className="py-2 px-3 font-medium text-[var(--text-primary)] font-mono">
                          {c.name}
                        </td>
                        <td className="py-2 px-3 text-[var(--text-secondary)] font-mono">
                          {c.version}
                        </td>
                        <td className="py-2 px-3 text-[var(--text-secondary)] font-mono uppercase text-[10px]">
                          {c.ecosystem}
                        </td>
                        <td className="py-2 px-3 text-[var(--text-muted)] font-mono text-[11px]">
                          {c.license || "Not Specified"}
                        </td>
                        <td className="py-2 px-3">
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[var(--bg-secondary)] text-[var(--text-secondary)] border border-[var(--border-subtle)]">
                            {c.direct ? "Direct" : "Transitive"}
                          </span>
                        </td>
                        <td className="py-2 px-3 text-right">
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
      )}

      {/* Tab Content: VEX Statements */}
      {activeTab === "vex" && (
        <div className="space-y-6">
          <div className="macos-card p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-3">
              <div>
                <h2 className="text-[14px] font-semibold text-[var(--text-primary)] tracking-tight">
                  Vulnerability Exploitability eXchange (VEX) Statuses
                </h2>
                <p className="text-[12px] text-[var(--text-secondary)]">
                  Document the real-world exploitability of dependencies for downstream consumers and SBOM audits.
                </p>
              </div>

              <div className="flex items-center gap-2">
                <MacTrafficLights />
              </div>
            </div>

            {/* VEX Table */}
            {vexStatements.length === 0 ? (
              <div className="text-[12px] text-[var(--text-muted)] py-8 text-center">
                No active VEX assertions. Select dependency findings to document exploitability applicability.
              </div>
            ) : (
              <div className="macos-panel overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-[12px]">
                    <thead>
                      <tr className="border-b border-[var(--border-color)] bg-[var(--bg-secondary)] text-[var(--text-secondary)] text-[11px] font-medium">
                        <th className="py-2.5 px-3">Vulnerability ID</th>
                        <th className="py-2.5 px-3">Component</th>
                        <th className="py-2.5 px-3">VEX Status</th>
                        <th className="py-2.5 px-3">Justification</th>
                        <th className="py-2.5 px-3">Last Updated</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[var(--border-subtle)]">
                      {vexStatements.map((v, i) => {
                        let statusColor = "var(--system-orange)";
                        let statusBg = "rgba(255, 149, 0, 0.1)";

                        if (v.status === "not_affected" || v.status === "fixed") {
                          statusColor = "var(--system-green)";
                          statusBg = "rgba(52, 199, 89, 0.1)";
                        } else if (v.status === "affected") {
                          statusColor = "var(--system-red)";
                          statusBg = "rgba(255, 59, 48, 0.1)";
                        }

                        return (
                          <tr key={i} className="hover:bg-[var(--bg-hover)] transition-colors">
                            <td className="py-2.5 px-3 font-mono font-medium text-[var(--accent)]">
                              {v.vulnerabilityId}
                            </td>
                            <td className="py-2.5 px-3 font-mono text-[var(--text-primary)]">
                              {v.componentName}
                            </td>
                            <td className="py-2.5 px-3">
                              <span
                                className="text-[11px] font-mono font-semibold px-2 py-0.5 rounded uppercase"
                                style={{ color: statusColor, backgroundColor: statusBg }}
                              >
                                {v.status.replace("_", " ")}
                              </span>
                            </td>
                            <td className="py-2.5 px-3 text-[11px] text-[var(--text-secondary)] font-mono">
                              {v.justification || "—"}
                            </td>
                            <td className="py-2.5 px-3 text-[11px] text-[var(--text-muted)] font-mono">
                              {new Date(v.timestamp).toLocaleDateString()}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>

          {/* VEX Assertion Creator Drawer */}
          <div className="macos-panel p-5 space-y-4 border border-[var(--border-subtle)]">
            <div className="flex items-center gap-2 pb-2 border-b border-[var(--border-subtle)]">
              <Plus className="w-4 h-4 text-[var(--accent)]" />
              <h3 className="text-[13px] font-semibold text-[var(--text-primary)]">
                Create or Update VEX Assertion
              </h3>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-[12px]">
              <div>
                <label className="text-[11px] uppercase text-[var(--text-secondary)] font-semibold block mb-1">
                  Select Vulnerability Finding
                </label>
                <select
                  value={selectedFindingForVex?.id || ""}
                  onChange={(e) => {
                    const match = findings.find((f) => f.id === e.target.value);
                    if (match) setSelectedFindingForVex(match);
                  }}
                  className="macos-input w-full py-1.5 px-2.5 text-[12px]"
                >
                  <option value="">-- Choose Finding --</option>
                  {findings
                    .filter((f) => f.category === "DEPENDENCIES")
                    .map((f) => (
                      <option key={f.id} value={f.id}>
                        {f.cve_id || f.rule_id} ({f.package_name}) - {f.severity}
                      </option>
                    ))}
                </select>
              </div>

              <div>
                <label className="text-[11px] uppercase text-[var(--text-secondary)] font-semibold block mb-1">
                  Exploitability Status
                </label>
                <select
                  value={vexStatus}
                  onChange={(e: any) => setVexStatus(e.target.value)}
                  className="macos-input w-full py-1.5 px-2.5 text-[12px]"
                >
                  <option value="affected">affected</option>
                  <option value="not_affected">not_affected</option>
                  <option value="fixed">fixed</option>
                  <option value="under_investigation">under_investigation</option>
                </select>
              </div>

              {vexStatus === "not_affected" && (
                <div>
                  <label className="text-[11px] uppercase text-[var(--text-secondary)] font-semibold block mb-1">
                    Justification (Mandatory for not_affected)
                  </label>
                  <select
                    value={vexJustification}
                    onChange={(e) => setVexJustification(e.target.value)}
                    className="macos-input w-full py-1.5 px-2.5 text-[12px]"
                  >
                    <option value="code_not_reachable">code_not_reachable</option>
                    <option value="code_not_present">code_not_present</option>
                    <option value="vulnerable_code_cannot_be_controlled_by_adversary">
                      vulnerable_code_cannot_be_controlled_by_adversary
                    </option>
                    <option value="inline_mitigations_already_exist">
                      inline_mitigations_already_exist
                    </option>
                  </select>
                </div>
              )}

              <div>
                <label className="text-[11px] uppercase text-[var(--text-secondary)] font-semibold block mb-1">
                  Analysis Notes / Impact Details
                </label>
                <input
                  type="text"
                  value={vexImpact}
                  onChange={(e) => setVexImpact(e.target.value)}
                  placeholder="e.g. Function not imported in production bundle"
                  className="macos-input w-full py-1.5 px-2.5 text-[12px]"
                />
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={handleSaveVexStatement}
                disabled={!selectedFindingForVex}
                className="macos-button macos-button-primary text-[12px]"
              >
                <span>Save VEX Statement</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
