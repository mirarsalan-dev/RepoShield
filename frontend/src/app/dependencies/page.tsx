"use client";

import React, { useState, useEffect, useMemo } from "react";
import Link from "next/link";
import {
  Package,
  Search,
  RotateCcw,
  ExternalLink,
  Info,
  Terminal,
  Copy,
  Check,
  AlertTriangle,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { ScanResult, Finding } from "@/lib/types";
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import { FindingDetailModal } from "@/components/findings/FindingDetailModal";
import { EmptyState } from "@/components/common/EmptyState";
import { formatTimeAgo } from "@/lib/utils";

export default function DependenciesPage() {
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [search, setSearch] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("ALL");
  const [selectedEcosystem, setSelectedEcosystem] = useState<string>("ALL");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  useEffect(() => {
    const saved = storage.getScanHistory();
    setHistory(saved);
    if (saved.length > 0) {
      setSelectedScan(saved[0]);
    }
  }, []);

  const depFindings = useMemo(() => {
    if (!selectedScan) return [];
    return selectedScan.findings.filter((f) => f.category === "DEPENDENCIES");
  }, [selectedScan]);

  const getEcosystem = (finding: Finding) => {
    if (finding.ecosystem) return finding.ecosystem;
    const lower = finding.file_path.toLowerCase();
    if (lower.includes("package.json") || lower.includes("package-lock") || lower.includes("yarn.lock") || lower.includes("pnpm")) return "npm";
    if (lower.includes("requirements") || lower.includes("pipfile") || lower.includes("setup.py") || lower.includes("pyproject")) return "PyPI";
    if (lower.includes("go.mod") || lower.includes("go.sum")) return "Go";
    if (lower.includes("cargo")) return "Cargo";
    if (lower.includes("pom.xml") || lower.includes("build.gradle")) return "Maven";
    if (lower.includes("composer")) return "Composer";
    return "Generic";
  };

  const ecosystems = useMemo(() => {
    const set = new Set<string>();
    depFindings.forEach((f) => set.add(getEcosystem(f)));
    return Array.from(set);
  }, [depFindings]);

  const filteredFindings = useMemo(() => {
    return depFindings.filter((f) => {
      if (selectedSeverity !== "ALL" && f.severity !== selectedSeverity) return false;
      if (selectedEcosystem !== "ALL" && getEcosystem(f) !== selectedEcosystem) return false;
      if (search.trim()) {
        const q = search.toLowerCase();
        const matchesPkg = f.package_name?.toLowerCase().includes(q) || false;
        const matchesTitle = f.title.toLowerCase().includes(q);
        const matchesCve = f.cve_id?.toLowerCase().includes(q) || false;
        const matchesGhsa = f.ghsa_id?.toLowerCase().includes(q) || false;
        const matchesFile = f.file_path.toLowerCase().includes(q);
        if (!matchesPkg && !matchesTitle && !matchesCve && !matchesGhsa && !matchesFile) return false;
      }
      return true;
    });
  }, [depFindings, selectedSeverity, selectedEcosystem, search]);

  const copyCommand = (cmd: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(cmd);
    setCopiedCmd(cmd);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  if (!selectedScan && history.length === 0) {
    return (
      <EmptyState
        icon={Package}
        title="No Dependency Audits"
        description="Scan any GitHub repository to analyze package manifests against the Google OSV database."
        actionText="Scan a Repository"
        actionHref="/scan"
      />
    );
  }

  const fixableCount = depFindings.filter((f) => !!f.fixed_version).length;
  const directCount = depFindings.filter((f) => f.direct_dependency === true).length;

  return (
    <div className="space-y-4 max-w-6xl">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[var(--border-color)]">
        <div>
          <h1 className="macos-title flex items-center gap-2">
            <Package className="w-5 h-5 text-[var(--accent)]" />
            <span>Dependency Vulnerability Intelligence</span>
          </h1>
          <p className="macos-subtitle">
            Authoritative software composition analysis (SCA) grounded in Google OSV with direct/transitive differentiation.
          </p>
        </div>

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
      </div>

      {/* Summary Inset Panel */}
      <div className="macos-panel p-3.5 grid grid-cols-2 sm:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-[var(--border-subtle)] text-[12px]">
        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Vulnerable packages</div>
          <div className="text-xl font-semibold text-[var(--text-primary)]">{depFindings.length}</div>
        </div>
        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Fixable upgrades</div>
          <div className="text-xl font-semibold text-[#34C759] dark:text-[#30D158]">{fixableCount}</div>
        </div>
        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Direct manifests</div>
          <div className="text-xl font-semibold text-[var(--text-primary)]">{directCount}</div>
        </div>
        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Advisory intelligence</div>
          <div className="font-mono text-[13px] font-medium text-[var(--text-primary)] truncate mt-1">
            Google OSV Multi-Eco
          </div>
        </div>
      </div>

      {/* Coverage Notice */}
      <div className="p-3 rounded-[6px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] flex items-start gap-2.5 text-[12px] text-[var(--text-secondary)]">
        <Info className="w-4 h-4 text-[var(--text-muted)] flex-shrink-0 mt-0.5" />
        <p className="leading-normal">
          Analysis evaluates declared manifests (npm, PyPI, Go, Cargo, Maven, Composer). Breaking-change risk is an estimate based on semver leap and requires test verification.
        </p>
      </div>

      {/* Filter Toolbar */}
      <div className="flex flex-col sm:flex-row gap-2.5 items-stretch sm:items-center justify-between">
        <div className="relative flex-1 max-w-sm">
          <Search className="w-3.5 h-3.5 text-[var(--text-muted)] absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by package, CVE, manifest..."
            className="macos-input w-full pl-8 text-[12px]"
          />
        </div>

        <div className="flex items-center gap-2">
          {ecosystems.length > 0 && (
            <select
              value={selectedEcosystem}
              onChange={(e) => setSelectedEcosystem(e.target.value)}
              className="macos-input h-7 text-[12px] cursor-pointer"
            >
              <option value="ALL">All Ecosystems</option>
              {ecosystems.map((eco) => (
                <option key={eco} value={eco}>{eco}</option>
              ))}
            </select>
          )}

          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="macos-input h-7 text-[12px] cursor-pointer"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {(search || selectedSeverity !== "ALL" || selectedEcosystem !== "ALL") && (
            <button
              onClick={() => {
                setSearch("");
                setSelectedSeverity("ALL");
                setSelectedEcosystem("ALL");
              }}
              className="macos-button h-7 text-[12px] px-2 text-[var(--text-secondary)]"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Reset</span>
            </button>
          )}
        </div>
      </div>

      {/* Package Audit Table */}
      <div className="macos-panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-[13px]">
            <thead>
              <tr className="border-b border-[var(--border-color)] bg-[var(--bg-secondary)] text-[var(--text-secondary)] text-[11px] font-medium select-none">
                <th className="py-2 px-3.5 w-24">Severity</th>
                <th className="py-2 px-3.5">Package &amp; Type</th>
                <th className="py-2 px-3.5">Installed</th>
                <th className="py-2 px-3.5">Fixed Version</th>
                <th className="py-2 px-3.5">Advisory ID</th>
                <th className="py-2 px-3.5">Remediation Command</th>
                <th className="py-2 px-3.5 text-right w-20">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-subtle)]">
              {filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-10 text-center text-[var(--text-secondary)] text-[12px]">
                    {depFindings.length === 0
                      ? "No dependency vulnerabilities identified in this scan."
                      : "No dependencies match active filters."}
                  </td>
                </tr>
              ) : (
                filteredFindings.map((finding) => (
                  <tr
                    key={finding.id}
                    onClick={() => setSelectedFinding(finding)}
                    className="hover:bg-[var(--bg-hover)] cursor-pointer transition-colors"
                  >
                    <td className="py-2.5 px-3.5 whitespace-nowrap">
                      <SeverityBadge severity={finding.severity} />
                    </td>
                    <td className="py-2.5 px-3.5 font-medium text-[var(--text-primary)]">
                      <div className="font-mono text-[12px] flex items-center gap-1.5">
                        <span>{finding.package_name || "Unknown package"}</span>
                        {finding.direct_dependency !== undefined && (
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-[var(--bg-secondary)] border border-[var(--border-subtle)] text-[var(--text-muted)]">
                            {finding.direct_dependency ? "direct" : "transitive"}
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-[var(--text-muted)] line-clamp-1 mt-0.5">{finding.title}</div>
                    </td>
                    <td className="py-2.5 px-3.5 font-mono text-[12px] text-[var(--text-secondary)]">
                      {finding.installed_version || "—"}
                    </td>
                    <td className="py-2.5 px-3.5 font-mono text-[12px]">
                      {finding.fixed_version ? (
                        <div className="flex items-center gap-1.5">
                          <span className="text-[#34C759] dark:text-[#30D158] font-medium">
                            &gt;= {finding.fixed_version}
                          </span>
                          {finding.breaking_change_risk && (
                            <span
                              className={`text-[9px] px-1 py-0.2 rounded border font-mono ${
                                finding.breaking_change_risk === "HIGH"
                                  ? "text-[#FF3B30] border-[#FF3B30]/30"
                                  : finding.breaking_change_risk === "LOW"
                                  ? "text-[#34C759] border-[#34C759]/30"
                                  : "text-amber-500 border-amber-500/30"
                              }`}
                              title="Estimated breaking change risk"
                            >
                              {finding.breaking_change_risk} risk
                            </span>
                          )}
                        </div>
                      ) : (
                        <span className="text-[var(--text-muted)]">No patch yet</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3.5 font-mono text-[12px] text-[var(--accent)]">
                      {finding.cve_id || finding.ghsa_id || finding.rule_id}
                    </td>
                    <td className="py-2.5 px-3.5 font-mono text-[11px] text-[var(--text-secondary)]">
                      {finding.update_command ? (
                        <button
                          onClick={(e) => copyCommand(finding.update_command || "", e)}
                          className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-[var(--bg-secondary)] hover:bg-[var(--bg-hover)] border border-[var(--border-subtle)] text-[var(--accent)] transition-colors"
                          title="Copy update command"
                        >
                          <Terminal className="w-3 h-3 text-[var(--text-muted)]" />
                          <span className="truncate max-w-[160px]">{finding.update_command}</span>
                          {copiedCmd === finding.update_command ? (
                            <Check className="w-3 h-3 text-[#34C759] flex-shrink-0" />
                          ) : (
                            <Copy className="w-3 h-3 text-[var(--text-muted)] flex-shrink-0" />
                          )}
                        </button>
                      ) : (
                        <span className="text-[var(--text-muted)]">—</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3.5 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedFinding(finding);
                        }}
                        className="macos-button h-6 text-[11px] px-2"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Inspector Modal */}
      <FindingDetailModal
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
}
