"use client";

import React, { useState, useEffect, useMemo } from "react";
import Link from "next/link";
import {
  Key,
  Search,
  RotateCcw,
  Copy,
  Check,
  ShieldAlert,
  Lock,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { ScanResult, Finding } from "@/lib/types";
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import { FindingDetailModal } from "@/components/findings/FindingDetailModal";
import { EmptyState } from "@/components/common/EmptyState";
import { formatTimeAgo } from "@/lib/utils";

export default function SecretsPage() {
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [search, setSearch] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("ALL");
  const [selectedDetector, setSelectedDetector] = useState<string>("ALL");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [copiedFile, setCopiedFile] = useState<string | null>(null);

  useEffect(() => {
    const saved = storage.getScanHistory();
    setHistory(saved);
    if (saved.length > 0) {
      setSelectedScan(saved[0]);
    }
  }, []);

  const secretFindings = useMemo(() => {
    if (!selectedScan) return [];
    return selectedScan.findings.filter((f) => f.category === "SECRETS");
  }, [selectedScan]);

  const detectors = useMemo(() => {
    const set = new Set<string>();
    secretFindings.forEach((f) => set.add(f.rule_id));
    return Array.from(set);
  }, [secretFindings]);

  const filteredFindings = useMemo(() => {
    return secretFindings.filter((f) => {
      if (selectedSeverity !== "ALL" && f.severity !== selectedSeverity) return false;
      if (selectedDetector !== "ALL" && f.rule_id !== selectedDetector) return false;
      if (search.trim()) {
        const q = search.toLowerCase();
        const matchesTitle = f.title.toLowerCase().includes(q);
        const matchesRule = f.rule_id.toLowerCase().includes(q);
        const matchesFile = f.file_path.toLowerCase().includes(q);
        if (!matchesTitle && !matchesRule && !matchesFile) return false;
      }
      return true;
    });
  }, [secretFindings, selectedSeverity, selectedDetector, search]);

  if (!selectedScan && history.length === 0) {
    return (
      <EmptyState
        icon={Key}
        title="No Secret Audits"
        description="Scan any GitHub repository with Gitleaks to inspect commits and source files for exposed credentials."
        actionText="Scan a Repository"
        actionHref="/scan"
      />
    );
  }

  const copyPath = (path: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(path);
    setCopiedFile(path);
    setTimeout(() => setCopiedFile(null), 2000);
  };

  return (
    <div className="space-y-4">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[var(--border-color)]">
        <div>
          <h1 className="text-[22px] font-semibold tracking-tight text-[var(--text-primary)]">
            Secrets
          </h1>
          <p className="text-[13px] text-[var(--text-secondary)] mt-0.5">
            Gitleaks detector identification with pre-redacted credentials.
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
          <div className="text-[var(--text-secondary)]">Exposed secrets</div>
          <div className="text-xl font-semibold text-[#FF3B30] dark:text-[#FF453A]">{secretFindings.length}</div>
        </div>
        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Redaction status</div>
          <div className="text-xl font-semibold text-[#34C759] dark:text-[#30D158]">100% Redacted</div>
        </div>
        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Scanner engine</div>
          <div className="text-xl font-semibold text-[var(--text-primary)]">Gitleaks</div>
        </div>
        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Target repository</div>
          <div className="font-mono text-[13px] font-medium text-[var(--text-primary)] truncate mt-1">
            {selectedScan?.owner}/{selectedScan?.repo}
          </div>
        </div>
      </div>

      {/* Revocation Protocol Guidance Inset */}
      <div className="p-3.5 rounded-[6px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] space-y-2 text-[12px]">
        <div className="flex items-center gap-1.5 font-semibold text-[var(--text-primary)]">
          <ShieldAlert className="w-3.5 h-3.5 text-[#FF3B30]" />
          <span>Credential Revocation Guidance</span>
        </div>
        <p className="text-[var(--text-secondary)] text-[12px] leading-normal">
          Committed secrets remain accessible in git commit history. Deleting lines or files is insufficient.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2 pt-1 font-mono text-[11px] text-[var(--text-secondary)]">
          <div className="p-2 rounded bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
            <strong className="text-[var(--text-primary)]">1. Invalidate:</strong> Revoke the token immediately in the service provider console.
          </div>
          <div className="p-2 rounded bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
            <strong className="text-[var(--text-primary)]">2. Purge History:</strong> Run <code className="text-[var(--accent)]">git-filter-repo</code> to remove the commit entry.
          </div>
          <div className="p-2 rounded bg-[var(--bg-surface)] border border-[var(--border-subtle)]">
            <strong className="text-[var(--text-primary)]">3. Reissue:</strong> Store newly issued credentials inside GitHub Actions Secrets.
          </div>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="flex flex-col sm:flex-row gap-2.5 items-stretch sm:items-center justify-between">
        <div className="relative flex-1 max-w-sm">
          <Search className="w-3.5 h-3.5 text-[var(--text-muted)] absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by rule ID, file location..."
            className="macos-input w-full pl-8 text-[12px]"
          />
        </div>

        <div className="flex items-center gap-2">
          {detectors.length > 0 && (
            <select
              value={selectedDetector}
              onChange={(e) => setSelectedDetector(e.target.value)}
              className="macos-input h-7 text-[12px] cursor-pointer"
            >
              <option value="ALL">All Detectors</option>
              {detectors.map((d) => (
                <option key={d} value={d}>{d}</option>
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
          </select>

          {(search || selectedSeverity !== "ALL" || selectedDetector !== "ALL") && (
            <button
              onClick={() => {
                setSearch("");
                setSelectedSeverity("ALL");
                setSelectedDetector("ALL");
              }}
              className="macos-button h-7 text-[12px] px-2 text-[var(--text-secondary)]"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Reset</span>
            </button>
          )}
        </div>
      </div>

      {/* Secret Detection Table */}
      <div className="macos-panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-[13px]">
            <thead>
              <tr className="border-b border-[var(--border-color)] bg-[var(--bg-secondary)] text-[var(--text-secondary)] text-[11px] font-medium select-none">
                <th className="py-2 px-3.5 w-24">Severity</th>
                <th className="py-2 px-3.5 w-44">Detector</th>
                <th className="py-2 px-3.5">Finding Description</th>
                <th className="py-2 px-3.5">File Location</th>
                <th className="py-2 px-3.5">Masked Evidence</th>
                <th className="py-2 px-3.5 text-right w-20">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-subtle)]">
              {filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-10 text-center text-[var(--text-secondary)] text-[12px]">
                    {secretFindings.length === 0
                      ? "Zero exposed secrets detected by Gitleaks."
                      : "No secrets match active filters."}
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
                    <td className="py-2.5 px-3.5 font-mono text-[12px] font-medium text-[var(--text-primary)]">
                      {finding.rule_id}
                    </td>
                    <td className="py-2.5 px-3.5">
                      <div className="font-medium text-[var(--text-primary)] line-clamp-1">{finding.title}</div>
                      <div className="text-[11px] text-[var(--text-muted)] line-clamp-1 mt-0.5">{finding.description}</div>
                    </td>
                    <td className="py-2.5 px-3.5 font-mono text-[12px] text-[var(--text-secondary)]">
                      <div className="flex items-center gap-1.5">
                        <span className="line-clamp-1 break-all">{finding.file_path}</span>
                        {finding.line_start && (
                          <span className="text-[var(--text-muted)] font-medium">:{finding.line_start}</span>
                        )}
                        <button
                          onClick={(e) => copyPath(finding.file_path, e)}
                          className="hover:text-[var(--accent)] p-0.5 transition-colors"
                          title="Copy path"
                        >
                          {copiedFile === finding.file_path ? (
                            <Check className="w-3 h-3 text-[#34C759]" />
                          ) : (
                            <Copy className="w-3 h-3 text-[var(--text-muted)]" />
                          )}
                        </button>
                      </div>
                    </td>
                    <td className="py-2.5 px-3.5 font-mono text-[11px]">
                      <span className="px-1.5 py-0.5 rounded bg-[var(--bg-secondary)] border border-[var(--border-subtle)] text-[#FF9500] dark:text-[#FF9F0A]">
                        {finding.evidence ? (
                          finding.evidence.length > 22 ? `${finding.evidence.slice(0, 18)}...` : finding.evidence
                        ) : (
                          "ghp_••••••••••••"
                        )}
                      </span>
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
