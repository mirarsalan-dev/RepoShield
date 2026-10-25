"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  LayoutDashboard,
  GitBranch,
  Clock,
  ArrowRight,
  SearchCode,
  Eye,
  FileCheck2,
  CheckCircle2,
  AlertCircle,
  XCircle,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { ScanResult, Finding } from "@/lib/types";
import { PageHeader } from "@/components/common/PageHeader";
import { MetricsCards } from "@/components/dashboard/MetricsCards";
import { ScannerStatus } from "@/components/dashboard/ScannerStatus";
import { SeverityChart } from "@/components/dashboard/SeverityChart";
import { EmptyState } from "@/components/common/EmptyState";
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import { FindingDetailModal } from "@/components/findings/FindingDetailModal";
import { formatDate, formatTimeAgo } from "@/lib/utils";

export default function DashboardPage() {
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [inspectFinding, setInspectFinding] = useState<Finding | null>(null);

  useEffect(() => {
    const saved = storage.getScanHistory();
    setHistory(saved);
    if (saved.length > 0) {
      setSelectedScan(saved[0]);
    }
  }, []);

  if (!selectedScan || history.length === 0) {
    return (
      <EmptyState
        icon={LayoutDashboard}
        title="No scans yet"
        description="Scan a GitHub repository to inspect secrets, dependencies, and supported security issues."
        actionText="Scan Repository"
        actionHref="/scan"
      />
    );
  }

  // Count unique repositories scanned
  const uniqueRepos = new Set(history.map((s) => `${s.owner}/${s.repo}`));
  const totalRepositoriesScanned = uniqueRepos.size;

  // Resolved findings calculation if historical comparisons exist
  const reviewedFindings = storage.getReviewedFindings();
  const resolvedCount = reviewedFindings.length;

  const topFindings = [...selectedScan.findings]
    .sort((a, b) => {
      const order: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4, INFO: 5 };
      return (order[a.severity] ?? 99) - (order[b.severity] ?? 99);
    })
    .slice(0, 6);

  const lastScanTimestamp = selectedScan.completed_at || selectedScan.started_at;

  return (
    <div className="space-y-6">
      {/* Restrained Page Header */}
      <PageHeader
        title="Overview"
        description="A concise summary of your repository security status and real scanner activity."
        badge={
          lastScanTimestamp ? (
            <span className="hidden sm:inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border)] text-[11px] font-mono text-[var(--foreground-secondary)]">
              <Clock className="w-3 h-3 text-[var(--foreground-tertiary)]" />
              <span>Last scan {formatTimeAgo(lastScanTimestamp)}</span>
            </span>
          ) : undefined
        }
        actions={
          <div className="flex items-center gap-2">
            {history.length > 1 && (
              <select
                value={selectedScan.scan_id}
                onChange={(e) => {
                  const found = history.find((s) => s.scan_id === e.target.value);
                  if (found) {
                    setSelectedScan(found);
                    storage.saveScan(found);
                  }
                }}
                className="macos-select h-9 text-[12px] cursor-pointer"
              >
                {history.map((scan) => (
                  <option key={scan.scan_id} value={scan.scan_id}>
                    {scan.owner}/{scan.repo} ({formatTimeAgo(scan.completed_at || scan.started_at)})
                  </option>
                ))}
              </select>
            )}

            <Link href="/scan" className="btn-primary">
              <SearchCode className="w-4 h-4" />
              <span>Scan Repository</span>
            </Link>
          </div>
        }
      />

      {/* 4 Compact Summary Information Panels */}
      <MetricsCards
        riskScore={selectedScan.risk_score}
        totalRepositoriesScanned={totalRepositoriesScanned}
        resolvedCount={resolvedCount}
      />

      {/* Honest Scanner Engine Status (Real diagnostic availability) */}
      <ScannerStatus currentScan={selectedScan} />

      {/* Main Two-Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column (7 cols): Findings by Severity & Top Findings */}
        <div className="lg:col-span-7 space-y-6">
          {/* Findings by Severity */}
          <SeverityChart riskScore={selectedScan.risk_score} />

          {/* Key Security Findings */}
          <div className="macos-panel p-4 space-y-3 border border-[var(--border)] rounded-[var(--radius-md)] bg-[var(--surface)]">
            <div className="flex items-center justify-between pb-2 border-b border-[var(--border)]">
              <div>
                <h3 className="text-[13px] font-semibold text-[var(--foreground)]">
                  Key Security Findings
                </h3>
                <p className="text-[11px] text-[var(--foreground-tertiary)]">
                  Highest severity issues requiring remediation
                </p>
              </div>
              <Link
                href="/results"
                className="text-[12px] text-[var(--primary)] hover:underline flex items-center gap-1 font-medium"
              >
                <span>View all ({selectedScan.findings.length})</span>
                <ArrowRight className="w-3 h-3" />
              </Link>
            </div>

            <div className="divide-y divide-[var(--border)]">
              {topFindings.length === 0 ? (
                <div className="py-8 text-center text-[13px] text-[var(--foreground-secondary)]">
                  No open findings in this repository.
                </div>
              ) : (
                topFindings.map((finding) => (
                  <div
                    key={finding.id}
                    onClick={() => setInspectFinding(finding)}
                    className="py-2.5 px-2 flex items-center justify-between gap-3 hover:bg-[var(--surface-hover)] rounded-[var(--radius-sm)] cursor-pointer transition-colors"
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <SeverityBadge severity={finding.severity} />
                      <div className="min-w-0">
                        <div className="text-[13px] font-medium text-[var(--foreground)] truncate">
                          {finding.title}
                        </div>
                        <div className="text-[11px] font-mono text-[var(--foreground-tertiary)] truncate mt-0.5">
                          {finding.file_path}{finding.line_start ? `:${finding.line_start}` : ""}
                        </div>
                      </div>
                    </div>

                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setInspectFinding(finding);
                      }}
                      className="p-1.5 rounded-[var(--radius-sm)] text-[var(--foreground-tertiary)] hover:text-[var(--foreground)] hover:bg-[var(--surface-secondary)] transition-colors"
                      title="Inspect finding details"
                    >
                      <Eye className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Right Column (5 cols): Repository Context & Recent Activity */}
        <div className="lg:col-span-5 space-y-6">
          {/* Target Repository Info */}
          <div className="macos-panel p-4 space-y-3.5 border border-[var(--border)] rounded-[var(--radius-md)] bg-[var(--surface)]">
            <div className="flex items-center justify-between pb-2 border-b border-[var(--border)]">
              <h3 className="text-[13px] font-semibold text-[var(--foreground)]">
                Repository Security Context
              </h3>
              <span className="text-[11px] font-mono px-2 py-0.5 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border)] text-[var(--foreground-secondary)]">
                {selectedScan.branch}
              </span>
            </div>

            <div className="space-y-2 text-[13px]">
              <div className="flex items-center justify-between p-2.5 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border)]">
                <span className="text-[var(--foreground-secondary)]">Calculated Risk Score</span>
                <span className="font-semibold text-[15px] font-mono text-[var(--foreground)]">
                  {selectedScan.risk_score?.score ?? 0}
                  <span className="text-[11px] text-[var(--foreground-tertiary)] font-normal"> / 100</span>
                </span>
              </div>

              <div className="flex items-center justify-between p-2.5 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border)]">
                <span className="text-[var(--foreground-secondary)]">Posture Level</span>
                <span className="font-medium text-[12px] uppercase tracking-wide">
                  {selectedScan.risk_score?.level ?? "SECURE"}
                </span>
              </div>

              <div className="flex items-center justify-between p-2.5 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border)]">
                <span className="text-[var(--foreground-secondary)]">Target Repository</span>
                <span className="font-mono text-[12px] text-[var(--foreground)] truncate max-w-[170px]">
                  {selectedScan.owner}/{selectedScan.repo}
                </span>
              </div>

              <div className="flex items-center justify-between p-2.5 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border)]">
                <span className="text-[var(--foreground-secondary)]">Commit Analyzed</span>
                <span className="font-mono text-[12px] text-[var(--foreground-tertiary)]">
                  {selectedScan.commit_sha ? selectedScan.commit_sha.slice(0, 7) : "HEAD"}
                </span>
              </div>

              <div className="flex items-center justify-between p-2.5 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border)]">
                <span className="text-[var(--foreground-secondary)]">Duration</span>
                <span className="text-[12px] font-mono text-[var(--foreground-tertiary)]">
                  {selectedScan.duration_seconds}s
                </span>
              </div>
            </div>
          </div>

          {/* Compact Recent Activity List */}
          <div className="macos-panel p-4 space-y-3 border border-[var(--border)] rounded-[var(--radius-md)] bg-[var(--surface)]">
            <div className="flex items-center justify-between pb-2 border-b border-[var(--border)]">
              <div>
                <h3 className="text-[13px] font-semibold text-[var(--foreground)]">
                  Recent Scans
                </h3>
                <p className="text-[11px] text-[var(--foreground-tertiary)]">
                  Historical scans in local cache
                </p>
              </div>
              <Link
                href="/history"
                className="text-[12px] text-[var(--primary)] hover:underline flex items-center gap-1 font-medium"
              >
                <span>All ({history.length})</span>
                <ArrowRight className="w-3 h-3" />
              </Link>
            </div>

            <div className="space-y-1.5">
              {history.slice(0, 5).map((scan) => {
                const isCurrent = scan.scan_id === selectedScan.scan_id;
                const isSuccess = scan.status === "COMPLETED";
                const isFailed = scan.status === "FAILED" || scan.status === "CANCELLED";

                return (
                  <div
                    key={scan.scan_id}
                    onClick={() => {
                      setSelectedScan(scan);
                      storage.saveScan(scan);
                    }}
                    className={`p-2.5 rounded-[var(--radius-sm)] border transition-all cursor-pointer flex items-center justify-between text-[12px] ${
                      isCurrent
                        ? "bg-[var(--surface-secondary)] border-[var(--border-strong)]"
                        : "bg-transparent border-transparent hover:bg-[var(--surface-hover)]"
                    }`}
                  >
                    <div className="min-w-0 pr-2">
                      <div className="flex items-center gap-2">
                        {isSuccess ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-[var(--success)] flex-shrink-0" />
                        ) : isFailed ? (
                          <XCircle className="w-3.5 h-3.5 text-[var(--danger)] flex-shrink-0" />
                        ) : (
                          <AlertCircle className="w-3.5 h-3.5 text-[var(--warning)] flex-shrink-0" />
                        )}
                        <span className="font-medium text-[var(--foreground)] truncate">
                          {scan.owner}/{scan.repo}
                        </span>
                      </div>
                      <div className="text-[11px] text-[var(--foreground-tertiary)] font-mono mt-0.5 pl-5">
                        {formatTimeAgo(scan.completed_at || scan.started_at)} • {scan.findings.length} findings
                      </div>
                    </div>

                    <div className="text-right flex-shrink-0">
                      <span className="font-mono text-[12px] font-medium text-[var(--foreground)]">
                        Risk {scan.risk_score?.score ?? 0}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Finding Inspector Detail Modal */}
      <FindingDetailModal
        finding={inspectFinding}
        onClose={() => setInspectFinding(null)}
      />
    </div>
  );
}
