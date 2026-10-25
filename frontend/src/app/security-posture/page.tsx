"use client";

import React, { useState, useEffect, Suspense } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  HelpCircle,
  ExternalLink,
  Lock,
  GitBranch,
  FileText,
  Workflow,
  Cpu,
  Info,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { ScanResult, PostureReport, PostureCheck } from "@/lib/types";
import { MacTrafficLights } from "@/components/common/Icons";

function SecurityPostureContent() {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string>("ALL");

  useEffect(() => {
    const history = storage.getScanHistory();
    setScans(history);
    if (history.length > 0) {
      setSelectedScan(history[0]);
    }
  }, []);

  const handleScanChange = (scanId: string) => {
    const scan = scans.find((s) => s.scan_id === scanId);
    if (scan) setSelectedScan(scan);
  };

  const report: PostureReport | undefined = selectedScan?.posture_report;
  const checks: PostureCheck[] = report?.checks || [];

  const filteredChecks = checks.filter((c) => {
    if (categoryFilter === "ALL") return true;
    return c.category === categoryFilter;
  });

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "Verified":
        return (
          <span className="flex items-center gap-1 text-[11px] font-medium text-[var(--system-green)] bg-[var(--system-green)]/10 px-2 py-0.5 rounded-[4px] border border-[var(--system-green)]/20">
            <CheckCircle2 className="w-3 h-3" />
            <span>Verified</span>
          </span>
        );
      case "Improvement recommended":
        return (
          <span className="flex items-center gap-1 text-[11px] font-medium text-[var(--system-orange)] bg-[var(--system-orange)]/10 px-2 py-0.5 rounded-[4px] border border-[var(--system-orange)]/20">
            <AlertTriangle className="w-3 h-3" />
            <span>Improvement Recommended</span>
          </span>
        );
      case "Failed":
        return (
          <span className="flex items-center gap-1 text-[11px] font-medium text-[var(--system-red)] bg-[var(--system-red)]/10 px-2 py-0.5 rounded-[4px] border border-[var(--system-red)]/20">
            <XCircle className="w-3 h-3" />
            <span>Failed</span>
          </span>
        );
      case "Unavailable":
        return (
          <span className="flex items-center gap-1 text-[11px] font-medium text-[var(--text-muted)] bg-[var(--bg-secondary)] px-2 py-0.5 rounded-[4px] border border-[var(--border-subtle)]">
            <Lock className="w-3 h-3" />
            <span>Unavailable (Permissions)</span>
          </span>
        );
      case "Not detected":
        return (
          <span className="flex items-center gap-1 text-[11px] font-medium text-[var(--text-secondary)] bg-[var(--bg-secondary)] px-2 py-0.5 rounded-[4px] border border-[var(--border-subtle)]">
            <HelpCircle className="w-3 h-3" />
            <span>Not Detected</span>
          </span>
        );
      default:
        return (
          <span className="text-[11px] text-[var(--text-muted)] bg-[var(--bg-secondary)] px-2 py-0.5 rounded-[4px]">
            {status}
          </span>
        );
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Top Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-[var(--border-subtle)]">
        <div className="space-y-1 min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="p-1.5 rounded-[6px] bg-[var(--accent)]/10 text-[var(--accent)] shrink-0 flex-shrink-0">
              <ShieldCheck className="w-5 h-5" />
            </span>
            <h1 className="text-[20px] font-semibold text-[var(--text-primary)] tracking-tight">
              Repository Security Posture
            </h1>
            <span className="text-[11px] font-mono px-2.5 py-0.5 rounded-full bg-[var(--accent)]/15 text-[var(--accent)] border border-[var(--accent)]/30 whitespace-nowrap shrink-0 flex-shrink-0 inline-flex items-center">
              OpenSSF Scorecard
            </span>
          </div>
          <p className="text-[13px] text-[var(--text-secondary)] mt-1">
            Evaluates branch protection, CI/CD permissions, dependency automation, and supply chain governance controls.
          </p>
        </div>

        {/* Scan Selector */}
        {scans.length > 0 && (
          <div className="flex items-center gap-3">
            <span className="text-[12px] text-[var(--text-secondary)]">Target:</span>
            <select
              value={selectedScan?.scan_id || ""}
              onChange={(e) => handleScanChange(e.target.value)}
              className="macos-input text-[12px] py-1 px-2.5 max-w-[220px]"
            >
              {scans.map((s) => (
                <option key={s.scan_id} value={s.scan_id}>
                  {s.owner}/{s.repo} (Score: {s.posture_report?.score || "N/A"})
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {!report ? (
        <div className="macos-panel p-12 text-center max-w-lg mx-auto space-y-3">
          <ShieldAlert className="w-10 h-10 text-[var(--text-muted)] mx-auto" />
          <h3 className="text-[15px] font-semibold text-[var(--text-primary)]">
            No Security Posture Data Available
          </h3>
          <p className="text-[13px] text-[var(--text-secondary)] leading-relaxed">
            Run a new scan with &ldquo;Repository Security Posture&rdquo; enabled to evaluate branch protection, CODEOWNERS, and CI/CD policies.
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Posture Score Hero */}
          <div className="macos-panel p-6 flex flex-col md:flex-row md:items-center justify-between gap-6 bg-gradient-to-r from-[var(--bg-primary)] to-[var(--bg-secondary)]">
            <div className="space-y-2">
              <div className="flex items-center gap-2.5">
                <span className="text-[11px] font-mono uppercase text-[var(--text-secondary)]">
                  Posture Rating
                </span>
                <span
                  className={`text-[11px] font-semibold uppercase px-2 py-0.5 rounded-[4px] ${
                    report.level === "EXCELLENT"
                      ? "bg-[var(--system-green)]/15 text-[var(--system-green)]"
                      : report.level === "GOOD"
                      ? "bg-[var(--accent)]/15 text-[var(--accent)]"
                      : report.level === "MODERATE"
                      ? "bg-[var(--system-orange)]/15 text-[var(--system-orange)]"
                      : "bg-[var(--system-red)]/15 text-[var(--system-red)]"
                  }`}
                >
                  {report.level} Posture
                </span>
              </div>
              <h2 className="text-[26px] font-bold text-[var(--text-primary)] tracking-tight">
                {selectedScan?.owner}/{selectedScan?.repo}
              </h2>
              <p className="text-[12px] text-[var(--text-secondary)] max-w-2xl leading-relaxed">
                {report.methodology}
              </p>
            </div>

            {/* Score Ring Display */}
            <div className="flex items-center gap-4 bg-[var(--bg-primary)] p-4 rounded-[10px] border border-[var(--border-subtle)] flex-shrink-0">
              <div className="text-right">
                <div className="text-[34px] font-bold text-[var(--accent)] font-mono leading-none">
                  {report.score}
                  <span className="text-[16px] text-[var(--text-muted)] font-normal">/100</span>
                </div>
                <div className="text-[11px] text-[var(--text-secondary)] mt-1">
                  OpenSSF Index
                </div>
              </div>
              <MacTrafficLights />
            </div>
          </div>

          {/* Checks Breakdown */}
          <div className="space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 px-1">
              <span className="text-[12px] font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
                Audited Controls ({filteredChecks.length})
              </span>
              <div className="flex items-center gap-2">
                {["ALL", "Governance", "Supply Chain", "CI/CD", "Branch Protections"].map((cat) => (
                  <button
                    key={cat}
                    onClick={() => setCategoryFilter(cat)}
                    className={`text-[11px] px-2.5 py-1 rounded-[5px] transition-colors ${
                      categoryFilter === cat
                        ? "bg-[var(--accent)] text-white font-medium"
                        : "bg-[var(--bg-secondary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {filteredChecks.map((check) => (
                <div
                  key={check.id}
                  className="macos-panel p-4 space-y-3 flex flex-col justify-between"
                >
                  <div className="space-y-2">
                    <div className="flex items-start justify-between gap-2">
                      <span className="text-[11px] font-mono text-[var(--text-muted)] uppercase">
                        {check.category}
                      </span>
                      {getStatusBadge(check.status)}
                    </div>
                    <h3 className="text-[14px] font-semibold text-[var(--text-primary)]">
                      {check.name}
                    </h3>
                    <p className="text-[12px] text-[var(--text-secondary)] leading-relaxed">
                      {check.evidence}
                    </p>
                  </div>

                  <div className="pt-3 border-t border-[var(--border-subtle)] space-y-2 text-[11px]">
                    <div className="text-[var(--text-primary)]">
                      <strong>Recommendation:</strong> {check.recommendation}
                    </div>
                    {check.documentation_url && (
                      <a
                        href={check.documentation_url}
                        target="_blank"
                        rel="noreferrer"
                        className="text-[var(--accent)] hover:underline inline-flex items-center gap-1"
                      >
                        <span>Official Documentation</span>
                        <ExternalLink className="w-3 h-3" />
                      </a>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function SecurityPosturePage() {
  return (
    <Suspense fallback={<div className="p-8 text-center text-[var(--text-muted)]">Loading Security Posture...</div>}>
      <SecurityPostureContent />
    </Suspense>
  );
}
