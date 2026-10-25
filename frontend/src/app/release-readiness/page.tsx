"use client";

import React, { useState, useEffect, useMemo } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Lock,
  Layers,
  FileCheck,
  Flame,
  ArrowRight,
  Settings2,
  RefreshCw,
} from "lucide-react";
import Link from "next/link";
import { storage } from "@/lib/storage";
import { ScanResult, Finding } from "@/lib/types";
import { formatTimeAgo } from "@/lib/utils";
import { EmptyState } from "@/components/common/EmptyState";
import { MacTrafficLights } from "@/components/common/Icons";

interface ReadinessGate {
  id: string;
  name: string;
  description: string;
  category: "vulnerabilities" | "secrets" | "supply_chain" | "governance";
  status: "PASSED" | "FAILED" | "WARNING" | "INCOMPLETE";
  evidence: string;
  remediation?: string;
}

export default function ReleaseReadinessPage() {
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);

  // Policy thresholds configured locally in browser
  const [blockOnCritical, setBlockOnCritical] = useState(true);
  const [blockOnHigh, setBlockOnHigh] = useState(true);
  const [blockOnCisaKev, setBlockOnCisaKev] = useState(true);
  const [blockOnExposedSecrets, setBlockOnExposedSecrets] = useState(true);
  const [maxAllowedHigh, setMaxAllowedHigh] = useState(0);

  useEffect(() => {
    const saved = storage.getScanHistory();
    setHistory(saved);
    if (saved.length > 0) {
      setSelectedScan(saved[0]);
    }
  }, []);

  const findings = selectedScan?.findings || [];

  // Evaluate gates
  const evaluation = useMemo(() => {
    if (!selectedScan) return null;

    const criticalCount = findings.filter((f) => f.severity === "CRITICAL").length;
    const highCount = findings.filter((f) => f.severity === "HIGH").length;
    const kevCount = findings.filter((f) => f.cisa_kev).length;
    const activeSecrets = findings.filter(
      (f) => f.category === "SECRETS" && !f.is_historical && f.remains_in_head !== false
    ).length;
    const historicalSecrets = findings.filter((f) => f.is_historical).length;
    const sbomCount = selectedScan.sbom_components?.length || 0;
    const postureScore = selectedScan.posture_report?.score;

    const gates: ReadinessGate[] = [
      {
        id: "gate-critical",
        name: "Zero Critical Vulnerabilities",
        description: "Enforces zero unmitigated CVSS 9.0+ or Critical findings across all scanners.",
        category: "vulnerabilities",
        status: criticalCount === 0 ? "PASSED" : blockOnCritical ? "FAILED" : "WARNING",
        evidence:
          criticalCount === 0
            ? "No critical severity findings detected."
            : `${criticalCount} critical finding${criticalCount > 1 ? "s" : ""} require resolution before release.`,
        remediation: "Remediate or patch identified critical findings before triggering deployment pipeline.",
      },
      {
        id: "gate-high",
        name: `High Severity Threshold (Limit: ≤ ${maxAllowedHigh})`,
        description: "Requires high severity vulnerabilities to remain strictly within acceptable threshold.",
        category: "vulnerabilities",
        status:
          highCount <= maxAllowedHigh
            ? "PASSED"
            : blockOnHigh
            ? "FAILED"
            : "WARNING",
        evidence:
          highCount === 0
            ? "Zero high severity issues detected."
            : `${highCount} high severity finding${highCount > 1 ? "s" : ""} detected (threshold allowed: ${maxAllowedHigh}).`,
        remediation: "Review high severity issues in Findings tab and resolve or apply verifiable patches.",
      },
      {
        id: "gate-cisa-kev",
        name: "CISA Known Exploited Vulnerabilities (KEV)",
        description: "Zero active vulnerabilities flagged in CISA's catalog of actively exploited exploits.",
        category: "vulnerabilities",
        status: kevCount === 0 ? "PASSED" : blockOnCisaKev ? "FAILED" : "WARNING",
        evidence:
          kevCount === 0
            ? "No findings correlate with CISA Known Exploited Vulnerabilities."
            : `${kevCount} finding${kevCount > 1 ? "s are" : " is"} listed in CISA KEV with active in-the-wild exploitation.`,
        remediation: "Urgent: Immediately upgrade affected libraries to neutralize documented active attacks.",
      },
      {
        id: "gate-secrets-head",
        name: "Zero Active Secrets in HEAD",
        description: "Verifies no unredacted API tokens, private keys, or credentials exist in current repository files.",
        category: "secrets",
        status:
          activeSecrets === 0
            ? "PASSED"
            : blockOnExposedSecrets
            ? "FAILED"
            : "WARNING",
        evidence:
          activeSecrets === 0
            ? "Working tree clean of recognized secret patterns."
            : `${activeSecrets} live credential${activeSecrets > 1 ? "s" : ""} detected in current source files.`,
        remediation: "Revoke credentials immediately at provider dashboard, move secrets to environment variables.",
      },
      {
        id: "gate-secrets-git",
        name: "Historical Git Leak Audit",
        description: "Audit Git commit history for previously committed keys that require credential rotation.",
        category: "secrets",
        status: historicalSecrets === 0 ? "PASSED" : "WARNING",
        evidence:
          historicalSecrets === 0
            ? "No secret patterns found in analyzed commit history."
            : `${historicalSecrets} historical secret${historicalSecrets > 1 ? "s" : ""} detected in past Git commits.`,
        remediation: "Rotate credentials at service provider. Removing keys from HEAD does not invalidate historical commits.",
      },
      {
        id: "gate-sbom",
        name: "Software Bill of Materials (SBOM) Generated",
        description: "CycloneDX/SPDX component inventory verified for software supply chain compliance.",
        category: "supply_chain",
        status: sbomCount > 0 ? "PASSED" : "WARNING",
        evidence:
          sbomCount > 0
            ? `${sbomCount} dependency components verified with package identifiers.`
            : "No dependency lockfiles identified to generate verifiable SBOM.",
        remediation: "Ensure lockfiles (package-lock.json, poetry.lock, go.sum, etc.) are committed.",
      },
      {
        id: "gate-posture",
        name: "Repository Security Posture & Branch Protection",
        description: "OpenSSF Scorecard governance checks and branch protection rules.",
        category: "governance",
        status:
          postureScore !== undefined
            ? postureScore >= 60
              ? "PASSED"
              : "WARNING"
            : "INCOMPLETE",
        evidence:
          postureScore !== undefined
            ? `Calculated posture index is ${postureScore}/100.`
            : "Posture checks unavailable or unassessed.",
        remediation: "Review Security Posture page to enable branch protection and SHA pinning.",
      },
    ];

    // Determine overall release decision:
    // "Ready Under Configured Policy", "Blocked by Policy", "Review Required", "Incomplete Assessment"
    const hasFailed = gates.some((g) => g.status === "FAILED");
    const hasIncomplete = gates.some((g) => g.status === "INCOMPLETE");
    const hasWarning = gates.some((g) => g.status === "WARNING");

    let decision: "Ready Under Configured Policy" | "Blocked by Policy" | "Review Required" | "Incomplete Assessment";
    let decisionColor: string;
    let decisionDescription: string;

    if (hasFailed) {
      decision = "Blocked by Policy";
      decisionColor = "#FF3B30";
      decisionDescription =
        "One or more configured blocking policy rules failed. Release pipeline must be gated until blocking issues are resolved.";
    } else if (hasIncomplete) {
      decision = "Incomplete Assessment";
      decisionColor = "#8E8E93";
      decisionDescription =
        "Required scanners or governance integrations did not complete successfully or lack telemetry to confirm compliance.";
    } else if (hasWarning) {
      decision = "Review Required";
      decisionColor = "#FF9500";
      decisionDescription =
        "Non-blocking warnings or historical leaks were identified that require security engineer acknowledgment prior to shipping.";
    } else {
      decision = "Ready Under Configured Policy";
      decisionColor = "#34C759";
      decisionDescription =
        "All configured security gates passed. The scanned commit complies with active security and dependency criteria.";
    }

    return {
      gates,
      decision,
      decisionColor,
      decisionDescription,
      failedCount: gates.filter((g) => g.status === "FAILED").length,
      warningCount: gates.filter((g) => g.status === "WARNING").length,
      passedCount: gates.filter((g) => g.status === "PASSED").length,
    };
  }, [
    selectedScan,
    findings,
    blockOnCritical,
    blockOnHigh,
    blockOnCisaKev,
    blockOnExposedSecrets,
    maxAllowedHigh,
  ]);

  if (!selectedScan && history.length === 0) {
    return (
      <EmptyState
        icon={ShieldCheck}
        title="No Scans Available for Release Readiness"
        description="Run a repository security scan to evaluate release readiness against your configured security policy."
        actionText="Scan a Repository"
        actionHref="/scan"
      />
    );
  }

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[var(--border-subtle)]">
        <div>
          <h1 className="macos-title flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-[var(--accent)]" />
            <span>Security Release Readiness</span>
          </h1>
          <p className="macos-subtitle">
            Evaluate whether your repository meets automated security policy gates before shipping to production.
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

      {evaluation && (
        <>
          {/* Main Decision Banner */}
          <div
            className="macos-card p-6 border-l-4 space-y-4"
            style={{ borderLeftColor: evaluation.decisionColor }}
          >
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="flex items-start gap-3.5">
                <div
                  className="w-10 h-10 rounded-[8px] flex items-center justify-center flex-shrink-0"
                  style={{
                    backgroundColor: `${evaluation.decisionColor}15`,
                    color: evaluation.decisionColor,
                  }}
                >
                  {evaluation.decision === "Ready Under Configured Policy" && (
                    <CheckCircle2 className="w-6 h-6" />
                  )}
                  {evaluation.decision === "Blocked by Policy" && (
                    <XCircle className="w-6 h-6" />
                  )}
                  {evaluation.decision === "Review Required" && (
                    <AlertTriangle className="w-6 h-6" />
                  )}
                  {evaluation.decision === "Incomplete Assessment" && (
                    <HelpCircle className="w-6 h-6" />
                  )}
                </div>

                <div>
                  <div className="flex items-center gap-2">
                    <span
                      className="text-[11px] font-mono font-semibold px-2 py-0.5 rounded tracking-wide uppercase"
                      style={{
                        backgroundColor: `${evaluation.decisionColor}20`,
                        color: evaluation.decisionColor,
                      }}
                    >
                      Gate Decision
                    </span>
                    <span className="text-[12px] font-mono text-[var(--text-secondary)]">
                      Target: {selectedScan?.owner}/{selectedScan?.repo}
                    </span>
                  </div>
                  <h2
                    className="text-[20px] font-bold tracking-tight mt-1"
                    style={{ color: evaluation.decisionColor }}
                  >
                    {evaluation.decision}
                  </h2>
                  <p className="text-[13px] text-[var(--text-secondary)] mt-1 max-w-2xl leading-relaxed">
                    {evaluation.decisionDescription}
                  </p>
                </div>
              </div>

              {/* Counts Badge */}
              <div className="flex sm:flex-col gap-2 font-mono text-[11px] text-right flex-shrink-0">
                <span className="text-[var(--system-green)] bg-[#34C759]/10 px-2 py-1 rounded border border-[#34C759]/20 font-medium">
                  {evaluation.passedCount} Gates Passed
                </span>
                {evaluation.failedCount > 0 && (
                  <span className="text-[var(--system-red)] bg-[#FF3B30]/10 px-2 py-1 rounded border border-[#FF3B30]/20 font-medium">
                    {evaluation.failedCount} Gates Blocked
                  </span>
                )}
                {evaluation.warningCount > 0 && (
                  <span className="text-[var(--system-orange)] bg-[#FF9500]/10 px-2 py-1 rounded border border-[#FF9500]/20 font-medium">
                    {evaluation.warningCount} Warnings
                  </span>
                )}
              </div>
            </div>

            {/* Disclaimer Alert */}
            <div className="pt-3 border-t border-[var(--border-subtle)] text-[11px] text-[var(--text-muted)] flex items-center justify-between">
              <span>
                Note: Passing configured policy gates indicates adherence to specified baseline thresholds. It does not guarantee the absolute absence of undetected zero-days.
              </span>
              <MacTrafficLights />
            </div>
          </div>

          {/* Policy Configuration Drawer / Controls */}
          <div className="macos-panel p-4 space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-[var(--border-subtle)]">
              <div className="flex items-center gap-2">
                <Settings2 className="w-4 h-4 text-[var(--accent)]" />
                <h3 className="text-[13px] font-semibold text-[var(--text-primary)]">
                  Active Policy Enforcement Rules
                </h3>
              </div>
              <span className="text-[11px] text-[var(--text-secondary)]">
                Local configuration (no database required)
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-[12px]">
              <label className="flex items-center gap-2 p-2 rounded bg-[var(--bg-secondary)] border border-[var(--border-subtle)] cursor-pointer">
                <input
                  type="checkbox"
                  checked={blockOnCritical}
                  onChange={(e) => setBlockOnCritical(e.target.checked)}
                  className="rounded border-[var(--border-subtle)] text-[var(--accent)]"
                />
                <span className="text-[var(--text-primary)] font-medium">
                  Block on Critical Findings
                </span>
              </label>

              <label className="flex items-center gap-2 p-2 rounded bg-[var(--bg-secondary)] border border-[var(--border-subtle)] cursor-pointer">
                <input
                  type="checkbox"
                  checked={blockOnHigh}
                  onChange={(e) => setBlockOnHigh(e.target.checked)}
                  className="rounded border-[var(--border-subtle)] text-[var(--accent)]"
                />
                <span className="text-[var(--text-primary)] font-medium">
                  Block on High Severity
                </span>
              </label>

              <label className="flex items-center gap-2 p-2 rounded bg-[var(--bg-secondary)] border border-[var(--border-subtle)] cursor-pointer">
                <input
                  type="checkbox"
                  checked={blockOnCisaKev}
                  onChange={(e) => setBlockOnCisaKev(e.target.checked)}
                  className="rounded border-[var(--border-subtle)] text-[var(--accent)]"
                />
                <span className="text-[var(--text-primary)] font-medium">
                  Block on CISA KEV Exploits
                </span>
              </label>

              <label className="flex items-center gap-2 p-2 rounded bg-[var(--bg-secondary)] border border-[var(--border-subtle)] cursor-pointer">
                <input
                  type="checkbox"
                  checked={blockOnExposedSecrets}
                  onChange={(e) => setBlockOnExposedSecrets(e.target.checked)}
                  className="rounded border-[var(--border-subtle)] text-[var(--accent)]"
                />
                <span className="text-[var(--text-primary)] font-medium">
                  Block on Live Secrets
                </span>
              </label>
            </div>
          </div>

          {/* Gates Checklist */}
          <div className="macos-card p-5 space-y-4">
            <div>
              <h2 className="text-[14px] font-semibold text-[var(--text-primary)] tracking-tight">
                Policy Gate Conditions &amp; Verification Status
              </h2>
              <p className="text-[12px] text-[var(--text-secondary)]">
                Detailed telemetry determining the release gate verdict for commit {selectedScan?.scan_id.slice(0, 8)}.
              </p>
            </div>

            <div className="divide-y divide-[var(--border-subtle)] border border-[var(--border-subtle)] rounded-[8px] overflow-hidden">
              {evaluation.gates.map((gate) => {
                let badgeColor = "var(--system-green)";
                let badgeBg = "rgba(52, 199, 89, 0.1)";
                let StatusIcon = CheckCircle2;

                if (gate.status === "FAILED") {
                  badgeColor = "var(--system-red)";
                  badgeBg = "rgba(255, 59, 48, 0.1)";
                  StatusIcon = XCircle;
                } else if (gate.status === "WARNING") {
                  badgeColor = "var(--system-orange)";
                  badgeBg = "rgba(255, 149, 0, 0.1)";
                  StatusIcon = AlertTriangle;
                } else if (gate.status === "INCOMPLETE") {
                  badgeColor = "var(--text-muted)";
                  badgeBg = "rgba(142, 142, 147, 0.1)";
                  StatusIcon = HelpCircle;
                }

                return (
                  <div
                    key={gate.id}
                    className="p-4 bg-[var(--bg-primary)] hover:bg-[var(--bg-hover)] transition-colors space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2.5">
                        <StatusIcon
                          className="w-4 h-4 flex-shrink-0"
                          style={{ color: badgeColor }}
                        />
                        <h4 className="text-[13px] font-semibold text-[var(--text-primary)]">
                          {gate.name}
                        </h4>
                      </div>

                      <span
                        className="text-[11px] font-mono px-2 py-0.5 rounded font-semibold uppercase"
                        style={{ color: badgeColor, backgroundColor: badgeBg }}
                      >
                        {gate.status}
                      </span>
                    </div>

                    <p className="text-[12px] text-[var(--text-secondary)] pl-6">
                      {gate.description}
                    </p>

                    <div className="pl-6 pt-1 text-[12px] font-mono text-[var(--text-primary)] bg-[var(--bg-secondary)] p-2.5 rounded-[6px] border border-[var(--border-subtle)]">
                      <span className="text-[var(--text-secondary)] font-sans text-[11px] uppercase mr-2 font-medium">
                        Evidence:
                      </span>
                      {gate.evidence}
                    </div>

                    {gate.status !== "PASSED" && gate.remediation && (
                      <div className="pl-6 text-[12px] text-[var(--accent)] flex items-center gap-1.5 pt-1">
                        <ArrowRight className="w-3.5 h-3.5" />
                        <span>Action: {gate.remediation}</span>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
