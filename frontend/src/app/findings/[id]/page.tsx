"use client";

import React, { useState, useEffect, Suspense } from "react";
import { useParams, useRouter } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft,
  FileCode,
  Terminal,
  Copy,
  Check,
  Package,
  Wrench,
  ExternalLink,
  Hash,
  Info,
  CheckCircle2,
  AlertTriangle,
  Flame,
  ShieldAlert,
  GitCommit,
  User,
  Calendar,
  Layers,
  FlaskConical,
  BookOpen,
  Code2,
  ShieldCheck,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { Finding } from "@/lib/types";
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import { MacTrafficLights } from "@/components/common/Icons";

function FindingDetailContent() {
  const params = useParams();
  const router = useRouter();
  const findingId = params?.id as string;

  const [finding, setFinding] = useState<Finding | null>(null);
  const [copied, setCopied] = useState(false);
  const [learningMode, setLearningMode] = useState<"beginner" | "developer" | "engineer">("developer");

  useEffect(() => {
    if (!findingId) return;
    const history = storage.getScanHistory();
    for (const scan of history) {
      const match = scan.findings.find((f) => f.id === findingId);
      if (match) {
        setFinding(match);
        break;
      }
    }
  }, [findingId]);

  if (!finding) {
    return (
      <div className="macos-panel p-10 text-center max-w-md mx-auto my-12 space-y-3">
        <h2 className="text-[15px] font-semibold text-[var(--text-primary)]">Finding Not Found</h2>
        <p className="text-[13px] text-[var(--text-secondary)]">
          The requested finding ID is not in active memory or local browser storage.
        </p>
        <div className="pt-2">
          <Link
            href="/results"
            className="macos-button macos-button-primary"
          >
            <ArrowLeft className="w-3.5 h-3.5 mr-1" />
            <span>Return to Findings</span>
          </Link>
        </div>
      </div>
    );
  }

  const handleCopy = () => {
    if (finding.evidence) {
      navigator.clipboard.writeText(finding.evidence);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const lineRangeText = finding.line_start
    ? finding.line_end && finding.line_end !== finding.line_start
      ? `L${finding.line_start}–L${finding.line_end}`
      : `L${finding.line_start}`
    : null;

  return (
    <div className="space-y-5 max-w-4xl mx-auto">
      {/* Back button & Action Toolbar */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => router.back()}
          className="macos-button text-[12px]"
        >
          <ArrowLeft className="w-3.5 h-3.5 mr-1" />
          <span>Back to Findings</span>
        </button>

        <Link
          href={`/fix-validation?findingId=${finding.id}`}
          className="macos-button macos-button-primary text-[12px] flex items-center gap-1.5"
        >
          <FlaskConical className="w-3.5 h-3.5" />
          <span>Validate Fix in Lab</span>
        </Link>
      </div>

      {/* Main Container */}
      <div className="macos-panel p-6 space-y-6">
        {/* Top Header */}
        <div className="space-y-2.5 pb-4 border-b border-[var(--border-subtle)]">
          <div className="flex items-center justify-between">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              
              {/* Exploitability Priority Badge (Feature 5) */}
              {finding.exploitability_priority && (
                <span
                  className={`text-[11px] font-mono font-semibold px-2 py-0.5 rounded ${
                    finding.exploitability_priority === "P1"
                      ? "bg-[#FF3B30]/15 text-[#FF3B30] border border-[#FF3B30]/30"
                      : finding.exploitability_priority === "P2"
                      ? "bg-[#FF9500]/15 text-[#FF9500] border border-[#FF9500]/30"
                      : "bg-[var(--bg-secondary)] text-[var(--text-secondary)] border border-[var(--border-subtle)]"
                  }`}
                >
                  Priority {finding.exploitability_priority}
                </span>
              )}

              {/* CISA KEV Badge */}
              {finding.cisa_kev && (
                <span className="text-[11px] font-mono font-semibold px-2 py-0.5 rounded bg-[#FF3B30]/20 text-[#FF3B30] border border-[#FF3B30]/40 flex items-center gap-1 animate-pulse">
                  <Flame className="w-3 h-3" />
                  <span>CISA KEV (Actively Exploited)</span>
                </span>
              )}

              <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[var(--bg-secondary)] border border-[var(--border-subtle)] text-[var(--text-secondary)]">
                {finding.category}
              </span>

              <span className="text-[11px] text-[var(--text-secondary)] font-mono px-2 py-0.5 rounded bg-[var(--bg-secondary)] border border-[var(--border-subtle)]">
                Scanner: {finding.detector_name}
              </span>
            </div>
            <MacTrafficLights />
          </div>

          <h1 className="text-[20px] font-semibold text-[var(--text-primary)] tracking-tight">
            {finding.title}
          </h1>
        </div>

        {/* Exploitability Intelligence & Reachability Banner */}
        {(finding.epss_score !== undefined || finding.cisa_kev || finding.reachability_status || finding.priority_rationale) && (
          <div className="p-4 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-[var(--border-subtle)]">
              <span className="text-[11px] uppercase font-semibold text-[var(--text-secondary)] tracking-wider flex items-center gap-1.5">
                <Flame className="w-3.5 h-3.5 text-[var(--system-orange)]" />
                <span>Exploitability &amp; Risk Intelligence</span>
              </span>
              {finding.exploitability_priority && (
                <span className="text-[11px] font-mono text-[var(--text-secondary)]">
                  Calculated Priority: <strong className="text-[var(--text-primary)]">{finding.exploitability_priority}</strong>
                </span>
              )}
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-[12px] font-mono">
              {finding.epss_score !== undefined && (
                <div>
                  <div className="text-[10px] text-[var(--text-secondary)] uppercase">EPSS Probability</div>
                  <div className="text-[13px] font-semibold text-[var(--text-primary)] mt-0.5">
                    {(finding.epss_score * 100).toFixed(2)}%
                    {finding.epss_percentile && (
                      <span className="text-[10px] text-[var(--text-secondary)] ml-1 font-normal">
                        ({(finding.epss_percentile * 100).toFixed(0)}th percentile)
                      </span>
                    )}
                  </div>
                </div>
              )}

              {finding.cvss_score !== undefined && (
                <div>
                  <div className="text-[10px] text-[var(--text-secondary)] uppercase">CVSS Base Score</div>
                  <div className="text-[13px] font-semibold text-[var(--system-orange)] mt-0.5">
                    {finding.cvss_score} / 10.0
                  </div>
                </div>
              )}

              {finding.reachability_status && (
                <div>
                  <div className="text-[10px] text-[var(--text-secondary)] uppercase">Code Reachability</div>
                  <div className="text-[12px] font-semibold text-[var(--accent)] mt-0.5 uppercase">
                    {finding.reachability_status.replace("_", " ")}
                  </div>
                </div>
              )}
            </div>

            {finding.priority_rationale && (
              <div className="text-[12px] text-[var(--text-secondary)] pt-1 leading-relaxed border-t border-[var(--border-subtle)]">
                <strong className="text-[var(--text-primary)]">Priority Rationale: </strong>
                {finding.priority_rationale}
              </div>
            )}
          </div>
        )}

        {/* Git History Secret Leak Details (Feature 3 & 6) */}
        {finding.is_historical && (
          <div className="p-4 rounded-[8px] bg-[#FF9500]/10 border border-[#FF9500]/30 space-y-2.5">
            <div className="flex items-center gap-2 text-[var(--system-orange)] font-semibold text-[13px]">
              <GitCommit className="w-4 h-4" />
              <span>Historical Secret Leak Detected in Git History</span>
            </div>
            <p className="text-[12px] text-[var(--text-primary)] leading-relaxed">
              This credential was discovered in commit history.
              {finding.remains_in_head === false ? (
                <strong className="text-[var(--system-orange)] ml-1">
                  Although removed from current HEAD files, the key remains visible in Git history.
                </strong>
              ) : (
                <strong className="text-[var(--system-red)] ml-1">
                  The secret currently remains exposed in the active working tree.
                </strong>
              )}
            </p>
            <div className="flex flex-wrap items-center gap-4 text-[11px] font-mono text-[var(--text-secondary)] pt-1">
              {finding.commit_sha && (
                <span className="flex items-center gap-1">
                  <Hash className="w-3 h-3" />
                  <span>Commit: {finding.commit_sha.slice(0, 8)}</span>
                </span>
              )}
              {finding.commit_author && (
                <span className="flex items-center gap-1">
                  <User className="w-3 h-3" />
                  <span>Author: {finding.commit_author}</span>
                </span>
              )}
              {finding.commit_date && (
                <span className="flex items-center gap-1">
                  <Calendar className="w-3 h-3" />
                  <span>Date: {new Date(finding.commit_date).toLocaleDateString()}</span>
                </span>
              )}
            </div>
            <div className="text-[11px] text-[var(--system-orange)] font-medium pt-1">
              Critical notice: Removing a secret from the latest commit does not remove it from earlier commits. Immediate credential revocation &amp; rotation is required at the identity provider.
            </div>
          </div>
        )}

        {/* Location & Metadata Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5 p-3.5 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] text-[12px]">
          <div>
            <div className="text-[11px] uppercase text-[var(--text-secondary)] font-medium">
              File Location
            </div>
            <div className="mt-1 font-mono text-[var(--accent)] break-all flex items-center gap-1.5">
              <FileCode className="w-3.5 h-3.5 flex-shrink-0" />
              <span>{finding.file_path}</span>
              {lineRangeText && <span className="text-[var(--text-secondary)] font-semibold">:{lineRangeText}</span>}
            </div>
          </div>

          <div>
            <div className="text-[11px] uppercase text-[var(--text-secondary)] font-medium">
              Detector &amp; Rule ID
            </div>
            <div className="mt-1 font-mono text-[var(--text-primary)] flex items-center gap-1.5">
              <Hash className="w-3.5 h-3.5 text-[var(--text-secondary)]" />
              <span>{finding.rule_id}</span>
            </div>
          </div>

          {finding.package_name && (
            <div>
              <div className="text-[11px] uppercase text-[var(--text-secondary)] font-medium">
                Affected Package
              </div>
              <div className="mt-1 font-mono text-[var(--system-orange)] flex items-center gap-1">
                <Package className="w-3.5 h-3.5" />
                <span>{finding.package_name} ({finding.installed_version || "unknown"})</span>
              </div>
            </div>
          )}

          {finding.fixed_version && (
            <div>
              <div className="text-[11px] uppercase text-[var(--text-secondary)] font-medium">
                Fixed in Version
              </div>
              <div className="mt-1 font-mono text-[var(--system-green)] font-medium flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>&gt;= {finding.fixed_version}</span>
              </div>
            </div>
          )}

          {(finding.cve_id || finding.ghsa_id) && (
            <div className="md:col-span-2 flex flex-wrap gap-2 pt-2 border-t border-[var(--border-subtle)]">
              {finding.cve_id && (
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                  target="_blank"
                  rel="noreferrer"
                  className="macos-button px-2 py-1 text-[11px] font-mono text-[var(--accent)]"
                >
                  <span>{finding.cve_id}</span>
                  <ExternalLink className="w-3 h-3 ml-1" />
                </a>
              )}
              {finding.ghsa_id && (
                <a
                  href={`https://github.com/advisories/${finding.ghsa_id}`}
                  target="_blank"
                  rel="noreferrer"
                  className="macos-button px-2 py-1 text-[11px] font-mono text-[var(--accent)]"
                >
                  <span>{finding.ghsa_id}</span>
                  <ExternalLink className="w-3 h-3 ml-1" />
                </a>
              )}
            </div>
          )}
        </div>

        {/* Security Learning Mode (Feature 13: 3 Explanation Levels) */}
        <div className="macos-card p-4 space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-[var(--border-subtle)]">
            <div className="flex items-center gap-2">
              <BookOpen className="w-4 h-4 text-[var(--accent)]" />
              <h3 className="text-[13px] font-semibold text-[var(--text-primary)]">
                Security Learning Mode
              </h3>
            </div>
            
            {/* Mode Switcher */}
            <div className="flex items-center gap-1 bg-[var(--bg-secondary)] p-0.5 rounded-[6px] border border-[var(--border-subtle)] text-[11px]">
              <button
                onClick={() => setLearningMode("beginner")}
                className={`px-2 py-1 rounded-[4px] font-medium transition-colors ${
                  learningMode === "beginner"
                    ? "bg-[var(--accent)] text-white"
                    : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                }`}
              >
                Beginner Mode
              </button>
              <button
                onClick={() => setLearningMode("developer")}
                className={`px-2 py-1 rounded-[4px] font-medium transition-colors ${
                  learningMode === "developer"
                    ? "bg-[var(--accent)] text-white"
                    : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                }`}
              >
                Developer Mode
              </button>
              <button
                onClick={() => setLearningMode("engineer")}
                className={`px-2 py-1 rounded-[4px] font-medium transition-colors ${
                  learningMode === "engineer"
                    ? "bg-[var(--accent)] text-white"
                    : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                }`}
              >
                Security Engineer
              </button>
            </div>
          </div>

          <div className="text-[13px] text-[var(--text-primary)] leading-relaxed p-3.5 rounded-[6px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)]">
            {learningMode === "beginner" && (
              <div className="space-y-2">
                <span className="text-[11px] font-semibold uppercase text-[var(--accent)] block">
                  Simple Conceptual Explanation
                </span>
                <p>
                  {finding.beginner_explanation ||
                    `This issue happens when sensitive information or insecure configuration is stored directly where unintended parties could see or exploit it. Think of it like leaving a key under the doormat—anyone who knows where to look can gain unauthorized entry.`}
                </p>
              </div>
            )}

            {learningMode === "developer" && (
              <div className="space-y-2">
                <span className="text-[11px] font-semibold uppercase text-[var(--accent)] block">
                  Code-Level Impact &amp; Fix
                </span>
                <p>
                  {finding.developer_explanation ||
                    `The source code contains pattern '${finding.rule_id}' at ${finding.file_path}. To correct this, isolate secrets into runtime environment variables, apply input sanitization or parameter binding, or upgrade dependencies to the safe version >= ${finding.fixed_version || "latest"}.`}
                </p>
              </div>
            )}

            {learningMode === "engineer" && (
              <div className="space-y-2">
                <span className="text-[11px] font-semibold uppercase text-[var(--accent)] block">
                  Technical Impact, Detection Evidence &amp; Trade-offs
                </span>
                <p>
                  {finding.security_engineer_explanation ||
                    `Detection rule '${finding.rule_id}' flagged matching AST/regex evidence with detector '${finding.detector_name}'. CVSS is ${finding.cvss_score || "N/A"}. Remediation requires credential revocation or patch validation in Fix Validation Lab to ensure no regression or behavioral breaks.`}
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Code Evidence Snippet */}
        {finding.evidence && (
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <div className="text-[12px] uppercase text-[var(--text-secondary)] font-medium tracking-wider flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-[var(--text-primary)]" />
                <span>Evidence Snippet (Pre-Redacted)</span>
              </div>
              <button
                onClick={handleCopy}
                className="macos-button px-2 py-1 text-[11px]"
              >
                {copied ? (
                  <>
                    <Check className="w-3 h-3 mr-1 text-[var(--system-green)]" />
                    <span>Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3 mr-1" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>
            <pre className="p-3.5 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] text-[12px] font-mono text-[var(--text-primary)] overflow-x-auto whitespace-pre-wrap break-all leading-5">
              {finding.evidence}
            </pre>
          </div>
        )}

        {/* Actionable Remediation Guidance */}
        <div className="space-y-1.5">
          <div className="text-[12px] uppercase text-[var(--text-secondary)] font-medium tracking-wider flex items-center gap-1.5">
            <Wrench className="w-3.5 h-3.5 text-[var(--system-green)]" />
            <span>Actionable Remediation Guidance</span>
          </div>
          <div className="p-3.5 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] text-[var(--text-primary)] text-[13px] leading-relaxed">
            {finding.remediation}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function FindingDetailPage() {
  return (
    <Suspense
      fallback={
        <div className="p-8 text-center text-[12px] text-[var(--text-secondary)]">
          Loading finding details...
        </div>
      }
    >
      <FindingDetailContent />
    </Suspense>
  );
}
