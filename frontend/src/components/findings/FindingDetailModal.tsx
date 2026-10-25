"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  X,
  Copy,
  Check,
  ExternalLink,
  FileCode,
  Package,
  Wrench,
  Hash,
  Info,
  CheckCircle2,
  Download,
  ShieldAlert,
  Sparkles,
  AlertTriangle,
  GitCommit,
  ClipboardCheck,
  Milestone,
} from "lucide-react";
import { Finding, PolicySuppression } from "@/lib/types";
import { SeverityBadge } from "./SeverityBadge";
import { storage } from "@/lib/storage";
import { api } from "@/lib/api";
import { AnimatedDialog } from "@/components/motion";

interface FindingDetailModalProps {
  finding: Finding | null;
  onClose: () => void;
  onStatusChange?: () => void;
}

export function FindingDetailModal({ finding: findingProp, onClose, onStatusChange }: FindingDetailModalProps) {
  const [renderedFinding, setRenderedFinding] = useState<Finding | null>(findingProp);
  const [copiedType, setCopiedType] = useState<string | null>(null);
  const [isSuppressDialogOpen, setIsSuppressDialogOpen] = useState(false);
  const [suppressReason, setSuppressReason] = useState("");
  const [suppressExpiry, setSuppressExpiry] = useState("");
  const [aiLoading, setAiLoading] = useState(false);
  const [aiExplanation, setAiExplanation] = useState<string | null>(null);

  useEffect(() => {
    if (findingProp) {
      setRenderedFinding(findingProp);
    }
  }, [findingProp]);

  const activeFinding = findingProp || renderedFinding;
  if (!activeFinding) return null;
  const finding = activeFinding;

  const fingerprint = finding.fingerprint || `${finding.detector_name}:${finding.rule_id}:${finding.file_path}`;
  const suppressions = storage.getSuppressions();
  const activeSuppression = suppressions.find((s) => s.fingerprint === fingerprint);
  const isSuppressed = !!activeSuppression;
  const reviewedList = storage.getReviewedFindings();
  const isReviewed = reviewedList.includes(finding.id);

  const copyToClipboard = (text: string, type: string) => {
    navigator.clipboard.writeText(text);
    setCopiedType(type);
    setTimeout(() => setCopiedType(null), 2000);
  };

  const handleDownloadPatch = () => {
    if (!finding.suggested_patch) return;
    const blob = new Blob([finding.suggested_patch], { type: "text/x-diff;charset=utf-8;" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `fix-${finding.rule_id.replace(/[^a-zA-Z0-9_-]/g, "_")}.patch`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  };

  const handleToggleReviewed = () => {
    storage.toggleReviewedFinding(finding.id);
    if (onStatusChange) onStatusChange();
  };

  const handleConfirmSuppression = (e: React.FormEvent) => {
    e.preventDefault();
    if (!suppressReason.trim()) return;

    const newSuppression: PolicySuppression = {
      fingerprint,
      rule_id: finding.rule_id,
      reason: suppressReason.trim(),
      expires_at: suppressExpiry ? new Date(suppressExpiry).toISOString() : undefined,
      created_at: new Date().toISOString(),
    };

    storage.addSuppression(newSuppression);
    setIsSuppressDialogOpen(false);
    setSuppressReason("");
    setSuppressExpiry("");
    if (onStatusChange) onStatusChange();
  };

  const handleRemoveSuppression = () => {
    storage.removeSuppression(fingerprint);
    if (onStatusChange) onStatusChange();
  };

  const handleRequestAiExplanation = async () => {
    setAiLoading(true);
    try {
      const res = await api.explainFinding(finding);
      setAiExplanation(res.explanation);
    } catch {
      setAiExplanation(
        "AI Assistant is currently operating in offline mode. Please configure GEMINI_API_KEY or OPENAI_API_KEY in the backend environment to enable live cloud explanations."
      );
    } finally {
      setAiLoading(false);
    }
  };

  const lineRangeText = finding.line_start
    ? finding.line_end && finding.line_end !== finding.line_start
      ? `L${finding.line_start}–L${finding.line_end}`
      : `L${finding.line_start}`
    : null;

  const evidenceLines = finding.evidence ? finding.evidence.split("\n") : [];
  const startLineNumber = finding.line_start || 1;

  return (
    <AnimatedDialog
      isOpen={!!findingProp}
      onClose={onClose}
      className="w-full max-w-3xl max-h-[90vh] overflow-y-auto text-[var(--foreground-primary)] flex flex-col bg-[var(--surface)] border border-[var(--border-strong)] rounded-[var(--radius-lg)] shadow-[var(--shadow-dialog)]"
      ariaLabel="Finding Details"
    >
        {/* macOS Sheet Header */}
        <div className="flex items-start justify-between p-5 border-b border-[var(--border)] bg-[var(--surface)] sticky top-0 z-20">
          <div className="space-y-1.5 pr-6">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              {finding.confidence && (
                <span className="text-[11px] font-mono px-2 py-0.5 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border-subtle)] text-[var(--foreground-secondary)]">
                  Confidence: {finding.confidence}
                </span>
              )}
              <span className="text-[11px] font-mono px-2 py-0.5 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border-subtle)] text-[var(--foreground-secondary)]">
                {finding.category}
              </span>
              <span className="text-[11px] text-[var(--foreground-tertiary)] font-mono">
                Scanner: {finding.detector_name}
              </span>

              {isSuppressed && (
                <span className="text-[11px] font-mono px-2 py-0.5 rounded-[var(--radius-sm)] bg-[var(--warning-subtle)] text-[var(--warning)] border border-[var(--warning)]/30">
                  SUPPRESSED
                </span>
              )}
              {isReviewed && !isSuppressed && (
                <span className="text-[11px] font-mono px-2 py-0.5 rounded-[var(--radius-sm)] bg-[var(--success-subtle)] text-[var(--success)] border border-[var(--success)]/30">
                  REVIEWED
                </span>
              )}
            </div>
            <h2 id="modal-title" className="text-[16px] font-semibold text-[var(--foreground-primary)] tracking-tight">
              {finding.title}
            </h2>
          </div>

          <button
            onClick={onClose}
            className="p-1 rounded-[var(--radius-sm)] text-[var(--foreground-tertiary)] hover:text-[var(--foreground-primary)] hover:bg-[var(--surface-hover)] transition-colors"
            aria-label="Close modal"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-5 space-y-5 flex-1 text-[13px]">
          {/* Metadata Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-3.5 rounded-[var(--radius-md)] bg-[var(--surface-secondary)] border border-[var(--border-subtle)]">
            <div>
              <div className="text-[11px] text-[var(--foreground-tertiary)] font-medium flex items-center justify-between">
                <span>File Location</span>
                <button
                  onClick={() => copyToClipboard(finding.file_path, "file")}
                  className="hover:text-[var(--primary)] flex items-center gap-1 transition-colors text-[10px] font-mono"
                >
                  {copiedType === "file" ? <Check className="w-3 h-3 text-[var(--success)]" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedType === "file" ? "Copied" : "Copy"}</span>
                </button>
              </div>
              <div className="mt-1 font-mono text-[12px] text-[var(--foreground-primary)] break-all flex items-center gap-1.5">
                <FileCode className="w-3.5 h-3.5 flex-shrink-0 text-[var(--foreground-secondary)]" />
                <span>{finding.file_path}</span>
                {lineRangeText && (
                  <span className="text-[var(--foreground-tertiary)] font-medium">:{lineRangeText}</span>
                )}
              </div>
            </div>

            <div>
              <div className="text-[11px] text-[var(--foreground-tertiary)] font-medium flex items-center justify-between">
                <span>Rule Identifier</span>
                <button
                  onClick={() => copyToClipboard(finding.rule_id, "rule")}
                  className="hover:text-[var(--primary)] flex items-center gap-1 transition-colors text-[10px] font-mono"
                >
                  {copiedType === "rule" ? <Check className="w-3 h-3 text-[var(--success)]" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedType === "rule" ? "Copied" : "Copy"}</span>
                </button>
              </div>
              <div className="mt-1 font-mono text-[12px] text-[var(--foreground-primary)] break-all flex items-center gap-1.5">
                <Hash className="w-3.5 h-3.5 flex-shrink-0 text-[var(--foreground-secondary)]" />
                <span>{finding.rule_id}</span>
              </div>
            </div>

            {finding.package_name && (
              <div>
                <div className="text-[11px] text-[var(--foreground-tertiary)] font-medium">
                  Affected Package
                </div>
                <div className="mt-1 font-mono text-[12px] text-[var(--foreground-primary)] flex items-center gap-1.5">
                  <Package className="w-3.5 h-3.5 text-[var(--foreground-secondary)] flex-shrink-0" />
                  <span>
                    {finding.package_name} {finding.installed_version ? `@ ${finding.installed_version}` : ""}
                  </span>
                  {finding.direct_dependency !== undefined && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded-[var(--radius-sm)] bg-[var(--surface)] border border-[var(--border-subtle)] text-[var(--foreground-tertiary)]">
                      {finding.direct_dependency ? "direct" : "transitive"}
                    </span>
                  )}
                </div>
              </div>
            )}

            {finding.fixed_version && (
              <div>
                <div className="text-[11px] text-[var(--foreground-tertiary)] font-medium">
                  Fixed in Version
                </div>
                <div className="mt-1 font-mono text-[12px] text-[var(--success)] font-medium flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0" />
                  <span>&gt;= {finding.fixed_version}</span>
                </div>
              </div>
            )}

            {/* Identifiers & References */}
            <div className="sm:col-span-2 flex flex-wrap gap-2 pt-2 border-t border-[var(--border-subtle)]">
              {finding.cwe_id && (
                <a
                  href={`https://cwe.mitre.org/data/definitions/${finding.cwe_id.replace("CWE-", "")}.html`}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-[var(--radius-sm)] bg-[var(--surface)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[11px] font-mono text-[var(--primary)] transition-colors"
                >
                  <span>{finding.cwe_id}</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              )}
              {finding.cve_id && (
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-[var(--radius-sm)] bg-[var(--surface)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[11px] font-mono text-[var(--primary)] transition-colors"
                >
                  <span>{finding.cve_id}</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              )}
              {finding.ghsa_id && (
                <a
                  href={`https://github.com/advisories/${finding.ghsa_id}`}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-[var(--radius-sm)] bg-[var(--surface)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[11px] font-mono text-[var(--primary)] transition-colors"
                >
                  <span>{finding.ghsa_id}</span>
                  <ExternalLink className="w-3 h-3" />
                </a>
              )}
            </div>
          </div>

          {/* Vulnerability Analysis */}
          <div>
            <div className="text-[12px] font-medium text-[var(--foreground-secondary)] mb-1.5 flex items-center gap-1.5">
              <Info className="w-3.5 h-3.5 text-[var(--primary)]" />
              <span>Vulnerability Analysis</span>
            </div>
            <div className="text-[13px] text-[var(--foreground-primary)] leading-relaxed bg-[var(--surface-secondary)] p-3.5 rounded-[var(--radius-md)] border border-[var(--border-subtle)]">
              {finding.description}
            </div>
          </div>

          {/* Technical Impact */}
          {finding.technical_impact && (
            <div>
              <div className="text-[12px] font-medium text-[var(--foreground-secondary)] mb-1.5 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-[var(--warning)]" />
                <span>Technical Impact &amp; Exploitation Context</span>
              </div>
              <div className="text-[13px] text-[var(--foreground-primary)] leading-relaxed bg-[var(--surface-secondary)] p-3.5 rounded-[var(--radius-md)] border border-[var(--border-subtle)]">
                {finding.technical_impact}
              </div>
            </div>
          )}

          {/* Dedicated Technical Code Surface: Sanitized Evidence */}
          {finding.evidence && (
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[12px] font-medium text-[var(--foreground-secondary)]">
                  Evidence (Sanitized)
                </span>
                <button
                  onClick={() => copyToClipboard(finding.evidence || "", "evidence")}
                  className="flex items-center gap-1 text-[11px] text-[var(--foreground-secondary)] hover:text-[var(--foreground-primary)] px-2 py-0.5 rounded-[var(--radius-sm)] hover:bg-[var(--surface-hover)] transition-colors"
                >
                  {copiedType === "evidence" ? <Check className="w-3 h-3 text-[var(--success)]" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedType === "evidence" ? "Copied" : "Copy"}</span>
                </button>
              </div>

              <div className="rounded-[var(--radius-md)] bg-[var(--surface-code)] border border-[var(--border-subtle)] overflow-hidden font-mono text-[12px]">
                <div className="p-3.5 overflow-x-auto max-h-48 leading-relaxed">
                  {evidenceLines.map((line, idx) => (
                    <div key={idx} className="flex items-start gap-3">
                      <span className="text-[var(--foreground-disabled)] select-none w-8 text-right pr-2 border-r border-[var(--border-subtle)] flex-shrink-0">
                        {startLineNumber + idx}
                      </span>
                      <span className="text-[var(--foreground-primary)] whitespace-pre-wrap break-all pl-1">
                        {line}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Security Fix Assistant Section */}
          <div className="space-y-3 pt-2 border-t border-[var(--border-subtle)]">
            <div className="flex items-center justify-between">
              <div className="text-[13px] font-semibold text-[var(--foreground-primary)] flex items-center gap-1.5">
                <Wrench className="w-4 h-4 text-[var(--primary)]" />
                <span>Security Fix Assistant</span>
              </div>
              <span className="text-[10px] text-[var(--foreground-tertiary)] font-mono">
                Proposed patch — review before applying
              </span>
            </div>

            {/* Remediation Step */}
            <div className="p-3.5 rounded-[var(--radius-md)] bg-[var(--surface-secondary)] border border-[var(--border-subtle)] text-[var(--foreground-primary)] text-[13px] leading-relaxed">
              <div className="text-[11px] font-medium text-[var(--foreground-tertiary)] uppercase tracking-wider mb-1">
                Remediation Guidance
              </div>
              {finding.remediation}
            </div>

            {/* Suggested Update Command (for dependencies) */}
            {finding.update_command && (
              <div className="p-3 rounded-[var(--radius-md)] bg-[var(--surface-secondary)] border border-[var(--border-subtle)] space-y-1">
                <div className="text-[11px] font-medium text-[var(--foreground-tertiary)] flex items-center justify-between">
                  <span>Suggested Package Update Command</span>
                  <button
                    onClick={() => copyToClipboard(finding.update_command || "", "pkgcmd")}
                    className="text-[10px] font-mono hover:text-[var(--primary)] flex items-center gap-1"
                  >
                    {copiedType === "pkgcmd" ? <Check className="w-3 h-3 text-[var(--success)]" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedType === "pkgcmd" ? "Copied" : "Copy Command"}</span>
                  </button>
                </div>
                <div className="font-mono text-[12px] text-[var(--primary)] bg-[var(--surface-code)] p-2.5 rounded-[var(--radius-sm)] border border-[var(--border-subtle)]">
                  {finding.update_command}
                </div>
              </div>
            )}

            {/* Dedicated Technical Code Surface: Proposed Patch Diff View */}
            {finding.suggested_patch && (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-medium text-[var(--foreground-secondary)] flex items-center gap-1.5">
                    <GitCommit className="w-3.5 h-3.5 text-[var(--foreground-tertiary)]" />
                    <span>Proposed Patch Diff</span>
                  </span>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => copyToClipboard(finding.suggested_patch || "", "patch")}
                      className="btn-secondary h-7 text-[11px] px-2"
                    >
                      {copiedType === "patch" ? <Check className="w-3 h-3 text-[var(--success)]" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedType === "patch" ? "Copied" : "Copy Patch"}</span>
                    </button>
                    <button
                      onClick={handleDownloadPatch}
                      className="btn-secondary h-7 text-[11px] px-2"
                    >
                      <Download className="w-3 h-3" />
                      <span>Download .patch</span>
                    </button>
                  </div>
                </div>

                <div className="rounded-[var(--radius-md)] bg-[var(--surface-code)] border border-[var(--border-subtle)] overflow-hidden font-mono text-[11px] p-3 max-h-48 overflow-x-auto leading-relaxed">
                  {finding.suggested_patch.split("\n").map((line, i) => {
                    const isAddition = line.startsWith("+");
                    const isDeletion = line.startsWith("-");
                    return (
                      <div
                        key={i}
                        className={
                          isAddition
                            ? "bg-[var(--success-subtle)] text-[var(--success)] -mx-3 px-3 border-l-2 border-[var(--success)]"
                            : isDeletion
                            ? "bg-[var(--danger-subtle)] text-[var(--danger)] -mx-3 px-3 border-l-2 border-[var(--danger)]"
                            : "text-[var(--foreground-secondary)] px-3"
                        }
                      >
                        {line}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Secure Code Implementation Example */}
            {finding.secure_code_example && (
              <div className="space-y-1.5">
                <div className="text-[11px] font-medium text-[var(--foreground-tertiary)] uppercase tracking-wider">
                  Secure Implementation Pattern
                </div>
                <pre className="p-3.5 rounded-[var(--radius-md)] bg-[var(--surface-code)] border border-[var(--border-subtle)] font-mono text-[11px] text-[var(--foreground-primary)] overflow-x-auto">
                  {finding.secure_code_example}
                </pre>
              </div>
            )}

            {/* Optional AI Security Explanation */}
            <div className="pt-2">
              {!aiExplanation ? (
                <button
                  onClick={handleRequestAiExplanation}
                  disabled={aiLoading}
                  className="btn-secondary h-8 text-[11.5px]"
                >
                  <Sparkles className="w-3.5 h-3.5 text-[var(--primary)]" />
                  <span>{aiLoading ? "Consulting AI Engine..." : "Explain with AI Security Assistant"}</span>
                </button>
              ) : (
                <div className="p-3.5 rounded-[var(--radius-md)] bg-[var(--primary-subtle)] border border-[var(--primary)]/25 space-y-2 text-[12px] text-[var(--foreground-primary)] animate-in fade-in">
                  <div className="flex items-center gap-1.5 font-semibold text-[var(--primary)]">
                    <Sparkles className="w-3.5 h-3.5" />
                    <span>AI Security Analysis</span>
                  </div>
                  <p className="leading-relaxed whitespace-pre-line text-[var(--foreground-primary)]">
                    {aiExplanation}
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Modal Action Footer */}
        <div className="p-4 border-t border-[var(--border)] bg-[var(--surface)] flex flex-wrap items-center justify-between gap-3 sticky bottom-0 z-20">
          <div className="flex items-center gap-2">
            <button
              onClick={handleToggleReviewed}
              className={`btn-secondary h-8 text-[12px] ${
                isReviewed ? "border-[var(--success)] text-[var(--success)]" : ""
              }`}
            >
              <CheckCircle2 className={`w-3.5 h-3.5 ${isReviewed ? "text-[var(--success)]" : ""}`} />
              <span>{isReviewed ? "Mark as Open" : "Mark as Reviewed"}</span>
            </button>

            {isSuppressed ? (
              <button
                onClick={handleRemoveSuppression}
                className="btn-secondary h-8 text-[12px] text-[var(--warning)]"
              >
                <span>Remove Suppression</span>
              </button>
            ) : (
              <button
                onClick={() => setIsSuppressDialogOpen(true)}
                className="btn-secondary h-8 text-[12px]"
              >
                <ShieldAlert className="w-3.5 h-3.5 text-[var(--foreground-tertiary)]" />
                <span>Suppress Finding</span>
              </button>
            )}

            <Link
              href={`/review-workbench?finding_id=${finding.id}`}
              className="btn-secondary h-8 text-[12px]"
              title="Triage this finding in the Review Workbench"
            >
              <ClipboardCheck className="w-3.5 h-3.5 text-indigo-500" />
              <span>Review Workbench</span>
            </Link>

            <Link
              href={`/timeline?fingerprint=${encodeURIComponent(fingerprint)}`}
              className="btn-secondary h-8 text-[12px]"
              title="Inspect vulnerability origin and lifecycle timeline"
            >
              <Milestone className="w-3.5 h-3.5 text-blue-500" />
              <span>Timeline</span>
            </Link>

            <Link
              href={`/fix-validation?finding_id=${finding.id}&rule_id=${encodeURIComponent(finding.rule_id)}`}
              className="btn-secondary h-8 text-[12px]"
            >
              <Wrench className="w-3.5 h-3.5 text-[var(--primary)]" />
              <span>Validate Fix in Lab</span>
            </Link>
          </div>

          <button
            onClick={onClose}
            className="btn-primary h-8 px-4 text-[12px]"
          >
            Done
          </button>
        </div>

        {/* Suppression Reason Dialog */}
        {isSuppressDialogOpen && (
          <div className="absolute inset-0 z-30 bg-black/60 flex items-center justify-center p-4">
            <div className="bg-[var(--surface-elevated)] border border-[var(--border-strong)] rounded-[var(--radius-lg)] p-5 max-w-md w-full space-y-4 shadow-[var(--shadow-dialog)]">
              <div>
                <h3 className="text-[14px] font-semibold text-[var(--foreground-primary)]">
                  Suppress Finding
                </h3>
                <p className="text-[12px] text-[var(--foreground-secondary)] mt-0.5">
                  Suppressed findings will be excluded from policy evaluation gates and reports.
                </p>
              </div>

              <form onSubmit={handleConfirmSuppression} className="space-y-3">
                <div>
                  <label className="block text-[11px] font-medium text-[var(--foreground-tertiary)] mb-1">
                    Suppression Justification
                  </label>
                  <textarea
                    required
                    value={suppressReason}
                    onChange={(e) => setSuppressReason(e.target.value)}
                    placeholder="e.g. Compensating control verified; test-only credential."
                    className="macos-input w-full h-20 p-2.5 text-[12px] resize-none"
                  />
                </div>

                <div>
                  <label className="block text-[11px] font-medium text-[var(--foreground-tertiary)] mb-1">
                    Expiration Date (Optional)
                  </label>
                  <input
                    type="date"
                    value={suppressExpiry}
                    onChange={(e) => setSuppressExpiry(e.target.value)}
                    className="macos-input w-full text-[12px]"
                  />
                </div>

                <div className="flex items-center justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setIsSuppressDialogOpen(false)}
                    className="btn-secondary h-8 text-[12px]"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="btn-primary h-8 px-3 text-[12px]"
                  >
                    Confirm Suppression
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </AnimatedDialog>
    );
}
