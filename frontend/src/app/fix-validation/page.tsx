"use client";

import React, { useState, useEffect, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import {
  Wrench,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  HelpCircle,
  Play,
  RotateCcw,
  Sparkles,
  FileCode,
  Shield,
  Layers,
  ArrowRight,
  Download,
  Copy,
  Check,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { api } from "@/lib/api";
import { Finding, FixValidationResult, ScanResult } from "@/lib/types";
import { MacTrafficLights } from "@/components/common/Icons";
import { SeverityBadge } from "@/components/findings/SeverityBadge";

function FixValidationLabContent() {
  const searchParams = useSearchParams();
  const initialFindingId = searchParams?.get("findingId");

  const [scans, setScans] = useState<ScanResult[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>("");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const [originalCode, setOriginalCode] = useState<string>("");
  const [remediatedCode, setRemediatedCode] = useState<string>("");
  const [isValidating, setIsValidating] = useState<boolean>(false);
  const [validationResult, setValidationResult] = useState<FixValidationResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  useEffect(() => {
    const history = storage.getScanHistory();
    setScans(history);
    if (history.length > 0) {
      const activeScan = history[0];
      setSelectedScanId(activeScan.scan_id);
      setFindings(activeScan.findings || []);

      if (initialFindingId) {
        const match = activeScan.findings.find((f) => f.id === initialFindingId);
        if (match) {
          selectFinding(match);
        } else if (activeScan.findings.length > 0) {
          selectFinding(activeScan.findings[0]);
        }
      } else if (activeScan.findings.length > 0) {
        selectFinding(activeScan.findings[0]);
      }
    }
  }, [initialFindingId]);

  const handleScanChange = (scanId: string) => {
    setSelectedScanId(scanId);
    const scan = scans.find((s) => s.scan_id === scanId);
    if (scan) {
      setFindings(scan.findings || []);
      if (scan.findings.length > 0) {
        selectFinding(scan.findings[0]);
      } else {
        setSelectedFinding(null);
        setOriginalCode("");
        setRemediatedCode("");
        setValidationResult(null);
      }
    }
  };

  const selectFinding = (finding: Finding) => {
    setSelectedFinding(finding);
    setValidationResult(null);
    setErrorMessage(null);

    // Initial code setup
    const snippet = finding.evidence || `// Vulnerable file: ${finding.file_path}\n// Rule: ${finding.rule_id}\n\n`;
    setOriginalCode(snippet);

    if (finding.suggested_patch) {
      // If patch available, extract or supply suggestion
      setRemediatedCode(snippet.replace(/AKIA[0-9A-Z]{16}/g, "process.env.AWS_KEY").replace(/sk-[a-zA-Z0-9]{24,}/g, "process.env.OPENAI_API_KEY"));
    } else {
      setRemediatedCode(snippet);
    }
  };

  const handleApplySuggestedPatch = () => {
    if (!selectedFinding) return;
    if (selectedFinding.secure_code_example) {
      setRemediatedCode(selectedFinding.secure_code_example);
    } else if (selectedFinding.suggested_patch) {
      setRemediatedCode(selectedFinding.suggested_patch);
    } else {
      setRemediatedCode(`// Secure Pattern Applied for ${selectedFinding.rule_id}\nconst config = process.env.SERVICE_KEY;\n`);
    }
  };

  const handleRunValidation = async () => {
    if (!selectedFinding) return;
    setIsValidating(true);
    setErrorMessage(null);
    setValidationResult(null);

    try {
      const res = await api.validateFix({
        finding: selectedFinding,
        original_code: originalCode,
        remediated_code: remediatedCode,
        file_path: selectedFinding.file_path,
      });
      setValidationResult(res);
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to execute validation in sandbox.");
    } finally {
      setIsValidating(false);
    }
  };

  const handleCopyReport = () => {
    if (!validationResult) return;
    const text = `RepoShield Fix Validation Report
Status: ${validationResult.status}
Finding: ${selectedFinding?.title}
Rule: ${validationResult.rule_id}
Scanner: ${validationResult.detector_name}
Summary: ${validationResult.summary}
Validated At: ${validationResult.timestamp}`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Top Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-[var(--border-subtle)]">
        <div className="space-y-1 min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="p-1.5 rounded-[6px] bg-[var(--accent)]/10 text-[var(--accent)] shrink-0 flex-shrink-0">
              <Wrench className="w-5 h-5" />
            </span>
            <h1 className="text-[20px] font-semibold text-[var(--text-primary)] tracking-tight">
              Fix Validation Lab
            </h1>
            <span className="text-[11px] font-mono px-2.5 py-0.5 rounded-full bg-[var(--accent)]/15 text-[var(--accent)] border border-[var(--accent)]/30 whitespace-nowrap shrink-0 flex-shrink-0 inline-flex items-center">
              Ephemeral Sandbox
            </span>
          </div>
          <p className="text-[13px] text-[var(--text-secondary)] mt-1">
            Test and verify whether proposed remediation patches eliminate the underlying security finding without executing untrusted code or pushing commits.
          </p>
        </div>

        {/* Scan Selector */}
        {scans.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-[12px] text-[var(--text-secondary)]">Target Scan:</span>
            <select
              value={selectedScanId}
              onChange={(e) => handleScanChange(e.target.value)}
              className="macos-input text-[12px] py-1 px-2.5 max-w-[220px]"
            >
              {scans.map((s) => (
                <option key={s.scan_id} value={s.scan_id}>
                  {s.owner}/{s.repo} ({s.findings.length} findings)
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {findings.length === 0 ? (
        <div className="macos-panel p-12 text-center max-w-lg mx-auto space-y-3">
          <Shield className="w-10 h-10 text-[var(--text-muted)] mx-auto" />
          <h3 className="text-[15px] font-semibold text-[var(--text-primary)]">
            No Findings Available for Validation
          </h3>
          <p className="text-[13px] text-[var(--text-secondary)]">
            Run a security scan first or select a historical scan with open security vulnerabilities to validate patches.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Finding Selector */}
          <div className="lg:col-span-4 space-y-3">
            <div className="flex items-center justify-between px-1">
              <span className="text-[12px] font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
                Select Finding ({findings.length})
              </span>
            </div>

            <div className="macos-panel divide-y divide-[var(--border-subtle)] max-h-[640px] overflow-y-auto">
              {findings.map((f) => {
                const isSelected = selectedFinding?.id === f.id;
                return (
                  <button
                    key={f.id}
                    onClick={() => selectFinding(f)}
                    className={`w-full text-left p-3 transition-colors ${
                      isSelected
                        ? "bg-[var(--accent)]/10 border-l-2 border-[var(--accent)]"
                        : "hover:bg-[var(--bg-hover)]"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <SeverityBadge severity={f.severity} />
                      <span className="text-[11px] font-mono text-[var(--text-muted)] truncate">
                        {f.detector_name}
                      </span>
                    </div>
                    <div className="text-[13px] font-medium text-[var(--text-primary)] mt-1.5 truncate">
                      {f.title}
                    </div>
                    <div className="text-[11px] font-mono text-[var(--text-secondary)] mt-0.5 truncate">
                      {f.file_path}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Right Column: Validation Workspace */}
          <div className="lg:col-span-8 space-y-5">
            {selectedFinding && (
              <>
                {/* Active Finding Banner */}
                <div className="macos-panel p-4 space-y-3">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={selectedFinding.severity} />
                        <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[var(--bg-secondary)] text-[var(--text-secondary)]">
                          {selectedFinding.category}
                        </span>
                        <span className="text-[11px] font-mono text-[var(--text-muted)]">
                          {selectedFinding.rule_id}
                        </span>
                      </div>
                      <h2 className="text-[16px] font-semibold text-[var(--text-primary)] mt-1.5">
                        {selectedFinding.title}
                      </h2>
                    </div>
                    <button
                      onClick={handleApplySuggestedPatch}
                      className="macos-button text-[12px] flex items-center gap-1.5 text-[var(--accent)] hover:bg-[var(--accent)]/10"
                    >
                      <Sparkles className="w-3.5 h-3.5" />
                      <span>Use Recommendation</span>
                    </button>
                  </div>
                  <p className="text-[12px] text-[var(--text-secondary)] leading-relaxed">
                    {selectedFinding.description}
                  </p>
                </div>

                {/* Code Editors Comparison */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Original Code */}
                  <div className="macos-panel flex flex-col h-[280px]">
                    <div className="h-9 px-3 border-b border-[var(--border-subtle)] bg-[var(--bg-secondary)] flex items-center justify-between flex-shrink-0">
                      <span className="text-[11px] font-semibold text-[var(--text-secondary)] uppercase">
                        Original Code (Detected Evidence)
                      </span>
                      <MacTrafficLights />
                    </div>
                    <textarea
                      value={originalCode}
                      onChange={(e) => setOriginalCode(e.target.value)}
                      className="w-full flex-1 p-3 font-mono text-[12px] bg-[var(--bg-primary)] text-[var(--text-primary)] resize-none border-none focus:outline-none"
                      placeholder="Paste or inspect offending code snippet..."
                    />
                  </div>

                  {/* Proposed Remediated Code */}
                  <div className="macos-panel flex flex-col h-[280px] border-[var(--accent)]/30">
                    <div className="h-9 px-3 border-b border-[var(--border-subtle)] bg-[var(--bg-secondary)] flex items-center justify-between flex-shrink-0">
                      <span className="text-[11px] font-semibold text-[var(--accent)] uppercase flex items-center gap-1.5">
                        <FileCode className="w-3.5 h-3.5" />
                        <span>Proposed Remediation Patch</span>
                      </span>
                      <span className="text-[10px] text-[var(--text-muted)]">Editable</span>
                    </div>
                    <textarea
                      value={remediatedCode}
                      onChange={(e) => setRemediatedCode(e.target.value)}
                      className="w-full flex-1 p-3 font-mono text-[12px] bg-[var(--bg-primary)] text-[var(--text-primary)] resize-none border-none focus:outline-none"
                      placeholder="Write or paste your patched code here..."
                    />
                  </div>
                </div>

                {/* Action Bar */}
                <div className="flex items-center justify-between">
                  <button
                    onClick={() => {
                      setRemediatedCode(originalCode);
                      setValidationResult(null);
                    }}
                    className="macos-button text-[12px] flex items-center gap-1.5 text-[var(--text-secondary)]"
                  >
                    <RotateCcw className="w-3.5 h-3.5" />
                    <span>Reset Editor</span>
                  </button>

                  <button
                    onClick={handleRunValidation}
                    disabled={isValidating || !remediatedCode.trim()}
                    className="macos-button macos-button-primary text-[13px] px-5 py-2 flex items-center gap-2"
                  >
                    {isValidating ? (
                      <>
                        <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                        <span>Running Sandbox Scanner...</span>
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4 fill-current" />
                        <span>Validate Fix with Live Scanner</span>
                      </>
                    )}
                  </button>
                </div>

                {/* Error Banner */}
                {errorMessage && (
                  <div className="macos-panel p-4 border-[var(--system-red)]/40 bg-[var(--system-red)]/10 text-[var(--system-red)] text-[13px] flex items-center gap-2">
                    <XCircle className="w-4 h-4 flex-shrink-0" />
                    <span>{errorMessage}</span>
                  </div>
                )}

                {/* Validation Results Panel */}
                {validationResult && (
                  <div
                    className={`macos-panel p-5 space-y-4 border ${
                      validationResult.status === "Resolved by verification" || validationResult.status === "Verified Resolved"
                        ? "border-[var(--system-green)]/40 bg-[var(--system-green)]/5"
                        : validationResult.status === "Still detected" || validationResult.status === "Still Detected"
                        ? "border-[var(--system-red)]/40 bg-[var(--system-red)]/5"
                        : validationResult.status === "New finding introduced" || validationResult.status === "Regression Detected"
                        ? "border-[var(--system-orange)]/40 bg-[var(--system-orange)]/5"
                        : "border-[var(--border-subtle)] bg-[var(--bg-secondary)]/10"
                    }`}
                  >
                    <div className="flex items-center justify-between pb-3 border-b border-[var(--border-subtle)]">
                      <div className="flex items-center gap-2.5">
                        {(validationResult.status === "Resolved by verification" || validationResult.status === "Verified Resolved") && (
                          <CheckCircle2 className="w-5 h-5 text-[var(--system-green)]" />
                        )}
                        {(validationResult.status === "Still detected" || validationResult.status === "Still Detected") && (
                          <XCircle className="w-5 h-5 text-[var(--system-red)]" />
                        )}
                        {(validationResult.status === "New finding introduced" || validationResult.status === "Regression Detected") && (
                          <AlertTriangle className="w-5 h-5 text-[var(--system-orange)]" />
                        )}
                        {validationResult.status !== "Resolved by verification" &&
                          validationResult.status !== "Verified Resolved" &&
                          validationResult.status !== "Still detected" &&
                          validationResult.status !== "Still Detected" &&
                          validationResult.status !== "New finding introduced" &&
                          validationResult.status !== "Regression Detected" && (
                          <HelpCircle className="w-5 h-5 text-[var(--text-muted)]" />
                        )}

                        <span className="text-[16px] font-semibold text-[var(--text-primary)]">
                          {validationResult.status}
                        </span>
                        <span className="text-[11px] text-[var(--text-secondary)] font-mono">
                          (Verified in {validationResult.duration_seconds}s)
                        </span>
                      </div>

                      <button
                        onClick={handleCopyReport}
                        className="macos-button text-[11px] flex items-center gap-1"
                      >
                        {copied ? <Check className="w-3 h-3 text-[var(--system-green)]" /> : <Copy className="w-3 h-3" />}
                        <span>{copied ? "Copied" : "Copy Validation Report"}</span>
                      </button>
                    </div>

                    <p className="text-[13px] text-[var(--text-primary)] leading-relaxed">
                      {validationResult.summary}
                    </p>

                    {/* Unified Diff */}
                    {validationResult.diff_unified && (
                      <div className="space-y-1.5">
                        <div className="text-[11px] font-semibold text-[var(--text-secondary)] uppercase">
                          Unified Code Diff
                        </div>
                        <pre className="p-3 rounded-[6px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] font-mono text-[11px] text-[var(--text-primary)] overflow-x-auto whitespace-pre">
                          {validationResult.diff_unified}
                        </pre>
                      </div>
                    )}

                    {/* Scanner Limitations Note */}
                    <div className="text-[11px] text-[var(--text-muted)] pt-2 border-t border-[var(--border-subtle)]">
                      <strong>Methodology &amp; Limitation:</strong> {validationResult.scanner_limitations}
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function FixValidationLabPage() {
  return (
    <Suspense fallback={<div className="p-8 text-center text-[var(--text-muted)]">Loading Fix Validation Lab...</div>}>
      <FixValidationLabContent />
    </Suspense>
  );
}
