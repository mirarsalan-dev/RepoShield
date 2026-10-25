"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  FlaskConical,
  Play,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Info,
  CheckCircle2,
  XCircle,
  Clock,
  Code2,
  ArrowRight,
  RotateCcw,
  Sparkles,
  Terminal,
  Layers,
  ChevronRight,
  FileCode,
  Shield,
  Search,
  ExternalLink,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { api } from "@/lib/api";
import {
  ScanResult,
  Finding,
  LiveScanResult,
  ScanBenchmarkReport,
  FindingBenchmarkResult,
} from "@/lib/types";
import { EmptyState } from "@/components/common/EmptyState";
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import { formatDate } from "@/lib/utils";

export default function TestLabPage() {
  const [activeTab, setActiveTab] = useState<"REPO_VALIDATION" | "LIVE_SANDBOX">("REPO_VALIDATION");
  
  // Real Repository Scans State
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>("");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string>("ALL");
  
  // Real Scan Benchmark State
  const [isBenchmarking, setIsBenchmarking] = useState(false);
  const [benchmarkReport, setBenchmarkReport] = useState<ScanBenchmarkReport | null>(null);
  const [singleVerifying, setSingleVerifying] = useState(false);
  const [singleVerifyResult, setSingleVerifyResult] = useState<LiveScanResult | null>(null);

  // Live Sandbox State
  const [sandboxLanguage, setSandboxLanguage] = useState<string>("python");
  const [sandboxCode, setSandboxCode] = useState<string>(
    "import subprocess\n\ndef execute_command(target):\n    # Test real detector rules live\n    subprocess.run(f'ping -c 1 {target}', shell=True)\n"
  );
  const [isAnalyzingLive, setIsAnalyzingLive] = useState(false);
  const [liveResult, setLiveResult] = useState<LiveScanResult | null>(null);
  const [liveError, setLiveError] = useState<string | null>(null);

  // Load real scan history exclusively from browser local storage (Zero dummy data)
  useEffect(() => {
    const history = storage.getScanHistory();
    setScans(history);
    if (history.length > 0) {
      const firstScan = history[0];
      setSelectedScanId(firstScan.scan_id);
      if (firstScan.findings && firstScan.findings.length > 0) {
        setSelectedFinding(firstScan.findings[0]);
      }
    }
  }, []);

  const selectedScan = scans.find((s) => s.scan_id === selectedScanId) || (scans.length > 0 ? scans[0] : null);

  // Handle changing repository
  const handleScanChange = (scanId: string) => {
    setSelectedScanId(scanId);
    setBenchmarkReport(null);
    setSingleVerifyResult(null);
    const match = scans.find((s) => s.scan_id === scanId);
    if (match && match.findings && match.findings.length > 0) {
      setSelectedFinding(match.findings[0]);
    } else {
      setSelectedFinding(null);
    }
  };

  // Filter real findings
  const filteredFindings = selectedScan?.findings?.filter((f) => {
    if (categoryFilter === "ALL") return true;
    return f.category?.toUpperCase() === categoryFilter.toUpperCase();
  }) || [];

  // Run full benchmark on the real repository scan findings
  const handleRunScanBenchmark = async () => {
    if (!selectedScan) return;
    setIsBenchmarking(true);
    setBenchmarkReport(null);
    try {
      const rep = await api.benchmarkScanFindings(selectedScan);
      setBenchmarkReport(rep);
    } catch (err: any) {
      console.warn("Failed to benchmark scan findings:", err);
    } finally {
      setIsBenchmarking(false);
    }
  };

  // Verify single real finding with live scanner engine
  const handleVerifySingleFinding = async () => {
    if (!selectedFinding) return;
    setSingleVerifying(true);
    setSingleVerifyResult(null);
    try {
      const codeToTest = selectedFinding.evidence || selectedFinding.secure_code_example || "";
      const lang = selectedFinding.file_path?.endsWith(".py")
        ? "python"
        : selectedFinding.file_path?.endsWith(".ts") || selectedFinding.file_path?.endsWith(".js")
        ? "javascript"
        : selectedFinding.file_path?.toLowerCase().includes("dockerfile")
        ? "dockerfile"
        : selectedFinding.file_path?.endsWith(".yml") || selectedFinding.file_path?.endsWith(".yaml")
        ? "yaml"
        : "generic";

      const res = await api.runLiveSecurityTest({
        code: codeToTest,
        language: lang,
        filename: selectedFinding.file_path,
      });
      setSingleVerifyResult(res);
    } catch (err: any) {
      console.warn("Failed to verify finding:", err);
    } finally {
      setSingleVerifying(false);
    }
  };

  // Transfer real finding to live sandbox
  const handleSendToSandbox = (finding: Finding) => {
    const code = finding.evidence || finding.secure_code_example || "";
    setSandboxCode(code);
    if (finding.file_path?.endsWith(".py")) setSandboxLanguage("python");
    else if (finding.file_path?.endsWith(".ts") || finding.file_path?.endsWith(".js")) setSandboxLanguage("javascript");
    else if (finding.file_path?.toLowerCase().includes("dockerfile")) setSandboxLanguage("dockerfile");
    else if (finding.file_path?.endsWith(".yml") || finding.file_path?.endsWith(".yaml")) setSandboxLanguage("yaml");
    else setSandboxLanguage("generic");

    setActiveTab("LIVE_SANDBOX");
    setLiveResult(null);
    setLiveError(null);
  };

  // Run live analysis on user code in sandbox
  const handleRunLiveAnalysis = async () => {
    if (!sandboxCode.trim()) {
      setLiveError("Please enter source code or a configuration snippet to analyze.");
      return;
    }
    setIsAnalyzingLive(true);
    setLiveError(null);
    setLiveResult(null);
    try {
      const res = await api.runLiveSecurityTest({
        code: sandboxCode,
        language: sandboxLanguage,
      });
      setLiveResult(res);
    } catch (err: any) {
      setLiveError(err.message || "Failed to execute live security detectors.");
    } finally {
      setIsAnalyzingLive(false);
    }
  };

  return (
    <div className="space-y-4 max-w-7xl mx-auto">
      {/* Top Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pb-3 border-b border-[var(--border-color)]">
        <div className="space-y-1 min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-[22px] font-semibold tracking-tight text-[var(--text-primary)] shrink-0">
              Safe Security Test Lab
            </h1>
            <span className="text-[11px] font-medium px-2.5 py-0.5 rounded-full bg-[var(--surface-secondary)] text-[var(--text-secondary)] border border-[var(--border-subtle)] whitespace-nowrap shrink-0 flex-shrink-0 inline-flex items-center">
              Zero Dummy Data • Live Scanner Engines
            </span>
          </div>
          <p className="text-[13px] text-[var(--text-secondary)] mt-0.5">
            Validate detection rule precision, test real findings from repository scans, and analyze live code snippets against Gitleaks, Semgrep, and Config scanners.
          </p>
        </div>

        {/* Tab Controls */}
        <div className="flex items-center bg-[var(--surface-secondary)] p-0.5 rounded-[8px] border border-[var(--border-subtle)] shrink-0">
          <button
            id="tab-repo-validation"
            onClick={() => setActiveTab("REPO_VALIDATION")}
            className={`px-3 py-1.5 rounded-[6px] text-[12px] font-medium transition-colors flex items-center gap-1.5 ${
              activeTab === "REPO_VALIDATION"
                ? "bg-[var(--surface)] text-[var(--text-primary)] shadow-sm border border-[var(--border-subtle)]"
                : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5 text-[#34C759]" />
            <span>Repository Scan Validation</span>
            {scans.length > 0 && (
              <span className="ml-1 text-[10px] px-1.5 py-0.2 rounded-full bg-[var(--accent-subtle)] text-[var(--accent)] font-mono">
                {scans.length}
              </span>
            )}
          </button>

          <button
            id="tab-live-sandbox"
            onClick={() => setActiveTab("LIVE_SANDBOX")}
            className={`px-3 py-1.5 rounded-[6px] text-[12px] font-medium transition-colors flex items-center gap-1.5 ${
              activeTab === "LIVE_SANDBOX"
                ? "bg-[var(--surface)] text-[var(--text-primary)] shadow-sm border border-[var(--border-subtle)]"
                : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            }`}
          >
            <Terminal className="w-3.5 h-3.5 text-[#0A84FF]" />
            <span>Live Security Sandbox</span>
          </button>
        </div>
      </div>

      {/* TAB 1: REPOSITORY SCAN VALIDATION */}
      {activeTab === "REPO_VALIDATION" && (
        <div className="space-y-4">
          {scans.length === 0 ? (
            <div className="macos-panel p-10 text-center max-w-lg mx-auto my-8 space-y-4">
              <div className="w-12 h-12 rounded-[10px] bg-[var(--surface-secondary)] border border-[var(--border-subtle)] flex items-center justify-center mx-auto text-[#0A84FF]">
                <FlaskConical className="w-6 h-6" />
              </div>
              <div className="space-y-1.5">
                <h3 className="text-[16px] font-semibold text-[var(--text-primary)]">
                  No Scanned Repositories Found
                </h3>
                <p className="text-[13px] text-[var(--text-secondary)] max-w-md mx-auto leading-relaxed">
                  Safe Security Test Lab operates strictly on <strong>real codebase data</strong>. Scan a public GitHub repository to benchmark detection rules, verify findings, and calculate live scanner precision.
                </p>
              </div>

              <div className="pt-2 flex flex-col sm:flex-row items-center justify-center gap-2.5">
                <Link
                  id="btn-scan-repo"
                  href="/scan"
                  className="macos-button macos-button-primary h-8 px-4 text-[12px] flex items-center gap-1.5 w-full sm:w-auto justify-center"
                >
                  <Search className="w-3.5 h-3.5" />
                  <span>Scan a Repository</span>
                </Link>

                <button
                  id="btn-open-sandbox"
                  onClick={() => setActiveTab("LIVE_SANDBOX")}
                  className="macos-button h-8 px-4 text-[12px] flex items-center gap-1.5 w-full sm:w-auto justify-center border border-[var(--border-subtle)] hover:bg-[var(--bg-hover)]"
                >
                  <Terminal className="w-3.5 h-3.5 text-[#0A84FF]" />
                  <span>Open Live Scanner Sandbox</span>
                </button>
              </div>
            </div>
          ) : (
            <>
              {/* Repository Selector and Benchmark Execution Bar */}
              <div className="macos-panel p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="text-[12px] font-medium text-[var(--text-secondary)]">
                    Target Scanned Repository:
                  </div>
                  <select
                    id="select-repository"
                    value={selectedScanId}
                    onChange={(e) => handleScanChange(e.target.value)}
                    className="h-8 text-[12px] rounded-[6px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] px-2.5 font-medium text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
                  >
                    {scans.map((s) => (
                      <option key={s.scan_id} value={s.scan_id}>
                        {s.owner}/{s.repo} ({s.branch || "default"}) — {s.findings?.length || 0} real findings
                      </option>
                    ))}
                  </select>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    id="btn-run-benchmark"
                    onClick={handleRunScanBenchmark}
                    disabled={isBenchmarking || !selectedScan || (selectedScan.findings?.length || 0) === 0}
                    className="macos-button macos-button-primary h-8 text-[12px] px-3.5 flex items-center gap-1.5 disabled:opacity-50"
                  >
                    <Play className={`w-3.5 h-3.5 ${isBenchmarking ? "animate-spin" : ""}`} />
                    <span>{isBenchmarking ? "Executing Live Benchmark..." : "Run Scanner Benchmark on Findings"}</span>
                  </button>
                </div>
              </div>

              {/* KPI Cards calculated strictly from real scan findings */}
              <div className="macos-panel p-3.5 grid grid-cols-2 sm:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-[var(--border-subtle)] text-[12px]">
                <div className="p-2 space-y-0.5">
                  <div className="text-[var(--text-secondary)]">Benchmark Precision</div>
                  <div className="text-xl font-semibold text-[#34C759]">
                    {benchmarkReport ? `${benchmarkReport.precision_pct}%` : "—"}
                  </div>
                  <div className="text-[11px] text-[var(--text-muted)]">
                    {benchmarkReport ? `${benchmarkReport.verified_detections} confirmed` : "Run benchmark to evaluate"}
                  </div>
                </div>

                <div className="p-2 space-y-0.5">
                  <div className="text-[var(--text-secondary)]">Average Rule Latency</div>
                  <div className="text-xl font-semibold text-[#0A84FF]">
                    {benchmarkReport ? `${benchmarkReport.avg_latency_ms}ms` : "—"}
                  </div>
                  <div className="text-[11px] text-[var(--text-muted)]">Live sandbox execution time</div>
                </div>

                <div className="p-2 space-y-0.5">
                  <div className="text-[var(--text-secondary)]">Real Repository Findings</div>
                  <div className="text-xl font-semibold text-[var(--text-primary)]">
                    {selectedScan?.findings?.length || 0} Findings
                  </div>
                  <div className="text-[11px] text-[var(--text-muted)]">
                    {selectedScan?.risk_score?.critical_count || 0} Critical, {selectedScan?.risk_score?.high_count || 0} High
                  </div>
                </div>

                <div className="p-2 space-y-0.5">
                  <div className="text-[var(--text-secondary)]">Active Security Engines</div>
                  <div className="text-xl font-semibold text-[var(--text-primary)]">
                    3 Live Engines
                  </div>
                  <div className="text-[11px] text-[var(--text-muted)]">Gitleaks, Semgrep, Config</div>
                </div>
              </div>

              {/* Notice Banner */}
              <div className="p-3 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] flex items-start gap-2.5 text-[12px]">
                <Info className="w-4 h-4 text-[#0A84FF] shrink-0 mt-0.5" />
                <div className="text-[var(--text-secondary)]">
                  <span className="font-semibold text-[var(--text-primary)]">Ground-Truth Verification: </span>
                  Testing against actual repository findings detected in <strong>{selectedScan?.owner}/{selectedScan?.repo}</strong>.
                  Each finding evidence snippet is verified in an isolated ephemeral directory with live detector AST rules.
                </div>
              </div>

              {/* Two Column Layout: Real Findings List & Inspector */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                {/* Left Panel: Real Findings List */}
                <div className="macos-panel p-3 space-y-2 lg:col-span-1">
                  <div className="flex items-center justify-between pb-1 border-b border-[var(--border-subtle)]">
                    <span className="text-[11px] font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
                      Real Findings ({filteredFindings.length})
                    </span>

                    {/* Category Filter */}
                    <select
                      id="select-category-filter"
                      value={categoryFilter}
                      onChange={(e) => setCategoryFilter(e.target.value)}
                      className="text-[10px] bg-[var(--surface-secondary)] border border-[var(--border-subtle)] rounded px-1.5 py-0.5 text-[var(--text-secondary)] focus:outline-none"
                    >
                      <option value="ALL">All Categories</option>
                      <option value="SECRETS">Secrets</option>
                      <option value="SAST">SAST / Code</option>
                      <option value="INFRASTRUCTURE">Infrastructure</option>
                      <option value="DEPENDENCIES">Dependencies</option>
                    </select>
                  </div>

                  <div className="space-y-1.5 max-h-[520px] overflow-y-auto pr-1">
                    {filteredFindings.length === 0 ? (
                      <div className="p-6 text-center text-[12px] text-[var(--text-secondary)]">
                        No findings matching filter in this repository scan.
                      </div>
                    ) : (
                      filteredFindings.map((f) => {
                        const isSelected = selectedFinding?.id === f.id;
                        const benchItem = benchmarkReport?.results.find((r) => r.finding_id === f.id);

                        return (
                          <div
                            key={f.id}
                            onClick={() => {
                              setSelectedFinding(f);
                              setSingleVerifyResult(null);
                            }}
                            className={`p-2.5 rounded-[6px] cursor-pointer transition-colors text-[12px] border ${
                              isSelected
                                ? "bg-[var(--accent-subtle)] border-[var(--accent)] text-[var(--accent)]"
                                : "bg-[var(--surface)] border-[var(--border-subtle)] hover:bg-[var(--bg-hover)] text-[var(--text-primary)]"
                            }`}
                          >
                            <div className="flex items-center justify-between gap-2">
                              <span className="font-semibold truncate">{f.title}</span>
                              <SeverityBadge severity={f.severity} />
                            </div>

                            <div className="flex items-center justify-between text-[11px] text-[var(--text-secondary)] mt-1 font-mono">
                              <span className="truncate max-w-[150px]">{f.file_path || "source"}</span>
                              {f.line_start && <span>L{f.line_start}</span>}
                            </div>

                            {benchItem && (
                              <div className="mt-1 pt-1 border-t border-[var(--border-subtle)] flex items-center justify-between text-[10px]">
                                <span className="text-[#34C759] font-medium flex items-center gap-1">
                                  <CheckCircle2 className="w-3 h-3" />
                                  <span>Live Verified</span>
                                </span>
                                <span className="font-mono text-[var(--text-muted)]">
                                  {benchItem.execution_time_ms}ms
                                </span>
                              </div>
                            )}
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>

                {/* Right Panel: Finding Inspector and Live Engine Verification */}
                <div className="macos-panel p-4 space-y-4 lg:col-span-2">
                  {selectedFinding ? (
                    <div className="space-y-4">
                      {/* Finding Details Header */}
                      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2 pb-3 border-b border-[var(--border-subtle)]">
                        <div>
                          <div className="flex items-center gap-2">
                            <h2 className="text-[15px] font-semibold text-[var(--text-primary)]">
                              {selectedFinding.title}
                            </h2>
                            <SeverityBadge severity={selectedFinding.severity} />
                          </div>
                          <p className="text-[12px] text-[var(--text-secondary)] mt-0.5">
                            {selectedFinding.description}
                          </p>
                        </div>

                        <div className="flex sm:flex-col items-center sm:items-end justify-between gap-1 text-[11px] font-mono shrink-0">
                          <span className="text-[var(--text-muted)]">Rule: {selectedFinding.rule_id}</span>
                          <span className="text-[var(--accent)]">{selectedFinding.detector_name}</span>
                        </div>
                      </div>

                      {/* File Path & CWE Badge */}
                      <div className="flex flex-wrap items-center gap-2 text-[11px]">
                        <span className="px-2 py-0.5 rounded bg-[var(--surface-secondary)] border border-[var(--border-subtle)] font-mono text-[var(--text-secondary)]">
                          File: {selectedFinding.file_path} {selectedFinding.line_start ? `(Line ${selectedFinding.line_start})` : ""}
                        </span>
                        {selectedFinding.cwe_id && (
                          <span className="px-2 py-0.5 rounded bg-[var(--surface-secondary)] border border-[var(--border-subtle)] font-mono text-[var(--text-secondary)]">
                            {selectedFinding.cwe_id}
                          </span>
                        )}
                        <span className="px-2 py-0.5 rounded bg-[var(--surface-secondary)] border border-[var(--border-subtle)] font-mono text-[var(--text-secondary)]">
                          Category: {selectedFinding.category}
                        </span>
                      </div>

                      {/* Code Evidence Display */}
                      <div className="space-y-1.5">
                        <div className="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-secondary)] flex items-center justify-between">
                          <span className="flex items-center gap-1.5">
                            <Code2 className="w-3.5 h-3.5 text-[#FF9500]" />
                            <span>Real Code Evidence from Repository</span>
                          </span>

                          <button
                            id="btn-test-in-sandbox"
                            onClick={() => handleSendToSandbox(selectedFinding)}
                            className="text-[11px] text-[#0A84FF] hover:underline flex items-center gap-1 normal-case font-medium"
                          >
                            <span>Open in Live Sandbox</span>
                            <ArrowRight className="w-3 h-3" />
                          </button>
                        </div>

                        <pre className="p-3 rounded-[6px] bg-[var(--bg-secondary)] text-[var(--text-primary)] font-mono text-[11px] overflow-x-auto border border-[var(--border-subtle)] min-h-[100px] leading-relaxed">
                          {selectedFinding.evidence || selectedFinding.secure_code_example || "// No raw snippet recorded for this finding."}
                        </pre>
                      </div>

                      {/* Live Rule Verification Section */}
                      <div className="p-3.5 rounded-[8px] bg-[var(--surface-secondary)] border border-[var(--border-subtle)] space-y-3">
                        <div className="flex items-center justify-between">
                          <div className="space-y-0.5">
                            <div className="text-[12px] font-semibold text-[var(--text-primary)]">
                              Real-Time Detector Rule Verification
                            </div>
                            <div className="text-[11px] text-[var(--text-secondary)]">
                              Executes the detector engine against this evidence snippet in a temporary RAM sandbox.
                            </div>
                          </div>

                          <button
                            id="btn-verify-single"
                            onClick={handleVerifySingleFinding}
                            disabled={singleVerifying || (!selectedFinding.evidence && !selectedFinding.secure_code_example)}
                            className="macos-button macos-button-primary h-7 text-[11px] px-3 flex items-center gap-1.5 disabled:opacity-50"
                          >
                            <Play className={`w-3 h-3 ${singleVerifying ? "animate-spin" : ""}`} />
                            <span>{singleVerifying ? "Verifying..." : "Verify Finding Live"}</span>
                          </button>
                        </div>

                        {singleVerifyResult && (
                          <div className="p-2.5 rounded-[6px] bg-[var(--surface)] border border-[var(--border-subtle)] text-[12px] space-y-1.5">
                            <div className="flex items-center justify-between">
                              <span className="font-semibold flex items-center gap-1.5">
                                {singleVerifyResult.safe ? (
                                  <>
                                    <CheckCircle2 className="w-4 h-4 text-[#34C759]" />
                                    <span className="text-[#34C759]">Detector Passed Clean</span>
                                  </>
                                ) : (
                                  <>
                                    <ShieldAlert className="w-4 h-4 text-[#FF453A]" />
                                    <span className="text-[#FF453A]">
                                      Live Detector Reproduced ({singleVerifyResult.total_findings} finding detected)
                                    </span>
                                  </>
                                )}
                              </span>

                              <span className="font-mono text-[11px] text-[var(--text-muted)]">
                                Latency: {singleVerifyResult.execution_time_ms}ms
                              </span>
                            </div>

                            <div className="text-[11px] text-[var(--text-secondary)]">
                              Engines evaluated: {singleVerifyResult.scanners_run.join(", ")} ({singleVerifyResult.rules_evaluated} rules)
                            </div>
                          </div>
                        )}
                      </div>

                      {/* Remediation & Secure Example */}
                      {selectedFinding.remediation && (
                        <div className="space-y-1.5 text-[12px]">
                          <div className="text-[11px] font-semibold uppercase tracking-wider text-[#34C759] flex items-center gap-1">
                            <ShieldCheck className="w-3.5 h-3.5" />
                            <span>Remediation Guidance</span>
                          </div>
                          <p className="text-[var(--text-secondary)] leading-relaxed">
                            {selectedFinding.remediation}
                          </p>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div className="p-12 text-center text-[12px] text-[var(--text-secondary)]">
                      Select a finding from the left panel to inspect code evidence and execute live rule validation.
                    </div>
                  )}
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {/* TAB 2: LIVE SECURITY TESTING SANDBOX */}
      {activeTab === "LIVE_SANDBOX" && (
        <div className="space-y-4">
          <div className="macos-panel p-4 space-y-4">
            {/* Sandbox Toolbar */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[var(--border-subtle)]">
              <div className="space-y-0.5">
                <h2 className="text-[15px] font-semibold text-[var(--text-primary)]">
                  Live Security Detection Sandbox
                </h2>
                <p className="text-[12px] text-[var(--text-secondary)]">
                  Write or paste real source code, secrets, Dockerfiles, or CI workflows to analyze with RepoShield's live scanning engines.
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                {/* Language Selector */}
                <select
                  id="select-sandbox-language"
                  value={sandboxLanguage}
                  onChange={(e) => setSandboxLanguage(e.target.value)}
                  className="h-8 text-[12px] rounded-[6px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] px-2.5 font-medium text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
                >
                  <option value="python">Python (.py)</option>
                  <option value="javascript">JavaScript / TypeScript (.ts, .js)</option>
                  <option value="dockerfile">Dockerfile</option>
                  <option value="yaml">GitHub Actions (.yml)</option>
                  <option value="generic">Secrets / Credentials (.env)</option>
                </select>

                <button
                  id="btn-run-live-analysis"
                  onClick={handleRunLiveAnalysis}
                  disabled={isAnalyzingLive}
                  className="macos-button macos-button-primary h-8 px-4 text-[12px] flex items-center gap-1.5"
                >
                  <Play className={`w-3.5 h-3.5 ${isAnalyzingLive ? "animate-spin" : ""}`} />
                  <span>{isAnalyzingLive ? "Executing Scanners..." : "Run Live Security Analysis"}</span>
                </button>

                <button
                  id="btn-clear-sandbox"
                  onClick={() => {
                    setSandboxCode("");
                    setLiveResult(null);
                    setLiveError(null);
                  }}
                  className="macos-button h-8 px-3 text-[12px] border border-[var(--border-subtle)] hover:bg-[var(--bg-hover)] text-[var(--text-secondary)]"
                >
                  Clear
                </button>
              </div>
            </div>

            {/* Code Editor Container */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-[11px] text-[var(--text-secondary)] px-1">
                <span>Source Code / Configuration Input</span>
                <span>{sandboxCode.split("\n").length} lines • {sandboxCode.length} characters</span>
              </div>

              <textarea
                id="textarea-sandbox-code"
                rows={10}
                value={sandboxCode}
                onChange={(e) => setSandboxCode(e.target.value)}
                placeholder="// Paste or write source code to test against live Gitleaks, Semgrep, and Config detectors..."
                className="w-full p-3.5 rounded-[8px] bg-[var(--bg-secondary)] text-[var(--text-primary)] font-mono text-[12px] leading-relaxed border border-[var(--border-subtle)] focus:outline-none focus:border-[var(--accent)] resize-y min-h-[160px]"
              />
            </div>

            {liveError && (
              <div className="p-3 rounded-[6px] bg-[#FF453A]/10 border border-[#FF453A]/30 text-[#FF453A] text-[12px] flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{liveError}</span>
              </div>
            )}

            {/* Live Results Panel */}
            {liveResult && (
              <div className="space-y-4 pt-2 border-t border-[var(--border-subtle)]">
                {/* Result Summary Ribbon */}
                <div className="p-3.5 rounded-[8px] bg-[var(--surface-secondary)] border border-[var(--border-subtle)] flex flex-wrap items-center justify-between gap-3 text-[12px]">
                  <div className="flex items-center gap-2">
                    {liveResult.safe ? (
                      <span className="px-2.5 py-1 rounded-[6px] bg-[#34C759]/15 text-[#34C759] border border-[#34C759]/30 font-semibold flex items-center gap-1.5">
                        <CheckCircle2 className="w-4 h-4" />
                        <span>Clean / Zero Vulnerabilities Detected</span>
                      </span>
                    ) : (
                      <span className="px-2.5 py-1 rounded-[6px] bg-[#FF453A]/15 text-[#FF453A] border border-[#FF453A]/30 font-semibold flex items-center gap-1.5">
                        <ShieldAlert className="w-4 h-4" />
                        <span>{liveResult.total_findings} Weaknesses Detected</span>
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-4 text-[11px] font-mono text-[var(--text-muted)]">
                    <span>Latency: <strong>{liveResult.execution_time_ms}ms</strong></span>
                    <span>Rules Evaluated: <strong>{liveResult.rules_evaluated}</strong></span>
                    <span>Engines: <strong>{liveResult.scanners_run.join(", ")}</strong></span>
                  </div>
                </div>

                {/* Findings Cards */}
                {liveResult.findings.length > 0 ? (
                  <div className="space-y-3">
                    <div className="text-[12px] font-semibold text-[var(--text-primary)]">
                      Detected Security Issues ({liveResult.findings.length})
                    </div>

                    {liveResult.findings.map((f, i) => (
                      <div
                        key={i}
                        className="p-3.5 rounded-[8px] bg-[var(--surface)] border border-[var(--border-subtle)] space-y-2.5 text-[12px]"
                      >
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <span className="font-semibold text-[var(--text-primary)]">{f.title}</span>
                            <SeverityBadge severity={f.severity} />
                          </div>

                          <div className="flex items-center gap-2 font-mono text-[11px] text-[var(--text-muted)]">
                            <span>Rule: {f.rule_id}</span>
                            {f.line_start && <span>Line: {f.line_start}</span>}
                          </div>
                        </div>

                        <p className="text-[var(--text-secondary)]">{f.description}</p>

                        {f.evidence && (
                          <div className="space-y-1">
                            <div className="text-[10px] uppercase font-semibold text-[var(--text-muted)] tracking-wider">
                              Matched Code Pattern
                            </div>
                            <pre className="p-2.5 rounded bg-[var(--bg-secondary)] font-mono text-[11px] text-[var(--text-primary)] overflow-x-auto border border-[var(--border-subtle)]">
                              {f.evidence}
                            </pre>
                          </div>
                        )}

                        {f.remediation && (
                          <div className="text-[11px] text-[var(--text-secondary)]">
                            <span className="font-semibold text-[#34C759]">Remediation: </span>
                            {f.remediation}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-6 text-center space-y-2 border border-dashed border-[#34C759]/30 rounded-[8px] bg-[#34C759]/5">
                    <ShieldCheck className="w-8 h-8 text-[#34C759] mx-auto" />
                    <div className="text-[14px] font-semibold text-[var(--text-primary)]">
                      Code Passed All Active Security Rules
                    </div>
                    <p className="text-[12px] text-[var(--text-secondary)] max-w-md mx-auto">
                      No credentials, AST injection vulnerabilities, or dangerous container instructions were detected by the live scanning engines.
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
