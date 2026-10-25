"use client";

import React, { useState, useEffect, useMemo } from "react";
import Link from "next/link";
import {
  Code2,
  Search,
  RotateCcw,
  Copy,
  Check,
  GitFork,
  ArrowRight,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  Layers,
  ChevronRight,
  ChevronDown,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { api } from "@/lib/api";
import { ScanResult, Finding, DataFlowReport, DataFlowPath } from "@/lib/types";
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import { FindingDetailModal } from "@/components/findings/FindingDetailModal";
import { EmptyState } from "@/components/common/EmptyState";
import { formatTimeAgo } from "@/lib/utils";

export default function CodeAnalysisPage() {
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [activeTab, setActiveTab] = useState<"findings" | "dataflow">("findings");

  // Filters for findings
  const [search, setSearch] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("ALL");
  const [selectedLanguage, setSelectedLanguage] = useState<string>("ALL");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [copiedFile, setCopiedFile] = useState<string | null>(null);

  // Dataflow state
  const [dataflowReport, setDataflowReport] = useState<DataFlowReport | null>(null);
  const [loadingDataflow, setLoadingDataflow] = useState(false);
  const [expandedPaths, setExpandedPaths] = useState<Record<string, boolean>>({});

  useEffect(() => {
    const saved = storage.getScanHistory();
    setHistory(saved);
    if (saved.length > 0) {
      setSelectedScan(saved[0]);
    }
  }, []);

  // Fetch data flow when scan changes or tab changes
  useEffect(() => {
    if (!selectedScan) return;

    let mounted = true;
    async function loadDataflow() {
      if (!selectedScan) return;
      setLoadingDataflow(true);
      try {
        // Try to fetch from scan_id or fallback to scan object
        let report: DataFlowReport;
        try {
          report = await api.getScanDataflow(selectedScan.scan_id);
        } catch {
          report = await api.generateCustomDataflow(selectedScan);
        }
        if (mounted) {
          setDataflowReport(report);
        }
      } catch (err) {
        console.warn("Failed to load source-to-sink data flow report:", err);
      } finally {
        if (mounted) setLoadingDataflow(false);
      }
    }

    loadDataflow();
    return () => {
      mounted = false;
    };
  }, [selectedScan]);

  const sastFindings = useMemo(() => {
    if (!selectedScan) return [];
    return selectedScan.findings.filter((f) => f.category === "SAST");
  }, [selectedScan]);

  const criticalHighCount = useMemo(() => {
    return sastFindings.filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH").length;
  }, [sastFindings]);

  const getLanguage = (filePath: string) => {
    const ext = filePath.split(".").pop()?.toLowerCase();
    switch (ext) {
      case "py": return "Python";
      case "js":
      case "jsx":
      case "mjs":
      case "cjs": return "JavaScript";
      case "ts":
      case "tsx": return "TypeScript";
      case "go": return "Go";
      case "java": return "Java";
      case "rb": return "Ruby";
      case "php": return "PHP";
      case "rs": return "Rust";
      case "c":
      case "cpp":
      case "h": return "C/C++";
      case "sh":
      case "bash": return "Shell";
      case "yml":
      case "yaml": return "YAML";
      default: return "Source";
    }
  };

  const languages = useMemo(() => {
    const set = new Set<string>();
    sastFindings.forEach((f) => set.add(getLanguage(f.file_path)));
    return Array.from(set);
  }, [sastFindings]);

  const filteredFindings = useMemo(() => {
    return sastFindings.filter((f) => {
      if (selectedSeverity !== "ALL" && f.severity !== selectedSeverity) return false;
      if (selectedLanguage !== "ALL" && getLanguage(f.file_path) !== selectedLanguage) return false;
      if (search.trim()) {
        const q = search.toLowerCase();
        const matchesTitle = f.title.toLowerCase().includes(q);
        const matchesRule = f.rule_id.toLowerCase().includes(q);
        const matchesFile = f.file_path.toLowerCase().includes(q);
        const matchesDesc = f.description.toLowerCase().includes(q);
        if (!matchesTitle && !matchesRule && !matchesFile && !matchesDesc) return false;
      }
      return true;
    });
  }, [sastFindings, selectedSeverity, selectedLanguage, search]);

  const copyPath = (path: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(path);
    setCopiedFile(path);
    setTimeout(() => setCopiedFile(null), 2000);
  };

  const togglePathExpand = (id: string) => {
    setExpandedPaths((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  if (!selectedScan && history.length === 0) {
    return (
      <EmptyState
        icon={Code2}
        title="No Code Analysis Audits"
        description="Scan any GitHub repository with Semgrep to perform abstract syntax tree static security analysis and data flow tracing."
        actionText="Scan a Repository"
        actionHref="/scan"
      />
    );
  }

  return (
    <div className="space-y-4">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[var(--border-color)]">
        <div>
          <h1 className="text-[22px] font-semibold tracking-tight text-[var(--text-primary)]">
            Code Analysis &amp; Data Flow
          </h1>
          <p className="text-[13px] text-[var(--text-secondary)] mt-0.5">
            Static application security testing (SAST) rule matches and source-to-sink taint propagation traces.
          </p>
        </div>

        <div className="flex items-center gap-2">
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

          {/* Tab Selector */}
          <div className="flex items-center bg-[var(--bg-secondary)] p-0.5 rounded-[6px] border border-[var(--border-color)]">
            <button
              onClick={() => setActiveTab("findings")}
              className={`px-3 py-1 rounded-[5px] text-[12px] font-medium transition-colors ${
                activeTab === "findings"
                  ? "bg-[var(--surface)] text-[var(--text-primary)] shadow-sm"
                  : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              }`}
            >
              Rule Matches ({sastFindings.length})
            </button>
            <button
              onClick={() => setActiveTab("dataflow")}
              className={`px-3 py-1 rounded-[5px] text-[12px] font-medium transition-colors flex items-center gap-1.5 ${
                activeTab === "dataflow"
                  ? "bg-[var(--surface)] text-[var(--text-primary)] shadow-sm"
                  : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              }`}
            >
              <GitFork className="w-3.5 h-3.5 text-[#0A84FF]" />
              <span>Source-to-Sink ({dataflowReport?.total_paths || 0})</span>
            </button>
          </div>
        </div>
      </div>

      {/* Summary Inset Panel */}
      <div className="macos-panel p-3.5 grid grid-cols-2 sm:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-[var(--border-subtle)] text-[12px]">
        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Static code flaws</div>
          <div className="text-xl font-semibold text-[var(--text-primary)]">{sastFindings.length}</div>
        </div>
        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">High / Critical priority</div>
          <div className={`text-xl font-semibold ${criticalHighCount > 0 ? "text-[#FF453A]" : "text-[#34C759]"}`}>
            {criticalHighCount}
          </div>
        </div>
        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Data flow paths</div>
          <div className="text-xl font-semibold text-[#0A84FF]">
            {dataflowReport?.total_paths ?? (loadingDataflow ? "..." : 0)}
          </div>
        </div>
        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Target repository</div>
          <div className="font-mono text-[13px] font-medium text-[var(--text-primary)] truncate mt-1">
            {selectedScan?.owner}/{selectedScan?.repo}
          </div>
        </div>
      </div>

      {/* Active Tab View: Findings */}
      {activeTab === "findings" && (
        <div className="space-y-4">
          {/* Filter Toolbar */}
          <div className="flex flex-col sm:flex-row gap-2.5 items-stretch sm:items-center justify-between">
            <div className="relative flex-1 max-w-sm">
              <Search className="w-3.5 h-3.5 text-[var(--text-muted)] absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Filter by rule, description, file..."
                className="macos-input w-full pl-8 text-[12px]"
              />
            </div>

            <div className="flex items-center gap-2">
              {languages.length > 0 && (
                <select
                  value={selectedLanguage}
                  onChange={(e) => setSelectedLanguage(e.target.value)}
                  className="macos-input h-7 text-[12px] cursor-pointer"
                >
                  <option value="ALL">All Languages</option>
                  {languages.map((lang) => (
                    <option key={lang} value={lang}>{lang}</option>
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

              {(search || selectedSeverity !== "ALL" || selectedLanguage !== "ALL") && (
                <button
                  onClick={() => {
                    setSearch("");
                    setSelectedSeverity("ALL");
                    setSelectedLanguage("ALL");
                  }}
                  className="macos-button h-7 text-[12px] px-2 text-[var(--text-secondary)]"
                >
                  <RotateCcw className="w-3 h-3" />
                  <span>Reset</span>
                </button>
              )}
            </div>
          </div>

          {/* Code Analysis Table */}
          <div className="macos-panel overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-[13px]">
                <thead>
                  <tr className="border-b border-[var(--border-color)] bg-[var(--bg-secondary)] text-[var(--text-secondary)] text-[11px] font-medium select-none">
                    <th className="py-2 px-3.5 w-24">Severity</th>
                    <th className="py-2 px-3.5 w-28">Language</th>
                    <th className="py-2 px-3.5">Rule &amp; Vulnerability</th>
                    <th className="py-2 px-3.5">File Location</th>
                    <th className="py-2 px-3.5 text-right w-20">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border-subtle)]">
                  {filteredFindings.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="py-10 text-center text-[var(--text-secondary)] text-[12px]">
                        {sastFindings.length === 0
                          ? "Zero static code flaws identified in this scan."
                          : "No code analysis findings match active filters."}
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
                        <td className="py-2.5 px-3.5 text-[12px] text-[var(--text-secondary)] font-medium">
                          {getLanguage(finding.file_path)}
                        </td>
                        <td className="py-2.5 px-3.5">
                          <div className="font-medium text-[var(--text-primary)] line-clamp-1">{finding.title}</div>
                          <div className="text-[11px] font-mono text-[var(--text-muted)] line-clamp-1 mt-0.5">{finding.rule_id}</div>
                        </td>
                        <td className="py-2.5 px-3.5 font-mono text-[12px] text-[var(--text-secondary)]">
                          <div className="flex items-center gap-1.5">
                            <span className="line-clamp-1 break-all">{finding.file_path}</span>
                            {finding.line_start && (
                              <span className="text-[var(--text-muted)] font-medium">
                                :L{finding.line_start}{finding.line_end && finding.line_end !== finding.line_start ? `-L${finding.line_end}` : ""}
                              </span>
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
        </div>
      )}

      {/* Active Tab View: Source-to-Sink Data Flow */}
      {activeTab === "dataflow" && (
        <div className="space-y-4">
          {/* Methodology & Limitations Disclosure Banner */}
          <div className="p-3.5 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] flex items-start gap-3">
            <Info className="w-4 h-4 text-[#0A84FF] shrink-0 mt-0.5" />
            <div className="text-[12px] text-[var(--text-secondary)] space-y-1">
              <div className="font-medium text-[var(--text-primary)]">
                Source-to-Sink Static Taint Analysis Methodology
              </div>
              <p>
                RepoShield analyzes AST parse trees across Python, JavaScript/TypeScript, and Go to trace untrusted inputs (Sources) such as HTTP parameters, headers, and form inputs flowing into security-sensitive operations (Sinks) like SQL queries, shell commands, and unsafe deserializers.
              </p>
              <p className="text-[11px] text-[var(--text-muted)]">
                Scope limitation: Analysis is localized to intra-procedural AST propagation and known pattern matches. Complete interprocedural taint flow across independent microservices or dynamically evaluated bindings cannot be established statically without runtime tracing.
              </p>
            </div>
          </div>

          {/* Dataflow Paths List */}
          {loadingDataflow ? (
            <div className="macos-panel p-8 text-center text-[12px] text-[var(--text-secondary)]">
              Tracing source-to-sink data flows from AST patterns...
            </div>
          ) : !dataflowReport || dataflowReport.paths.length === 0 ? (
            <div className="macos-panel p-10 text-center space-y-2">
              <ShieldCheck className="w-8 h-8 text-[#34C759] mx-auto" />
              <div className="text-[14px] font-medium text-[var(--text-primary)]">
                No Dangerous Source-to-Sink Paths Detected
              </div>
              <p className="text-[12px] text-[var(--text-secondary)] max-w-md mx-auto">
                No direct tainted propagation from user-controlled inputs into sensitive system sinks was identified in this scan.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {dataflowReport.paths.map((path) => {
                const isExpanded = !!expandedPaths[path.id];
                const matchingFinding = selectedScan?.findings.find((f) => f.id === path.finding_id);

                return (
                  <div
                    key={path.id}
                    className="macos-panel overflow-hidden border border-[var(--border-color)] transition-all"
                  >
                    {/* Path Card Header */}
                    <div
                      onClick={() => togglePathExpand(path.id)}
                      className="p-3.5 bg-[var(--bg-secondary)] flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer hover:bg-[var(--bg-hover)] transition-colors"
                    >
                      <div className="flex items-start sm:items-center gap-2.5">
                        <button className="text-[var(--text-muted)] p-0.5 mt-0.5 sm:mt-0">
                          {isExpanded ? (
                            <ChevronDown className="w-4 h-4" />
                          ) : (
                            <ChevronRight className="w-4 h-4" />
                          )}
                        </button>
                        <SeverityBadge severity={path.severity} />
                        <span className="text-[11px] font-medium px-2 py-0.5 rounded bg-[var(--surface)] text-[var(--text-secondary)] border border-[var(--border-subtle)]">
                          {path.language}
                        </span>
                        <div>
                          <div className="text-[13px] font-semibold text-[var(--text-primary)] flex items-center gap-2">
                            <span>{path.finding_title}</span>
                          </div>
                          <div className="text-[11px] text-[var(--text-secondary)] font-mono mt-0.5 flex items-center gap-1.5 flex-wrap">
                            <span className="text-[#FF9500]">Source: {path.source_type}</span>
                            <ArrowRight className="w-3 h-3 text-[var(--text-muted)]" />
                            <span className="text-[#FF453A]">Sink: {path.sink_type}</span>
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-2 self-end sm:self-auto">
                        <span
                          className={`text-[11px] font-medium px-2 py-0.5 rounded ${
                            path.confidence === "CONFIRMED_LOCAL_FLOW"
                              ? "bg-emerald-500/10 text-emerald-500 border border-emerald-500/20"
                              : "bg-amber-500/10 text-amber-500 border border-amber-500/20"
                          }`}
                        >
                          {path.confidence === "CONFIRMED_LOCAL_FLOW"
                            ? "Confirmed Local Flow"
                            : "Potential Pattern Match"}
                        </span>
                        {matchingFinding && (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedFinding(matchingFinding);
                            }}
                            className="macos-button h-6 text-[11px] px-2"
                          >
                            Inspect
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Step-by-Step Flow Visualization */}
                    <div className="p-4 space-y-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[12px]">
                        {/* Source Box */}
                        <div className="p-3 rounded-[6px] bg-[var(--surface)] border border-[var(--border-subtle)] space-y-1.5">
                          <div className="text-[11px] font-semibold uppercase tracking-wider text-[#FF9500] flex items-center gap-1.5">
                            <Layers className="w-3.5 h-3.5" />
                            <span>1. Untrusted Source Input</span>
                          </div>
                          <div className="font-mono text-[11px] text-[var(--text-primary)] font-medium">
                            Variable: <span className="text-[#0A84FF]">{path.source_variable}</span>
                          </div>
                          <div className="text-[11px] text-[var(--text-secondary)] font-mono">
                            Location: {path.source_location}
                          </div>
                          <div className="text-[11px] text-[var(--text-muted)]">
                            Classification: {path.source_type}
                          </div>
                        </div>

                        {/* Sink Box */}
                        <div className="p-3 rounded-[6px] bg-[var(--surface)] border border-[var(--border-subtle)] space-y-1.5">
                          <div className="text-[11px] font-semibold uppercase tracking-wider text-[#FF453A] flex items-center gap-1.5">
                            <ShieldAlert className="w-3.5 h-3.5" />
                            <span>2. Sensitive Execution Sink</span>
                          </div>
                          <div className="font-mono text-[11px] text-[var(--text-primary)] font-medium">
                            Operation: <span className="text-[#FF453A]">{path.sink_operation}</span>
                          </div>
                          <div className="text-[11px] text-[var(--text-secondary)] font-mono">
                            Location: {path.sink_location}
                          </div>
                          <div className="text-[11px] text-[var(--text-muted)]">
                            Sink Category: {path.sink_type}
                          </div>
                        </div>
                      </div>

                      {/* Sanitization & Propagation Details */}
                      <div className="p-3 rounded-[6px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] space-y-2 text-[12px]">
                        <div className="flex items-center justify-between">
                          <span className="font-medium text-[var(--text-primary)]">
                            Sanitization &amp; Validation Status:
                          </span>
                          <span
                            className={`font-medium text-[11px] px-2 py-0.5 rounded ${
                              path.sanitization_effective
                                ? "bg-emerald-500/10 text-emerald-500"
                                : "bg-red-500/10 text-red-500"
                            }`}
                          >
                            {path.sanitization_detected
                              ? `Detected: ${path.sanitization_detected}`
                              : "No Sanitizer Detected in Propagation Chain"}
                          </span>
                        </div>

                        {/* Propagation Steps Accordion */}
                        {path.propagation_steps && path.propagation_steps.length > 0 && isExpanded && (
                          <div className="mt-3 pt-3 border-t border-[var(--border-subtle)] space-y-2">
                            <div className="text-[11px] font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
                              Intermediate AST Taint Steps:
                            </div>
                            <div className="space-y-1.5 font-mono text-[11px]">
                              {path.propagation_steps.map((st) => (
                                <div
                                  key={st.step_number}
                                  className="p-2 rounded bg-[var(--surface)] border border-[var(--border-subtle)] space-y-1"
                                >
                                  <div className="flex items-center justify-between text-[var(--text-muted)]">
                                    <span>Step {st.step_number}: {st.description}</span>
                                    <span>{st.file_path}:L{st.line_number}</span>
                                  </div>
                                  <pre className="text-[var(--text-primary)] bg-[var(--bg-secondary)] p-1.5 rounded overflow-x-auto text-[11px]">
                                    {st.code_snippet}
                                  </pre>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        <div className="text-[11px] text-[var(--text-muted)] flex items-start gap-1.5 pt-1">
                          <AlertTriangle className="w-3.5 h-3.5 text-amber-500 shrink-0 mt-0.5" />
                          <span>{path.analysis_limitation}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Inspector Modal */}
      <FindingDetailModal
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
}
