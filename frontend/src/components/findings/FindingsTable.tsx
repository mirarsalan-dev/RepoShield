"use client";

import React, { useState, useMemo } from "react";
import {
  Search,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  RotateCcw,
  Copy,
  Check,
  ChevronLeft,
  ChevronRight,
  FileText,
  ShieldAlert,
  CheckCircle2,
} from "lucide-react";
import { Finding, Severity } from "@/lib/types";
import { SeverityBadge } from "./SeverityBadge";
import { FindingDetailModal } from "./FindingDetailModal";
import { storage } from "@/lib/storage";

interface FindingsTableProps {
  findings: Finding[];
  initialCategory?: string;
  onRefresh?: () => void;
}

type SortField = "severity" | "title" | "category" | "file_path";
type SortDirection = "asc" | "desc";

const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
  UNKNOWN: 0,
};

export function FindingsTable({ findings, initialCategory = "ALL", onRefresh }: FindingsTableProps) {
  const [search, setSearch] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string>(initialCategory);
  const [selectedSeverity, setSelectedSeverity] = useState<string>("ALL");
  const [selectedScanner, setSelectedScanner] = useState<string>("ALL");
  const [selectedStatus, setSelectedStatus] = useState<string>("ALL");
  const [selectedConfidence, setSelectedConfidence] = useState<string>("ALL");
  const [selectedPriority, setSelectedPriority] = useState<string>("ALL");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [copiedFile, setCopiedFile] = useState<string | null>(null);
  const [syncKey, setSyncKey] = useState(0);

  // Sorting state
  const [sortField, setSortField] = useState<SortField>("severity");
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc");

  // Pagination state
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(12);

  // Available scanners
  const scanners = useMemo(() => {
    const set = new Set<string>();
    findings.forEach((f) => {
      if (f.detector_name) set.add(f.detector_name);
    });
    return Array.from(set);
  }, [findings]);

  // Suppressions and Reviewed sets
  const suppressions = useMemo(() => {
    const map = new Map<string, string>();
    storage.getSuppressions().forEach((s) => map.set(s.fingerprint, s.reason));
    return map;
  }, [syncKey]);

  const reviewedSet = useMemo(() => {
    return new Set(storage.getReviewedFindings());
  }, [syncKey]);

  // Filtered & Sorted findings
  const filteredFindings = useMemo(() => {
    const list = findings.filter((f) => {
      const fp = f.fingerprint || `${f.detector_name}:${f.rule_id}:${f.file_path}`;
      const isSuppressed = suppressions.has(fp);
      const isReviewed = reviewedSet.has(f.id);

      // Status Filter
      if (selectedStatus === "SUPPRESSED" && !isSuppressed) return false;
      if (selectedStatus === "REVIEWED" && (!isReviewed || isSuppressed)) return false;
      if (selectedStatus === "OPEN" && (isSuppressed || isReviewed)) return false;

      // Category Filter
      if (selectedCategory !== "ALL" && f.category !== selectedCategory) return false;

      // Severity Filter
      if (selectedSeverity !== "ALL" && f.severity !== selectedSeverity) return false;

      // Scanner Filter
      if (selectedScanner !== "ALL" && f.detector_name !== selectedScanner) return false;

      // Confidence Filter
      if (selectedConfidence !== "ALL" && f.confidence !== selectedConfidence) return false;

      // Priority Filter (V2 Risk Intelligence)
      if (selectedPriority !== "ALL" && f.exploitability_priority !== selectedPriority) return false;

      // Search Query
      if (search.trim()) {
        const query = search.toLowerCase();
        const matchesTitle = f.title.toLowerCase().includes(query);
        const matchesFile = f.file_path.toLowerCase().includes(query);
        const matchesRule = f.rule_id.toLowerCase().includes(query);
        const matchesDesc = f.description.toLowerCase().includes(query);
        const matchesPkg = f.package_name?.toLowerCase().includes(query) || false;
        if (!matchesTitle && !matchesFile && !matchesRule && !matchesDesc && !matchesPkg) {
          return false;
        }
      }
      return true;
    });

    list.sort((a, b) => {
      let comparison = 0;
      if (sortField === "severity") {
        comparison = (SEVERITY_ORDER[a.severity] || 0) - (SEVERITY_ORDER[b.severity] || 0);
      } else if (sortField === "title") {
        comparison = a.title.localeCompare(b.title);
      } else if (sortField === "category") {
        comparison = a.category.localeCompare(b.category);
      } else if (sortField === "file_path") {
        comparison = a.file_path.localeCompare(b.file_path);
      }
      return sortDirection === "asc" ? comparison : -comparison;
    });

    return list;
  }, [
    findings,
    search,
    selectedCategory,
    selectedSeverity,
    selectedScanner,
    selectedStatus,
    selectedConfidence,
    selectedPriority,
    sortField,
    sortDirection,
    suppressions,
    reviewedSet,
  ]);

  const totalPages = Math.ceil(filteredFindings.length / pageSize) || 1;
  const paginatedFindings = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredFindings.slice(start, start + pageSize);
  }, [filteredFindings, currentPage, pageSize]);

  const handleFilterChange = (setter: (val: any) => void, val: any) => {
    setter(val);
    setCurrentPage(1);
  };

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection(sortDirection === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortDirection(field === "severity" ? "desc" : "asc");
    }
  };

  const resetFilters = () => {
    setSearch("");
    setSelectedCategory("ALL");
    setSelectedSeverity("ALL");
    setSelectedScanner("ALL");
    setSelectedStatus("ALL");
    setSelectedConfidence("ALL");
    setCurrentPage(1);
  };

  const copyPath = (path: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(path);
    setCopiedFile(path);
    setTimeout(() => setCopiedFile(null), 2000);
  };

  const handleStatusChange = () => {
    setSyncKey((k) => k + 1);
    if (onRefresh) onRefresh();
  };

  const secretsCount = findings.filter((f) => f.category === "SECRETS").length;
  const depsCount = findings.filter((f) => f.category === "DEPENDENCIES").length;
  const sastCount = findings.filter((f) => f.category === "SAST").length;
  const infraCount = findings.filter((f) => f.category === "INFRASTRUCTURE").length;

  return (
    <div className="space-y-3">
      {/* Restrained Filter Toolbar */}
      <div className="flex flex-col sm:flex-row gap-2.5 items-stretch sm:items-center justify-between">
        {/* Search */}
        <div className="relative flex-1 max-w-sm">
          <Search className="w-3.5 h-3.5 text-[var(--text-muted)] absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => handleFilterChange(setSearch, e.target.value)}
            placeholder="Search title, rule ID, package, or file..."
            className="macos-input w-full pl-8 text-[12px]"
          />
        </div>

        {/* Filter Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Status Filter */}
          <select
            value={selectedStatus}
            onChange={(e) => handleFilterChange(setSelectedStatus, e.target.value)}
            className="macos-input h-7 text-[12px] cursor-pointer"
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open Findings</option>
            <option value="REVIEWED">Reviewed</option>
            <option value="SUPPRESSED">Suppressed ({suppressions.size})</option>
          </select>

          {/* Category Filter */}
          <select
            value={selectedCategory}
            onChange={(e) => handleFilterChange(setSelectedCategory, e.target.value)}
            className="macos-input h-7 text-[12px] cursor-pointer"
          >
            <option value="ALL">All Categories ({findings.length})</option>
            <option value="SECRETS">Secrets ({secretsCount})</option>
            <option value="DEPENDENCIES">Dependencies ({depsCount})</option>
            <option value="SAST">Static Analysis ({sastCount})</option>
            {infraCount > 0 && <option value="INFRASTRUCTURE">Infrastructure ({infraCount})</option>}
          </select>

          {/* Severity Filter */}
          <select
            value={selectedSeverity}
            onChange={(e) => handleFilterChange(setSelectedSeverity, e.target.value)}
            className="macos-input h-7 text-[12px] cursor-pointer"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>

          {/* Confidence Filter */}
          <select
            value={selectedConfidence}
            onChange={(e) => handleFilterChange(setSelectedConfidence, e.target.value)}
            className="macos-input h-7 text-[12px] cursor-pointer"
          >
            <option value="ALL">Confidence</option>
            <option value="HIGH">High Confidence</option>
            <option value="MEDIUM">Medium Confidence</option>
            <option value="LOW">Low Confidence</option>
          </select>

          {/* Priority Filter */}
          <select
            value={selectedPriority}
            onChange={(e) => handleFilterChange(setSelectedPriority, e.target.value)}
            className="macos-input h-7 text-[12px] cursor-pointer"
          >
            <option value="ALL">All Priorities</option>
            <option value="P1">P1 - Active / Critical</option>
            <option value="P2">P2 - High Priority</option>
            <option value="P3">P3 - Medium</option>
            <option value="P4">P4 - Low / Hardened</option>
          </select>

          {scanners.length > 1 && (
            <select
              value={selectedScanner}
              onChange={(e) => handleFilterChange(setSelectedScanner, e.target.value)}
              className="macos-input h-7 text-[12px] cursor-pointer"
            >
              <option value="ALL">All Scanners</option>
              {scanners.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          )}

          {(search ||
            selectedCategory !== "ALL" ||
            selectedSeverity !== "ALL" ||
            selectedScanner !== "ALL" ||
            selectedStatus !== "ALL" ||
            selectedConfidence !== "ALL") && (
            <button
              onClick={resetFilters}
              className="macos-button h-7 text-[12px] px-2 text-[var(--text-secondary)]"
              title="Reset filters"
            >
              <RotateCcw className="w-3 h-3" />
              <span>Reset</span>
            </button>
          )}
        </div>
      </div>

      {/* Findings Table */}
      <div className="macos-panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-[13px]">
            <thead>
              <tr className="border-b border-[var(--border-color)] bg-[var(--bg-secondary)] text-[var(--text-secondary)] text-[11px] font-medium select-none">
                <th
                  className="py-2 px-3.5 w-28 cursor-pointer hover:text-[var(--text-primary)]"
                  onClick={() => handleSort("severity")}
                >
                  <div className="flex items-center gap-1">
                    <span>Severity</span>
                    {sortField === "severity" ? (
                      sortDirection === "asc" ? <ArrowUp className="w-3 h-3 text-[var(--accent)]" /> : <ArrowDown className="w-3 h-3 text-[var(--accent)]" />
                    ) : (
                      <ArrowUpDown className="w-2.5 h-2.5 opacity-40" />
                    )}
                  </div>
                </th>
                <th
                  className="py-2 px-3.5 cursor-pointer hover:text-[var(--text-primary)]"
                  onClick={() => handleSort("title")}
                >
                  <div className="flex items-center gap-1">
                    <span>Finding & Rule</span>
                    {sortField === "title" ? (
                      sortDirection === "asc" ? <ArrowUp className="w-3 h-3 text-[var(--accent)]" /> : <ArrowDown className="w-3 h-3 text-[var(--accent)]" />
                    ) : (
                      <ArrowUpDown className="w-2.5 h-2.5 opacity-40" />
                    )}
                  </div>
                </th>
                <th
                  className="py-2 px-3.5 w-24 cursor-pointer hover:text-[var(--text-primary)] hidden md:table-cell"
                  onClick={() => handleSort("category")}
                >
                  <div className="flex items-center gap-1">
                    <span>Category</span>
                    {sortField === "category" ? (
                      sortDirection === "asc" ? <ArrowUp className="w-3 h-3 text-[var(--accent)]" /> : <ArrowDown className="w-3 h-3 text-[var(--accent)]" />
                    ) : (
                      <ArrowUpDown className="w-2.5 h-2.5 opacity-40" />
                    )}
                  </div>
                </th>
                <th
                  className="py-2 px-3.5 cursor-pointer hover:text-[var(--text-primary)]"
                  onClick={() => handleSort("file_path")}
                >
                  <div className="flex items-center gap-1">
                    <span>File</span>
                    {sortField === "file_path" ? (
                      sortDirection === "asc" ? <ArrowUp className="w-3 h-3 text-[var(--accent)]" /> : <ArrowDown className="w-3 h-3 text-[var(--accent)]" />
                    ) : (
                      <ArrowUpDown className="w-2.5 h-2.5 opacity-40" />
                    )}
                  </div>
                </th>
                <th className="py-2 px-3.5 w-24 text-[var(--text-secondary)] hidden sm:table-cell">
                  Status
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-subtle)]">
              {paginatedFindings.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-12 text-center text-[var(--text-secondary)]">
                    <FileText className="w-6 h-6 text-[var(--text-muted)] mx-auto mb-1.5" />
                    <div className="text-[13px] font-medium text-[var(--text-primary)]">
                      No findings match criteria
                    </div>
                    <p className="text-[12px] text-[var(--text-secondary)] mt-0.5">
                      Adjust your search or clear active filters.
                    </p>
                  </td>
                </tr>
              ) : (
                paginatedFindings.map((finding) => {
                  const fp = finding.fingerprint || `${finding.detector_name}:${finding.rule_id}:${finding.file_path}`;
                  const isSuppressed = suppressions.has(fp);
                  const isReviewed = reviewedSet.has(finding.id);

                  return (
                    <tr
                      key={finding.id}
                      className={`hover:bg-[var(--bg-hover)] transition-colors cursor-pointer group ${
                        isSuppressed ? "opacity-60 bg-[var(--bg-secondary)]/50" : ""
                      }`}
                      onClick={() => setSelectedFinding(finding)}
                    >
                      <td className="py-2.5 px-3.5 whitespace-nowrap">
                        <SeverityBadge severity={finding.severity} />
                      </td>
                      <td className="py-2.5 px-3.5 max-w-md">
                        <div className="font-medium text-[var(--text-primary)] group-hover:text-[var(--accent)] transition-colors line-clamp-1 flex items-center gap-1.5 flex-wrap">
                          <span>{finding.title}</span>
                          {finding.exploitability_priority && (
                            <span
                              className={`text-[9px] font-mono font-semibold px-1 py-0.5 rounded ${
                                finding.exploitability_priority === "P1"
                                  ? "bg-[#FF3B30]/15 text-[#FF3B30] border border-[#FF3B30]/30"
                                  : finding.exploitability_priority === "P2"
                                  ? "bg-[#FF9500]/15 text-[#FF9500] border border-[#FF9500]/30"
                                  : "bg-[var(--bg-secondary)] text-[var(--text-secondary)] border border-[var(--border-subtle)]"
                              }`}
                            >
                              {finding.exploitability_priority}
                            </span>
                          )}
                          {finding.cisa_kev && (
                            <span className="text-[9px] font-mono px-1 py-0.5 rounded bg-[#FF3B30]/20 text-[#FF3B30] border border-[#FF3B30]/40 font-bold">
                              KEV
                            </span>
                          )}
                          {finding.is_historical && (
                            <span className="text-[9px] font-mono px-1 py-0.5 rounded bg-[#FF9500]/20 text-[#FF9500] border border-[#FF9500]/40 font-medium">
                              GIT LEAK
                            </span>
                          )}
                          {finding.confidence && (
                            <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-[var(--bg-secondary)] text-[var(--text-muted)] border border-[var(--border-subtle)]">
                              {finding.confidence}
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] font-mono text-[var(--text-muted)] mt-0.5 truncate">
                          {finding.rule_id}
                        </div>
                      </td>
                      <td className="py-2.5 px-3.5 text-[12px] text-[var(--text-secondary)] hidden md:table-cell whitespace-nowrap">
                        {finding.category}
                      </td>
                      <td className="py-2.5 px-3.5 font-mono text-[12px] text-[var(--text-secondary)]">
                        <div className="flex items-center gap-1.5">
                          <span className="line-clamp-1 break-all">{finding.file_path}</span>
                          {finding.line_start && (
                            <span className="text-[var(--text-muted)] font-medium flex-shrink-0">
                              :{finding.line_start}
                            </span>
                          )}
                          <button
                            onClick={(e) => copyPath(finding.file_path, e)}
                            className="opacity-0 group-hover:opacity-100 hover:text-[var(--accent)] p-0.5 transition-opacity"
                            title="Copy file path"
                          >
                            {copiedFile === finding.file_path ? (
                              <Check className="w-3 h-3 text-[#34C759]" />
                            ) : (
                              <Copy className="w-3 h-3 text-[var(--text-muted)]" />
                            )}
                          </button>
                        </div>
                      </td>
                      <td className="py-2.5 px-3.5 text-[11px] font-mono hidden sm:table-cell whitespace-nowrap">
                        {isSuppressed ? (
                          <span className="px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20">
                            Suppressed
                          </span>
                        ) : isReviewed ? (
                          <span className="px-1.5 py-0.5 rounded bg-[#34C759]/10 text-[#34C759] border border-[#34C759]/20 flex items-center gap-1 w-max">
                            <CheckCircle2 className="w-2.5 h-2.5" />
                            <span>Reviewed</span>
                          </span>
                        ) : (
                          <span className="text-[var(--text-muted)]">Open</span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Compact Table Footer */}
        <div className="px-3.5 py-2.5 border-t border-[var(--border-subtle)] bg-[var(--bg-secondary)] flex items-center justify-between text-[12px] text-[var(--text-secondary)]">
          <div>
            Showing <span className="font-medium text-[var(--text-primary)]">{filteredFindings.length > 0 ? (currentPage - 1) * pageSize + 1 : 0}</span>–
            <span className="font-medium text-[var(--text-primary)]">
              {Math.min(currentPage * pageSize, filteredFindings.length)}
            </span>{" "}
            of <span className="font-medium text-[var(--text-primary)]">{filteredFindings.length}</span> findings
          </div>

          <div className="flex items-center gap-1">
            <button
              disabled={currentPage <= 1}
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              className="p-1 rounded hover:bg-[var(--bg-hover)] disabled:opacity-30 disabled:hover:bg-transparent text-[var(--text-primary)] transition-colors"
              aria-label="Previous page"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
            </button>
            <span className="px-1.5 text-[11px] text-[var(--text-muted)]">
              {currentPage} / {totalPages}
            </span>
            <button
              disabled={currentPage >= totalPages}
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              className="p-1 rounded hover:bg-[var(--bg-hover)] disabled:opacity-30 disabled:hover:bg-transparent text-[var(--text-primary)] transition-colors"
              aria-label="Next page"
            >
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Inspector Modal */}
      <FindingDetailModal
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        onStatusChange={handleStatusChange}
      />
    </div>
  );
}
