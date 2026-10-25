"use client";

import React, { useState, useEffect, useMemo, useRef } from "react";
import Link from "next/link";
import {
  GitBranch,
  Star,
  GitFork,
  AlertCircle,
  Clock,
  Layers,
  ExternalLink,
  Search,
  SearchCode,
  FileText,
  Sliders,
  History as HistoryIcon,
  Package,
  ShieldAlert,
  Download,
  Upload,
  Trash2,
  Copy,
  Check,
  ChevronRight,
  FolderGit2,
  AlertTriangle,
} from "lucide-react";
import { GithubIcon } from "@/components/common/Icons";
import { storage } from "@/lib/storage";
import { api } from "@/lib/api";
import { ScanResult, RepositoryMetadata } from "@/lib/types";
import { formatDate, formatTimeAgo, formatBytes } from "@/lib/utils";
import { FindingsTable } from "@/components/findings/FindingsTable";
import { EmptyState } from "@/components/common/EmptyState";
import { SeverityBadge } from "@/components/findings/SeverityBadge";

type WorkspaceTab = "repos" | "patterns" | "inspector";

export default function RepositoryWorkspacePage() {
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [meta, setMeta] = useState<RepositoryMetadata | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<WorkspaceTab>("repos");
  const [search, setSearch] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [importNotice, setImportNotice] = useState<string | null>(null);

  useEffect(() => {
    const saved = storage.getScanHistory();
    setHistory(saved);
    if (saved.length > 0) {
      setSelectedScan(saved[0]);
      loadMeta(saved[0].repo_url);
    }
  }, []);

  const loadMeta = async (url: string) => {
    setIsLoading(true);
    setError(null);
    try {
      const settings = storage.getSettings();
      const res = await api.getRepoInfo(url, settings.githubToken);
      setMeta(res);
    } catch (err: any) {
      setError(err.message || "Failed to fetch live repository metadata.");
    } finally {
      setIsLoading(false);
    }
  };

  // Unique list of scanned repositories
  const uniqueRepos = useMemo(() => {
    const map = new Map<string, ScanResult>();
    history.forEach((scan) => {
      const key = `${scan.owner}/${scan.repo}`.toLowerCase();
      if (!map.has(key)) {
        map.set(key, scan);
      }
    });
    return Array.from(map.values()).filter((repo) => {
      if (!search.trim()) return true;
      const q = search.toLowerCase();
      return (
        repo.repo.toLowerCase().includes(q) ||
        repo.owner.toLowerCase().includes(q) ||
        repo.branch.toLowerCase().includes(q)
      );
    });
  }, [history, search]);

  // Repeated Security Flaws Across Repositories (Phase 12 requirement)
  const repeatedPatterns = useMemo(() => {
    const ruleRepoMap = new Map<string, { title: string; category: string; severity: string; repos: Set<string> }>();

    history.forEach((scan) => {
      const repoName = `${scan.owner}/${scan.repo}`;
      scan.findings.forEach((f) => {
        const key = f.rule_id || f.title;
        if (!ruleRepoMap.has(key)) {
          ruleRepoMap.set(key, {
            title: f.title,
            category: f.category,
            severity: f.severity,
            repos: new Set<string>(),
          });
        }
        ruleRepoMap.get(key)!.repos.add(repoName);
      });
    });

    return Array.from(ruleRepoMap.entries())
      .filter(([_, data]) => data.repos.size > 1)
      .map(([ruleId, data]) => ({
        ruleId,
        title: data.title,
        category: data.category,
        severity: data.severity,
        repoCount: data.repos.size,
        repoList: Array.from(data.repos),
      }))
      .sort((a, b) => b.repoCount - a.repoCount);
  }, [history]);

  // Remove a single repository from local workspace
  const handleRemoveRepo = (owner: string, repo: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (window.confirm(`Remove ${owner}/${repo} from your local workspace?`)) {
      const toRemove = history.filter(
        (s) => s.owner.toLowerCase() === owner.toLowerCase() && s.repo.toLowerCase() === repo.toLowerCase()
      );
      toRemove.forEach((s) => storage.deleteScan(s.scan_id));
      const updated = history.filter(
        (s) => !(s.owner.toLowerCase() === owner.toLowerCase() && s.repo.toLowerCase() === repo.toLowerCase())
      );
      setHistory(updated);
      if (selectedScan && selectedScan.owner === owner && selectedScan.repo === repo) {
        setSelectedScan(updated[0] || null);
      }
    }
  };

  // Export Workspace Summary (JSON)
  const exportWorkspace = () => {
    const summary = {
      version: "reposhield-workspace-v1",
      exported_at: new Date().toISOString(),
      total_repositories: uniqueRepos.length,
      repositories: uniqueRepos.map((r) => ({
        owner: r.owner,
        repo: r.repo,
        repo_url: r.repo_url,
        branch: r.branch,
        commit_sha: r.commit_sha,
        scanned_at: r.completed_at || r.started_at,
        findings_count: r.findings.length,
        critical_count: r.findings.filter((f) => f.severity === "CRITICAL").length,
        high_count: r.findings.filter((f) => f.severity === "HIGH").length,
        scanner_coverage: Object.keys(r.scanners_coverage || {}),
      })),
    };

    const blob = new Blob([JSON.stringify(summary, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `reposhield-workspace-summary.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Import Workspace
  const handleImportFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const data = JSON.parse(event.target?.result as string);
        if (data.version && data.repositories) {
          setImportNotice(`Loaded workspace metadata for ${data.total_repositories} repositories.`);
          setTimeout(() => setImportNotice(null), 4000);
        } else {
          alert("Invalid workspace bundle format.");
        }
      } catch (err) {
        alert("Failed to parse JSON file.");
      }
    };
    reader.readAsText(file);
  };

  if (!selectedScan && history.length === 0) {
    return (
      <EmptyState
        icon={GitBranch}
        title="No Repositories in Workspace"
        description="Scan any public or private GitHub repository to build your local Multi-Repository Security Workspace."
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
            Multi-Repository Security Workspace
          </h1>
          <p className="text-[13px] text-[var(--text-secondary)] mt-0.5">
            Organize multiple repositories, track cross-codebase vulnerability patterns, and compare scanner coverage.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleImportFile}
            accept=".json"
            className="hidden"
          />
          <button
            onClick={() => fileInputRef.current?.click()}
            className="macos-button h-7 text-[12px] px-2.5 flex items-center gap-1.5"
            title="Import Workspace Summary"
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Import</span>
          </button>

          <button
            onClick={exportWorkspace}
            className="macos-button h-7 text-[12px] px-2.5 flex items-center gap-1.5"
            title="Export Workspace Summary"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Summary</span>
          </button>

          <Link
            href="/scan"
            className="macos-button macos-button-primary h-7 text-[12px] px-2.5 flex items-center gap-1.5"
          >
            <SearchCode className="w-3.5 h-3.5" />
            <span>Add / Scan Repo</span>
          </Link>
        </div>
      </div>

      {/* Import Notice */}
      {importNotice && (
        <div className="p-3 rounded-[6px] bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 text-[12px] flex items-center gap-2">
          <Check className="w-4 h-4" />
          <span>{importNotice}</span>
        </div>
      )}

      {/* KPI Cards Panel */}
      <div className="macos-panel p-3.5 grid grid-cols-2 sm:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-[var(--border-subtle)] text-[12px]">
        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Monitored Repositories</div>
          <div className="text-xl font-semibold text-[var(--text-primary)]">
            {uniqueRepos.length}
          </div>
        </div>
        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Repeated Flaw Patterns</div>
          <div className="text-xl font-semibold text-[#FF9500]">
            {repeatedPatterns.length}
          </div>
        </div>
        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Active Scan Reports</div>
          <div className="text-xl font-semibold text-[var(--text-primary)]">
            {history.length}
          </div>
        </div>
        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Local Storage State</div>
          <div className="text-[12px] font-mono text-[var(--text-primary)] mt-1">
            Zero Database (RAM/Browser)
          </div>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex items-center gap-2 border-b border-[var(--border-subtle)] pb-2 text-[12px]">
        <button
          onClick={() => setActiveTab("repos")}
          className={`px-3 py-1.5 rounded-[6px] font-medium transition-colors ${
            activeTab === "repos"
              ? "bg-[var(--accent)] text-white"
              : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
          }`}
        >
          Repository Matrix ({uniqueRepos.length})
        </button>
        <button
          onClick={() => setActiveTab("patterns")}
          className={`px-3 py-1.5 rounded-[6px] font-medium transition-colors ${
            activeTab === "patterns"
              ? "bg-[var(--accent)] text-white"
              : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
          }`}
        >
          Cross-Repo Repeated Patterns ({repeatedPatterns.length})
        </button>
        {selectedScan && (
          <button
            onClick={() => setActiveTab("inspector")}
            className={`px-3 py-1.5 rounded-[6px] font-medium transition-colors ${
              activeTab === "inspector"
                ? "bg-[var(--accent)] text-white"
                : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            }`}
          >
            Repo Inspector: {selectedScan.owner}/{selectedScan.repo}
          </button>
        )}
      </div>

      {/* Tab 1: Repository Matrix */}
      {activeTab === "repos" && (
        <div className="space-y-3">
          <div className="macos-panel overflow-hidden">
            <div className="p-3 border-b border-[var(--border-subtle)] flex items-center justify-between bg-[var(--bg-secondary)]">
              <div className="relative w-72">
                <Search className="w-3.5 h-3.5 text-[var(--text-muted)] absolute left-2.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Filter workspace repositories..."
                  className="macos-input w-full pl-8 h-6.5 text-[12px]"
                />
              </div>
              <span className="text-[11px] text-[var(--text-muted)] font-mono">
                {uniqueRepos.length} repositories
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-[13px]">
                <thead>
                  <tr className="border-b border-[var(--border-color)] bg-[var(--bg-secondary)] text-[var(--text-secondary)] text-[11px] font-medium select-none">
                    <th className="py-2 px-3.5">Repository</th>
                    <th className="py-2 px-3.5">Branch</th>
                    <th className="py-2 px-3.5">Commit</th>
                    <th className="py-2 px-3.5">Last Scanned</th>
                    <th className="py-2 px-3.5">Findings</th>
                    <th className="py-2 px-3.5">Coverage</th>
                    <th className="py-2 px-3.5 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border-subtle)]">
                  {uniqueRepos.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-8 text-center text-[var(--text-secondary)] text-[12px]">
                        No repositories matching active filter.
                      </td>
                    </tr>
                  ) : (
                    uniqueRepos.map((repo) => {
                      const isSelected =
                        selectedScan?.owner.toLowerCase() === repo.owner.toLowerCase() &&
                        selectedScan?.repo.toLowerCase() === repo.repo.toLowerCase();
                      const critCount = repo.findings.filter((f) => f.severity === "CRITICAL").length;
                      const highCount = repo.findings.filter((f) => f.severity === "HIGH").length;

                      return (
                        <tr
                          key={repo.scan_id}
                          onClick={() => {
                            setSelectedScan(repo);
                            loadMeta(repo.repo_url);
                          }}
                          className={`cursor-pointer transition-colors ${
                            isSelected
                              ? "bg-[var(--accent-subtle)] font-medium text-[var(--accent)]"
                              : "hover:bg-[var(--bg-hover)] text-[var(--text-primary)]"
                          }`}
                        >
                          <td className="py-2.5 px-3.5 flex items-center gap-2">
                            <GithubIcon className="w-4 h-4 flex-shrink-0 text-[var(--text-secondary)]" />
                            <span className="truncate">{repo.owner}/{repo.repo}</span>
                          </td>
                          <td className="py-2.5 px-3.5 font-mono text-[12px] text-[var(--text-secondary)]">
                            {repo.branch}
                          </td>
                          <td className="py-2.5 px-3.5 font-mono text-[12px] text-[var(--text-muted)]">
                            {repo.commit_sha ? repo.commit_sha.slice(0, 7) : "HEAD"}
                          </td>
                          <td className="py-2.5 px-3.5 text-[12px] text-[var(--text-secondary)]">
                            {formatTimeAgo(repo.completed_at || repo.started_at)}
                          </td>
                          <td className="py-2.5 px-3.5 font-mono text-[12px]">
                            <div className="flex items-center gap-1.5">
                              <span className="font-semibold text-[var(--text-primary)]">{repo.findings.length}</span>
                              {critCount > 0 && (
                                <span className="text-[10px] px-1 rounded bg-red-500/10 text-red-500 font-bold">
                                  {critCount}C
                                </span>
                              )}
                              {highCount > 0 && (
                                <span className="text-[10px] px-1 rounded bg-amber-500/10 text-amber-500 font-bold">
                                  {highCount}H
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="py-2.5 px-3.5 text-[11px] font-mono text-[var(--text-muted)]">
                            {Object.keys(repo.scanners_coverage || {}).length} Engines
                          </td>
                          <td className="py-2.5 px-3.5 text-right">
                            <div className="flex items-center justify-end gap-1.5">
                              <Link
                                href={`/scan?repo=${encodeURIComponent(repo.repo_url)}`}
                                onClick={(e) => e.stopPropagation()}
                                className="macos-button h-6 text-[11px] px-2"
                              >
                                Re-Scan
                              </Link>
                              <button
                                onClick={(e) => handleRemoveRepo(repo.owner, repo.repo, e)}
                                className="macos-button h-6 text-[11px] px-1.5 text-[var(--text-muted)] hover:text-[#FF453A]"
                                title="Remove from workspace"
                              >
                                <Trash2 className="w-3 h-3" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Cross-Repo Repeated Patterns */}
      {activeTab === "patterns" && (
        <div className="space-y-3">
          {repeatedPatterns.length === 0 ? (
            <div className="macos-panel p-8 text-center text-[12px] text-[var(--text-secondary)]">
              No repeated vulnerability patterns identified across workspace repositories.
            </div>
          ) : (
            repeatedPatterns.map((pat) => (
              <div
                key={pat.ruleId}
                className="macos-panel p-4 space-y-3 border border-[var(--border-color)]"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={pat.severity as any} />
                    <span className="font-semibold text-[13px] text-[var(--text-primary)]">
                      {pat.title}
                    </span>
                    <span className="font-mono text-[11px] text-[var(--text-muted)]">
                      ({pat.ruleId})
                    </span>
                  </div>

                  <span className="text-[11px] font-semibold px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
                    Shared in {pat.repoCount} Repositories
                  </span>
                </div>

                <div className="space-y-1 pl-2 text-[12px]">
                  <div className="text-[11px] text-[var(--text-muted)] uppercase font-semibold">
                    Affected Workspace Codebases:
                  </div>
                  <div className="flex flex-wrap gap-2 pt-0.5">
                    {pat.repoList.map((rn) => (
                      <span
                        key={rn}
                        className="px-2 py-0.5 rounded bg-[var(--surface)] text-[var(--text-primary)] font-mono text-[11px] border border-[var(--border-subtle)]"
                      >
                        {rn}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* Tab 3: Selected Repo Inspector */}
      {activeTab === "inspector" && selectedScan && (
        <div className="macos-panel p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[var(--border-subtle)]">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-[6px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] flex items-center justify-center">
                <GithubIcon className="w-5 h-5 text-[var(--text-primary)]" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h2 className="text-[16px] font-semibold text-[var(--text-primary)] tracking-tight">
                    {selectedScan.owner}/{selectedScan.repo}
                  </h2>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded-[4px] bg-[var(--bg-secondary)] text-[var(--text-secondary)] border border-[var(--border-subtle)]">
                    {meta?.is_private ? "Private" : "Public"}
                  </span>
                </div>
                <p className="text-[12px] text-[var(--text-secondary)] truncate max-w-xl mt-0.5">
                  {meta?.description || "Public repository analyzed on RepoShield."}
                </p>
              </div>
            </div>

            <a
              href={selectedScan.repo_url}
              target="_blank"
              rel="noreferrer"
              className="macos-button h-7 text-[12px]"
            >
              <GithubIcon className="w-3.5 h-3.5" />
              <span>GitHub</span>
              <ExternalLink className="w-3 h-3 text-[var(--text-muted)]" />
            </a>
          </div>

          {/* Findings Summary Table */}
          <div className="pt-2">
            <h3 className="text-[13px] font-semibold text-[var(--text-primary)] mb-2">
              Repository Security Findings ({selectedScan.findings.length})
            </h3>
            <FindingsTable findings={selectedScan.findings} />
          </div>
        </div>
      )}
    </div>
  );
}
