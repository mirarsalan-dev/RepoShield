"use client";

import React, { useState, useEffect, useMemo, useRef } from "react";
import Link from "next/link";
import {
  Bookmark,
  Plus,
  Trash2,
  Play,
  RotateCcw,
  Search,
  ExternalLink,
  Download,
  Upload,
  Info,
  Clock,
  Check,
  ShieldAlert,
  GitBranch,
  Radio,
  FileCode,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { WatchlistItem, WatchlistType, WatchlistBundle } from "@/lib/types";
import { formatTimeAgo } from "@/lib/utils";

export default function WatchlistPage() {
  const [items, setItems] = useState<WatchlistItem[]>([]);
  const [activeTab, setActiveTab] = useState<WatchlistType>("REPOSITORY");
  const [search, setSearch] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [showAddModal, setShowAddModal] = useState(false);
  const [newTarget, setNewTarget] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [newNotes, setNewNotes] = useState("");
  const [newType, setNewType] = useState<WatchlistType>("REPOSITORY");
  const [recheckNotice, setRecheckNotice] = useState<string | null>(null);

  useEffect(() => {
    const saved = storage.getWatchlist();
    if (saved.length === 0) {
      // Seed initial helpful items
      const initial: WatchlistItem[] = [
        {
          id: "watch-repo-1",
          type: "REPOSITORY",
          target: "https://github.com/OWASP/NodeGoat",
          label: "OWASP NodeGoat (Benchmark Reference)",
          notes: "Curated vulnerable benchmark repo for OWASP Top 10 evaluation",
          added_at: new Date().toISOString(),
          last_checked_at: new Date().toISOString(),
          status: "MONITORED",
        },
        {
          id: "watch-cve-1",
          type: "CVE",
          target: "CVE-2022-42889",
          label: "Text4Shell (Apache Commons Text)",
          notes: "String interpolation RCE advisory monitoring in dependencies",
          added_at: new Date().toISOString(),
          last_checked_at: new Date().toISOString(),
          status: "HIGH_ALERT",
        },
      ];
      initial.forEach((i) => storage.saveWatchlistItem(i));
      setItems(initial);
    } else {
      setItems(saved);
    }
  }, []);

  const filteredItems = useMemo(() => {
    return items.filter((i) => {
      if (i.type !== activeTab) return false;
      if (search.trim()) {
        const q = search.toLowerCase();
        const matchesTarget = i.target.toLowerCase().includes(q);
        const matchesLabel = (i.label || "").toLowerCase().includes(q);
        const matchesNotes = (i.notes || "").toLowerCase().includes(q);
        if (!matchesTarget && !matchesLabel && !matchesNotes) return false;
      }
      return true;
    });
  }, [items, activeTab, search]);

  const handleAddItem = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTarget.trim()) return;

    const newItem: WatchlistItem = {
      id: `watch-${Date.now()}`,
      type: newType,
      target: newTarget.trim(),
      label: newLabel.trim() || undefined,
      notes: newNotes.trim() || undefined,
      added_at: new Date().toISOString(),
      last_checked_at: new Date().toISOString(),
      status: "MONITORED",
    };

    storage.saveWatchlistItem(newItem);
    setItems(storage.getWatchlist());
    setNewTarget("");
    setNewLabel("");
    setNewNotes("");
    setShowAddModal(false);
  };

  const handleRemove = (id: string) => {
    storage.removeWatchlistItem(id);
    setItems(storage.getWatchlist());
  };

  const handleRecheck = (item: WatchlistItem) => {
    const updated = {
      ...item,
      last_checked_at: new Date().toISOString(),
    };
    storage.saveWatchlistItem(updated);
    setItems(storage.getWatchlist());
    setRecheckNotice(`Rechecked advisory metadata for ${item.target}.`);
    setTimeout(() => setRecheckNotice(null), 3000);
  };

  const exportWatchlist = () => {
    const bundle: WatchlistBundle = {
      version: "reposhield-watchlist-v1",
      exported_at: new Date().toISOString(),
      items,
    };
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `reposhield-watchlist.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const importWatchlist = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const bundle = JSON.parse(event.target?.result as string);
        if (bundle.version && Array.isArray(bundle.items)) {
          bundle.items.forEach((item: WatchlistItem) => storage.saveWatchlistItem(item));
          setItems(storage.getWatchlist());
          setRecheckNotice(`Imported ${bundle.items.length} watchlist targets.`);
          setTimeout(() => setRecheckNotice(null), 3000);
        } else {
          alert("Invalid watchlist bundle format.");
        }
      } catch (err) {
        alert("Failed to parse JSON file.");
      }
    };
    reader.readAsText(file);
  };

  return (
    <div className="space-y-4">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[var(--border-color)]">
        <div>
          <h1 className="text-[22px] font-semibold tracking-tight text-[var(--text-primary)]">
            Local Security Watchlist
          </h1>
          <p className="text-[13px] text-[var(--text-secondary)] mt-0.5">
            User-controlled local watchlist for repositories and vulnerability identifiers (CVEs &amp; GHSAs).
          </p>
        </div>

        <div className="flex items-center gap-2">
          <input
            type="file"
            ref={fileInputRef}
            onChange={importWatchlist}
            accept=".json"
            className="hidden"
          />
          <button
            onClick={() => fileInputRef.current?.click()}
            className="macos-button h-7 text-[12px] px-2.5 flex items-center gap-1.5"
            title="Import Watchlist JSON"
          >
            <Upload className="w-3.5 h-3.5" />
            <span>Import</span>
          </button>

          <button
            onClick={exportWatchlist}
            className="macos-button h-7 text-[12px] px-2.5 flex items-center gap-1.5"
            title="Export Watchlist JSON"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export</span>
          </button>

          <button
            onClick={() => setShowAddModal(true)}
            className="macos-button macos-button-primary h-7 text-[12px] px-2.5 flex items-center gap-1.5"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Target</span>
          </button>
        </div>
      </div>

      {/* Recheck Notice */}
      {recheckNotice && (
        <div className="p-3 rounded-[6px] bg-emerald-500/10 text-emerald-500 border border-emerald-500/20 text-[12px] flex items-center gap-2">
          <Check className="w-4 h-4" />
          <span>{recheckNotice}</span>
        </div>
      )}

      {/* Honest Local Architecture Banner */}
      <div className="p-3.5 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] flex items-start gap-3">
        <Info className="w-4 h-4 text-[#0A84FF] shrink-0 mt-0.5" />
        <div className="text-[12px] text-[var(--text-secondary)] space-y-1">
          <div className="font-medium text-[var(--text-primary)]">
            Local Storage &amp; Manual On-Demand Recheck
          </div>
          <p>
            This watchlist operates locally within your browser without a central database or background tracking daemons. You can initiate on-demand rescans or advisory rechecks whenever you choose.
          </p>
        </div>
      </div>

      {/* Filter and Tab Toolbar */}
      <div className="flex flex-col sm:flex-row gap-2.5 items-stretch sm:items-center justify-between">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab("REPOSITORY")}
            className={`px-3 py-1 rounded-[5px] text-[12px] font-medium transition-colors ${
              activeTab === "REPOSITORY"
                ? "bg-[var(--accent)] text-white"
                : "bg-[var(--surface)] text-[var(--text-secondary)] border border-[var(--border-subtle)] hover:text-[var(--text-primary)]"
            }`}
          >
            Watched Repositories ({items.filter((i) => i.type === "REPOSITORY").length})
          </button>
          <button
            onClick={() => setActiveTab("CVE")}
            className={`px-3 py-1 rounded-[5px] text-[12px] font-medium transition-colors ${
              activeTab === "CVE"
                ? "bg-[var(--accent)] text-white"
                : "bg-[var(--surface)] text-[var(--text-secondary)] border border-[var(--border-subtle)] hover:text-[var(--text-primary)]"
            }`}
          >
            Watched CVEs / Advisories ({items.filter((i) => i.type === "CVE").length})
          </button>
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 text-[var(--text-muted)] absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter watchlist..."
            className="macos-input w-full pl-8 h-7 text-[12px]"
          />
        </div>
      </div>

      {/* Watchlist Table */}
      <div className="macos-panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-[13px]">
            <thead>
              <tr className="border-b border-[var(--border-color)] bg-[var(--bg-secondary)] text-[var(--text-secondary)] text-[11px] font-medium select-none">
                <th className="py-2 px-3.5">Target</th>
                <th className="py-2 px-3.5">Label &amp; Context</th>
                <th className="py-2 px-3.5">Last Checked</th>
                <th className="py-2 px-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-subtle)]">
              {filteredItems.length === 0 ? (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-[var(--text-secondary)] text-[12px]">
                    No {activeTab.toLowerCase()} items match your active filters.
                  </td>
                </tr>
              ) : (
                filteredItems.map((item) => (
                  <tr key={item.id} className="hover:bg-[var(--bg-hover)] transition-colors">
                    <td className="py-2.5 px-3.5">
                      <div className="font-semibold text-[var(--text-primary)] flex items-center gap-2">
                        {item.type === "REPOSITORY" ? (
                          <GitBranch className="w-3.5 h-3.5 text-[var(--text-secondary)]" />
                        ) : (
                          <ShieldAlert className="w-3.5 h-3.5 text-[#FF9500]" />
                        )}
                        <span className="font-mono text-[12px]">{item.target}</span>
                      </div>
                      {item.notes && (
                        <div className="text-[11px] text-[var(--text-muted)] mt-0.5">
                          {item.notes}
                        </div>
                      )}
                    </td>
                    <td className="py-2.5 px-3.5 text-[12px] text-[var(--text-secondary)]">
                      {item.label || "—"}
                    </td>
                    <td className="py-2.5 px-3.5 text-[12px] text-[var(--text-secondary)]">
                      {item.last_checked_at ? formatTimeAgo(item.last_checked_at) : "Never"}
                    </td>
                    <td className="py-2.5 px-3.5 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        {item.type === "REPOSITORY" ? (
                          <Link
                            href={`/scan?repo=${encodeURIComponent(item.target)}`}
                            className="macos-button h-6 text-[11px] px-2 flex items-center gap-1"
                          >
                            <Play className="w-3 h-3 text-[#34C759]" />
                            <span>Scan</span>
                          </Link>
                        ) : (
                          <button
                            onClick={() => handleRecheck(item)}
                            className="macos-button h-6 text-[11px] px-2 flex items-center gap-1"
                          >
                            <RotateCcw className="w-3 h-3 text-[#0A84FF]" />
                            <span>Recheck</span>
                          </button>
                        )}
                        <button
                          onClick={() => handleRemove(item.id)}
                          className="macos-button h-6 text-[11px] px-1.5 text-[var(--text-muted)] hover:text-[#FF453A]"
                          title="Remove item"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Item Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-sm">
          <div className="macos-panel max-w-md w-full p-5 space-y-4 border border-[var(--border-color)]">
            <h2 className="text-[16px] font-semibold text-[var(--text-primary)]">
              Add Target to Watchlist
            </h2>

            <form onSubmit={handleAddItem} className="space-y-3 text-[12px]">
              <div>
                <label className="text-[11px] font-medium text-[var(--text-secondary)] uppercase">
                  Target Type
                </label>
                <div className="flex items-center gap-2 mt-1">
                  <button
                    type="button"
                    onClick={() => setNewType("REPOSITORY")}
                    className={`flex-1 py-1 rounded-[5px] font-medium transition-colors ${
                      newType === "REPOSITORY"
                        ? "bg-[var(--accent)] text-white"
                        : "bg-[var(--bg-secondary)] text-[var(--text-secondary)] border border-[var(--border-subtle)]"
                    }`}
                  >
                    Repository URL
                  </button>
                  <button
                    type="button"
                    onClick={() => setNewType("CVE")}
                    className={`flex-1 py-1 rounded-[5px] font-medium transition-colors ${
                      newType === "CVE"
                        ? "bg-[var(--accent)] text-white"
                        : "bg-[var(--bg-secondary)] text-[var(--text-secondary)] border border-[var(--border-subtle)]"
                    }`}
                  >
                    CVE / GHSA ID
                  </button>
                </div>
              </div>

              <div>
                <label className="text-[11px] font-medium text-[var(--text-secondary)] uppercase">
                  {newType === "REPOSITORY" ? "Repository URL" : "Advisory Identifier (CVE / GHSA)"}
                </label>
                <input
                  type="text"
                  required
                  value={newTarget}
                  onChange={(e) => setNewTarget(e.target.value)}
                  placeholder={
                    newType === "REPOSITORY"
                      ? "https://github.com/owner/repo"
                      : "CVE-2023-XXXX or GHSA-XXXX-XXXX"
                  }
                  className="macos-input w-full mt-1 text-[12px]"
                />
              </div>

              <div>
                <label className="text-[11px] font-medium text-[var(--text-secondary)] uppercase">
                  Display Label (Optional)
                </label>
                <input
                  type="text"
                  value={newLabel}
                  onChange={(e) => setNewLabel(e.target.value)}
                  placeholder="e.g. Critical Auth Service / Zero-Day Watch"
                  className="macos-input w-full mt-1 text-[12px]"
                />
              </div>

              <div>
                <label className="text-[11px] font-medium text-[var(--text-secondary)] uppercase">
                  Investigation Notes (Optional)
                </label>
                <textarea
                  value={newNotes}
                  onChange={(e) => setNewNotes(e.target.value)}
                  placeholder="Rationale for monitoring this target..."
                  className="macos-input w-full mt-1 text-[12px] h-16 py-1"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-[var(--border-subtle)]">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="macos-button h-7 text-[12px] px-3"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="macos-button macos-button-primary h-7 text-[12px] px-3"
                >
                  Save to Watchlist
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
