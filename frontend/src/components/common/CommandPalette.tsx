"use client";

import React, { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import {
  Search,
  LayoutDashboard,
  SearchCode,
  FileCheck2,
  Package,
  Network,
  ShieldCheck,
  Globe,
  Server,
  Wrench,
  TrendingDown,
  Rocket,
  Layers,
  FileText,
  Settings,
  HelpCircle,
  Sun,
  Moon,
  Radar,
  ClipboardCheck,
  Milestone,
  PackageCheck,
  ArrowRight,
  CornerDownLeft,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { ScanResult } from "@/lib/types";
import { useTheme } from "@/components/common/ThemeContext";
import { AnimatedDialog } from "@/components/motion";

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
}

interface ActionItem {
  id: string;
  label: string;
  category: "Navigation" | "Actions" | "Preferences";
  icon: any;
  href?: string;
  action?: () => void;
  shortcut?: string;
}

export function CommandPalette({ isOpen, onClose }: CommandPaletteProps) {
  const router = useRouter();
  const { resolvedTheme, toggleTheme } = useTheme();
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [recentScans, setRecentScans] = useState<ScanResult[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const baseActions: ActionItem[] = [
    { id: "dash", label: "Overview Dashboard", category: "Navigation", icon: LayoutDashboard, href: "/dashboard" },
    { id: "scan", label: "Start New Scan", category: "Actions", icon: SearchCode, href: "/scan", shortcut: "⌘N" },
    { id: "coverage", label: "Security Coverage Map (9 Engines)", category: "Navigation", icon: Radar, href: "/security-coverage" },
    { id: "timeline", label: "Vulnerability Origin & Incident Timeline", category: "Navigation", icon: Milestone, href: "/timeline" },
    { id: "watchlist", label: "Local Security Watchlist (Repositories & CVEs)", category: "Navigation", icon: FileCheck2, href: "/watchlist" },
    { id: "test-lab", label: "Safe Security Test Lab (Fixture Benchmark)", category: "Actions", icon: Wrench, href: "/test-lab" },
    { id: "review", label: "Security Review Workbench (Triage & Notes)", category: "Actions", icon: ClipboardCheck, href: "/review-workbench" },
    { id: "supply-chain", label: "Software Supply Chain Trust Center", category: "Navigation", icon: PackageCheck, href: "/supply-chain" },
    { id: "exploitability", label: "Exploitability Evidence Board (6 Dimensions)", category: "Navigation", icon: Globe, href: "/exploitability" },
    { id: "dataflow", label: "Source-to-Sink Data Flow Tracing (SAST)", category: "Navigation", icon: SearchCode, href: "/code-analysis" },
    { id: "findings", label: "Security Findings", category: "Navigation", icon: FileCheck2, href: "/results" },
    { id: "attacks", label: "Attack Path Intelligence", category: "Navigation", icon: Network, href: "/attack-paths" },
    { id: "posture", label: "Security Posture & Compliance", category: "Navigation", icon: ShieldCheck, href: "/security-posture" },
    { id: "deps", label: "Dependency Intelligence (SCA)", category: "Navigation", icon: Package, href: "/dependencies" },
    { id: "api-sec", label: "API & Endpoint Security", category: "Navigation", icon: Globe, href: "/api-security" },
    { id: "container", label: "Container Image & Dockerfile Inspector", category: "Navigation", icon: Server, href: "/container-inspector" },
    { id: "infra", label: "Infrastructure Security (IaC)", category: "Navigation", icon: Server, href: "/infrastructure" },
    { id: "compliance", label: "Compliance Evidence Pack (OWASP ASVS / NIST SSDF)", category: "Navigation", icon: FileCheck2, href: "/compliance" },
    { id: "fixes", label: "Fix Validation Sandbox", category: "Actions", icon: Wrench, href: "/fix-validation" },
    { id: "debt", label: "Security Debt & SLA Tracker", category: "Navigation", icon: TrendingDown, href: "/security-debt" },
    { id: "release", label: "Release Readiness Gate", category: "Actions", icon: Rocket, href: "/release-readiness" },
    { id: "sbom", label: "SBOM & VEX Center", category: "Navigation", icon: Layers, href: "/sbom-vex" },
    { id: "reports", label: "Security Reports & Exports", category: "Actions", icon: FileText, href: "/reports" },
    { id: "how-it-works", label: "How RepoShield Works (Architecture & Engines)", category: "Navigation", icon: HelpCircle, href: "/how-it-works" },
    { id: "web-audit", label: "Live Website Security Audit", category: "Actions", icon: Globe, href: "/website-security" },
    { id: "settings", label: "Application Settings", category: "Preferences", icon: Settings, href: "/settings" },
    {
      id: "theme",
      label: `Switch Appearance to ${resolvedTheme === "dark" ? "Light" : "Dark"} Mode`,
      category: "Preferences",
      icon: resolvedTheme === "dark" ? Sun : Moon,
      action: toggleTheme,
      shortcut: "⌘T",
    },
  ];

  useEffect(() => {
    if (isOpen) {
      setQuery("");
      setSelectedIndex(0);
      setRecentScans(storage.getScanHistory().slice(0, 3));
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isOpen]);

  const filteredActions = baseActions.filter((act) =>
    act.label.toLowerCase().includes(query.toLowerCase()) ||
    act.category.toLowerCase().includes(query.toLowerCase())
  );

  const totalItems = filteredActions.length;

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        if (isOpen) onClose();
      }
      if (!isOpen) return;

      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        setSelectedIndex((prev) => (totalItems > 0 ? (prev + 1) % totalItems : 0));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setSelectedIndex((prev) => (totalItems > 0 ? (prev - 1 + totalItems) % totalItems : 0));
      } else if (e.key === "Enter") {
        e.preventDefault();
        const selected = filteredActions[selectedIndex];
        if (selected) {
          executeAction(selected);
        }
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose, totalItems, filteredActions, selectedIndex]);

  const executeAction = (action: ActionItem) => {
    onClose();
    if (action.action) {
      action.action();
    } else if (action.href) {
      router.push(action.href);
    }
  };

  return (
    <AnimatedDialog
      isOpen={isOpen}
      onClose={onClose}
      position="top"
      className="w-full max-w-xl bg-[var(--surface)] border border-[var(--border)] rounded-[var(--radius-lg)] shadow-[var(--shadow-dialog)] overflow-hidden flex flex-col"
      ariaLabel="Command Palette"
    >
        {/* Search Input Bar (Raycast / Spotlight Style) */}
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-[var(--border)] bg-[var(--surface)]">
          <Search className="w-4 h-4 text-[var(--foreground-secondary)] flex-shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
            placeholder="Type a command or search views..."
            className="w-full bg-transparent text-[13.5px] text-[var(--foreground)] placeholder:text-[var(--foreground-tertiary)] focus:outline-none"
          />
          <kbd className="hidden sm:inline-flex items-center px-1.5 py-0.5 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border)] text-[10px] font-mono text-[var(--foreground-tertiary)]">
            ESC
          </kbd>
        </div>

        {/* Results List */}
        <div
          ref={listRef}
          className="max-h-80 overflow-y-auto p-2 space-y-0.5"
          tabIndex={-1}
        >
          {filteredActions.length === 0 ? (
            <div className="p-8 text-center text-[13px] text-[var(--foreground-secondary)]">
              No matching commands found for &ldquo;{query}&rdquo;
            </div>
          ) : (
            filteredActions.map((action, idx) => {
              const Icon = action.icon;
              const isSelected = idx === selectedIndex;

              return (
                <button
                  key={action.id}
                  onClick={() => executeAction(action)}
                  onMouseEnter={() => setSelectedIndex(idx)}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-[var(--radius-sm)] text-[13px] transition-colors ${
                    isSelected
                      ? "bg-[var(--primary)] text-white"
                      : "text-[var(--foreground)] hover:bg-[var(--surface-hover)]"
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <Icon
                      className={`w-4 h-4 flex-shrink-0 ${
                        isSelected ? "text-white" : "text-[var(--foreground-secondary)]"
                      }`}
                    />
                    <span className="truncate">{action.label}</span>
                  </div>

                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span
                      className={`text-[11px] font-mono uppercase ${
                        isSelected ? "text-white/80" : "text-[var(--foreground-tertiary)]"
                      }`}
                    >
                      {action.category}
                    </span>
                    {action.shortcut && (
                      <kbd
                        className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                          isSelected
                            ? "bg-white/20 text-white"
                            : "bg-[var(--surface-secondary)] text-[var(--foreground-secondary)] border border-[var(--border)]"
                        }`}
                      >
                        {action.shortcut}
                      </kbd>
                    )}
                    {isSelected && <CornerDownLeft className="w-3.5 h-3.5 text-white/90" />}
                  </div>
                </button>
              );
            })
          )}
        </div>

        {/* Footer Bar with Keyboard Hints */}
        <div className="px-4 py-2 bg-[var(--surface-secondary)] border-t border-[var(--border)] flex items-center justify-between text-[11px] text-[var(--foreground-tertiary)] select-none">
          <div className="flex items-center gap-3">
            <span>
              <kbd className="font-mono">↑</kbd> <kbd className="font-mono">↓</kbd> Navigate
            </span>
            <span>
              <kbd className="font-mono">↵</kbd> Select
            </span>
            <span>
              <kbd className="font-mono">esc</kbd> Dismiss
            </span>
          </div>
          <span>RepoShield Security Engine</span>
        </div>
    </AnimatedDialog>
  );
}
