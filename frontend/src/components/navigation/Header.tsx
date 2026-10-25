"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Search,
  ChevronRight,
  SearchCode,
  GitBranch,
  PanelLeft,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { ScanResult } from "@/lib/types";
import { CommandPalette } from "@/components/common/CommandPalette";
import { ThemeToggle } from "@/components/common/ThemeContext";
import { useSidebar } from "./SidebarContext";
import { getSectionForRoute } from "@/lib/navigation";

const ROUTE_NAMES: Record<string, string> = {
  "/": "Overview",
  "/dashboard": "Overview",
  "/scan": "New Scan",
  "/security-coverage": "Security Coverage Map",
  "/timeline": "Incident Timeline",
  "/review-workbench": "Review Workbench",
  "/repository": "Repositories",
  "/results": "Findings",
  "/history": "Scan History",
  "/pr-checks": "Pull Request Checks",
  "/attack-paths": "Attack Paths",
  "/security-posture": "Security Posture",
  "/supply-chain": "Supply Chain Trust Center",
  "/dependencies": "Dependency Intelligence",
  "/api-security": "API Security",
  "/infrastructure": "Infrastructure Security",
  "/fix-validation": "Fix Validation",
  "/security-debt": "Security Debt",
  "/release-readiness": "Release Readiness",
  "/sbom-vex": "SBOM & VEX",
  "/reports": "Reports",
  "/settings": "Settings",
  "/how-it-works": "How It Works",
  "/website-security": "Live Website Audit",
  "/secrets": "Secret Leaks",
  "/policies": "Security Policies",
  "/test-lab": "Safe Security Test Lab",
  "/watchlist": "Security Watchlist",
  "/exploitability": "Exploitability Evidence Board",
  "/code-analysis": "Source Data Flow Analysis",
  "/container-inspector": "Container Inspector",
  "/compliance": "Compliance Evidence Pack",
};

export function Header() {
  const pathname = usePathname();
  const { toggleCollapsed, toggleMobileOpen } = useSidebar();
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false);

  useEffect(() => {
    const saved = storage.getScanHistory();
    setHistory(saved);
    if (saved.length > 0) {
      setSelectedScan(saved[0]);
    }
  }, [pathname]);

  const currentSection = getSectionForRoute(pathname);
  const currentRouteName =
    ROUTE_NAMES[pathname] || (pathname.startsWith("/findings/") ? "Finding Details" : "Console");

  const handleToggleSidebar = () => {
    if (typeof window !== "undefined" && window.innerWidth < 768) {
      toggleMobileOpen();
    } else {
      toggleCollapsed();
    }
  };

  return (
    <>
      <header className="h-14 px-4 md:px-7 flex items-center justify-between sticky top-0 z-30 select-none bg-[var(--background)] border-b border-[var(--border)] transition-colors duration-[var(--motion-fast)]">
        {/* Left: Sidebar Toggle, Breadcrumbs & Target Repository Context */}
        <div className="flex items-center gap-2.5 text-[13px]">
          {/* macOS Native Sidebar Toggle Button */}
          <button
            onClick={handleToggleSidebar}
            suppressHydrationWarning
            className="p-1.5 rounded-[var(--radius-sm)] text-[var(--foreground-tertiary)] hover:text-[var(--foreground-primary)] hover:bg-[var(--surface-hover)] transition-colors"
            title="Toggle Sidebar (⌘B)"
            aria-label="Toggle Sidebar"
          >
            <PanelLeft className="w-4 h-4" />
          </button>

          <nav className="flex items-center gap-1.5 text-[var(--foreground-secondary)]">
            <Link
              href="/dashboard"
              className="hover:text-[var(--foreground-primary)] transition-colors text-[13px]"
            >
              RepoShield
            </Link>
            {currentSection && currentSection.id !== "overview" && (
              <>
                <ChevronRight className="w-3.5 h-3.5 text-[var(--foreground-tertiary)]" />
                <Link
                  href={currentSection.href}
                  className="hover:text-[var(--foreground-primary)] transition-colors text-[13px] hidden sm:inline"
                >
                  {currentSection.shortName}
                </Link>
              </>
            )}
            <ChevronRight className="w-3.5 h-3.5 text-[var(--foreground-tertiary)]" />
            <span className="text-[var(--foreground-primary)] font-medium text-[13px]">
              {currentRouteName}
            </span>
          </nav>

          {/* Target Repository Quick Context Selector */}
          {history.length > 0 && selectedScan && (
            <div className="hidden lg:flex items-center gap-1.5 ml-2.5 pl-2.5 border-l border-[var(--border-subtle)]">
              <GitBranch className="w-3.5 h-3.5 text-[var(--foreground-tertiary)]" />
              <select
                value={selectedScan.scan_id}
                onChange={(e) => {
                  const s = history.find((x) => x.scan_id === e.target.value);
                  if (s) {
                    setSelectedScan(s);
                    storage.saveScan(s);
                  }
                }}
                suppressHydrationWarning
                className="h-7 px-2 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border)] text-[12px] font-mono text-[var(--foreground-primary)] focus:outline-none focus:border-[var(--primary)] cursor-pointer transition-colors"
              >
                {history.map((s) => (
                  <option key={s.scan_id} value={s.scan_id}>
                    {s.owner}/{s.repo} ({s.branch})
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>

        {/* Right: Quick Search, Theme Toggle & New Scan Action */}
        <div className="flex items-center gap-2">
          {/* Quick Search Trigger */}
          <button
            onClick={() => setIsCommandPaletteOpen(true)}
            suppressHydrationWarning
            className="flex items-center gap-2 h-8 px-2.5 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] hover:bg-[var(--surface-hover)] border border-[var(--border)] text-[12px] text-[var(--foreground-secondary)] hover:text-[var(--foreground-primary)] transition-colors"
            title="Search commands (⌘K)"
          >
            <Search className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Search</span>
            <kbd className="hidden sm:inline-flex items-center px-1.5 py-0.5 rounded-[3px] bg-[var(--surface)] border border-[var(--border-subtle)] text-[10px] font-mono text-[var(--foreground-tertiary)]">
              ⌘K
            </kbd>
          </button>

          {/* Theme Toggle Button */}
          <ThemeToggle />

          {/* New Scan Primary Action */}
          <Link
            href="/scan"
            className="btn-primary h-8 px-3 text-[12px]"
          >
            <SearchCode className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Scan Repo</span>
          </Link>
        </div>
      </header>

      {/* Global Command Palette */}
      <CommandPalette
        isOpen={isCommandPaletteOpen}
        onClose={() => setIsCommandPaletteOpen(false)}
      />
    </>
  );
}
