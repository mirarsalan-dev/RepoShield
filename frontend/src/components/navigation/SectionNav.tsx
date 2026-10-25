"use client";

import React, { useRef, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { ChevronRight, Sparkles } from "lucide-react";
import { NAV_SECTIONS, getSectionForRoute, NavSection, NavItem } from "@/lib/navigation";

export function SectionNav() {
  const pathname = usePathname();
  const currentSection = getSectionForRoute(pathname);
  const scrollContainerRef = useRef<HTMLDivElement>(null);

  // Auto-scroll active item into view on navigation
  useEffect(() => {
    if (!scrollContainerRef.current) return;
    const activeEl = scrollContainerRef.current.querySelector('[data-active="true"]');
    if (activeEl) {
      activeEl.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "center" });
    }
  }, [pathname]);

  // If on Overview/Dashboard, render a clean Section Hub switch bar
  if (!currentSection || currentSection.id === "overview") {
    return (
      <div className="w-full bg-[var(--background)]/80 backdrop-blur-md border-b border-[var(--border)] sticky top-14 z-20 transition-colors select-none">
        <div className="max-w-7xl mx-auto px-4 md:px-7 py-2 flex items-center justify-between gap-4 overflow-x-auto scrollbar-none">
          <div className="flex items-center gap-2 text-[12px] text-[var(--foreground-secondary)] flex-shrink-0">
            <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-[var(--surface-secondary)] border border-[var(--border-subtle)] text-[11px] font-mono text-[var(--foreground-tertiary)]">
              <Sparkles className="w-3 h-3 text-[var(--primary)]" />
              Navigation Hub
            </span>
            <span className="hidden sm:inline text-[var(--foreground-tertiary)]">•</span>
            <span className="hidden sm:inline text-[11.5px]">Jump directly to security capability centers:</span>
          </div>

          <nav className="flex items-center gap-1.5 flex-shrink-0" aria-label="Section Quick Jump">
            {NAV_SECTIONS.filter((s) => s.id !== "overview").map((sec) => {
              const Icon = sec.icon;
              return (
                <Link
                  key={sec.id}
                  href={sec.href}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-[var(--radius-sm)] text-[11.5px] font-medium text-[var(--foreground-secondary)] hover:text-[var(--foreground-primary)] hover:bg-[var(--surface-hover)] border border-transparent hover:border-[var(--border-subtle)] transition-all duration-[var(--motion-fast)]"
                >
                  <Icon className="w-3.5 h-3.5 text-[var(--primary)] flex-shrink-0" />
                  <span>{sec.shortName}</span>
                  {sec.badge && (
                    <span className="text-[9.5px] px-1 py-0.2 rounded font-mono bg-[var(--surface-secondary)] text-[var(--foreground-tertiary)]">
                      {sec.badge.split(" ")[0]}
                    </span>
                  )}
                </Link>
              );
            })}
          </nav>
        </div>
      </div>
    );
  }

  // Active section local navigation bar
  const SectionIcon = currentSection.icon;
  const isDirectFinding = pathname.startsWith("/findings/");

  return (
    <div className="w-full bg-[var(--background)]/85 backdrop-blur-md border-b border-[var(--border)] sticky top-14 z-20 transition-colors select-none">
      <div className="max-w-7xl mx-auto px-4 md:px-7 py-2 flex flex-col md:flex-row md:items-center justify-between gap-2.5">
        
        {/* Left: Section Identity Badge */}
        <div className="flex items-center gap-2 flex-shrink-0">
          <Link
            href={currentSection.href}
            className="group flex items-center gap-1.5 px-2.5 py-1 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border-subtle)] hover:border-[var(--border)] transition-colors"
            title={currentSection.description}
          >
            <SectionIcon className="w-3.5 h-3.5 text-[var(--primary)] flex-shrink-0 transition-transform group-hover:scale-105" />
            <span className="text-[12px] font-semibold text-[var(--foreground-primary)] tracking-tight">
              {currentSection.name}
            </span>
            {currentSection.badge && (
              <span className="ml-1 text-[10px] font-mono px-1.5 py-0.2 rounded bg-[var(--primary-subtle)] text-[var(--primary)]">
                {currentSection.badge}
              </span>
            )}
          </Link>
          <ChevronRight className="w-3.5 h-3.5 text-[var(--foreground-tertiary)] hidden sm:block" />
        </div>

        {/* Right / Center: macOS Segmented Control Local Navigation Strip */}
        <div className="relative min-w-0 flex-1 md:max-w-4xl overflow-hidden">
          <nav
            ref={scrollContainerRef}
            className="flex items-center gap-1 p-1 rounded-lg bg-[var(--surface-secondary)] border border-[var(--border-subtle)] overflow-x-auto scrollbar-none"
            aria-label={`${currentSection.name} Local Navigation`}
          >
            {currentSection.items.map((item: NavItem) => {
              const Icon = item.icon;
              // Check active status
              const isExact = pathname === item.href;
              const isNestedFindings = item.href === "/results" && isDirectFinding;
              const isActive = isExact || isNestedFindings;

              return (
                <Link
                  key={item.href}
                  href={item.href}
                  data-active={isActive ? "true" : "false"}
                  className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-[var(--radius-sm)] text-[12px] whitespace-nowrap transition-all duration-[var(--motion-fast)] ${
                    isActive
                      ? "bg-[var(--surface)] text-[var(--primary)] font-semibold shadow-xs border border-[var(--border)]"
                      : "text-[var(--foreground-secondary)] hover:text-[var(--foreground-primary)] hover:bg-[var(--surface-hover)] border border-transparent"
                  }`}
                  title={item.description || item.label}
                >
                  <Icon
                    className={`w-3.5 h-3.5 flex-shrink-0 ${
                      isActive ? "text-[var(--primary)]" : "text-[var(--foreground-tertiary)]"
                    }`}
                  />
                  <span>{item.shortLabel || item.label}</span>
                  {item.badge && (
                    <span
                      className={`text-[9.5px] px-1 py-0.2 rounded font-mono ${
                        isActive
                          ? "bg-[var(--primary-subtle)] text-[var(--primary)] font-semibold"
                          : "bg-[var(--surface)] text-[var(--foreground-tertiary)]"
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </Link>
              );
            })}
          </nav>
        </div>

      </div>
    </div>
  );
}
