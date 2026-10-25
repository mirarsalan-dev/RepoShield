"use client";

import React, { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  Globe,
  BookOpen,
  HardDrive,
  X,
  ExternalLink,
} from "lucide-react";
import { api } from "@/lib/api";
import { SystemHealth } from "@/lib/types";
import { ShieldLogo, MacTrafficLights } from "@/components/common/Icons";
import { DocumentationModal } from "@/components/common/DocumentationModal";
import { useSidebar } from "./SidebarContext";
import {
  NAV_SECTIONS,
  getSectionForRoute,
  isRouteInSection,
  NavSection,
  NavItem,
} from "@/lib/navigation";

export function Sidebar() {
  const pathname = usePathname();
  const router = useRouter();
  const { isCollapsed, isMobileOpen, toggleCollapsed, closeMobile } = useSidebar();
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [isBackendOnline, setIsBackendOnline] = useState<boolean>(true);
  const [isDocsOpen, setIsDocsOpen] = useState(false);

  // Track expanded state of sections: default to only the active section being expanded
  const activeSection = useMemo(() => getSectionForRoute(pathname), [pathname]);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>(() => {
    const initial: Record<string, boolean> = {};
    const current = getSectionForRoute(pathname);
    if (current && current.id !== "overview") {
      initial[current.id] = true;
    }
    return initial;
  });

  // Automatically ensure active section is expanded when pathname changes
  useEffect(() => {
    if (activeSection && activeSection.id !== "overview") {
      setExpandedSections((prev) => ({
        ...prev,
        [activeSection.id]: true,
      }));
    }
  }, [activeSection]);

  const toggleSection = (sectionId: string, e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setExpandedSections((prev) => ({
      ...prev,
      [sectionId]: !prev[sectionId],
    }));
  };

  useEffect(() => {
    let isMounted = true;
    async function checkStatus() {
      try {
        const res = await api.getHealth();
        if (isMounted) {
          setHealth(res);
          setIsBackendOnline(true);
        }
      } catch {
        if (isMounted) {
          setIsBackendOnline(false);
        }
      }
    }

    checkStatus();
    const interval = setInterval(checkStatus, 20000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  const renderNav = (collapsed: boolean, onMobile = false) => (
    <div className="flex flex-col h-full select-none text-[13px] bg-[var(--sidebar)] border-r border-[var(--border)] transition-colors duration-[var(--motion-fast)]">
      {/* Top Header / macOS Traffic Lights */}
      <div className="h-14 px-3.5 flex items-center justify-between border-b border-[var(--border-subtle)] flex-shrink-0 bg-[var(--sidebar)]">
        <div className="flex items-center gap-2.5">
          <MacTrafficLights />
          {(!collapsed || onMobile) && (
            <div className="flex items-center gap-1.5 pl-1.5">
              <ShieldLogo className="w-4 h-4 text-[var(--primary)]" />
              <span className="font-semibold text-[13px] text-[var(--foreground-primary)] tracking-tight">
                RepoShield
              </span>
            </div>
          )}
        </div>

        {onMobile ? (
          <button
            onClick={closeMobile}
            suppressHydrationWarning
            className="p-1 rounded-[var(--radius-sm)] text-[var(--foreground-secondary)] hover:text-[var(--foreground-primary)] hover:bg-[var(--surface-hover)] transition-colors"
            aria-label="Close menu"
          >
            <X className="w-4 h-4" />
          </button>
        ) : (
          <button
            onClick={toggleCollapsed}
            suppressHydrationWarning
            className="hidden md:flex p-1 rounded-[var(--radius-sm)] hover:bg-[var(--surface-hover)] text-[var(--foreground-tertiary)] hover:text-[var(--foreground-primary)] transition-colors"
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            aria-label="Toggle sidebar collapse"
          >
            {collapsed ? <ChevronRight className="w-3.5 h-3.5" /> : <ChevronLeft className="w-3.5 h-3.5" />}
          </button>
        )}
      </div>

      {/* Primary Section Hubs (Clean, Decluttered Global Navigation) */}
      <div className="flex-1 py-3 px-2 space-y-1.5 overflow-y-auto">
        {NAV_SECTIONS.map((section) => {
          const SectionIcon = section.icon;
          const isSectionActive = isRouteInSection(pathname, section.id);
          const isOverview = section.id === "overview";
          const isExpanded = isOverview ? false : (expandedSections[section.id] ?? false);

          if (collapsed && !onMobile) {
            // Icon-only collapsed state
            return (
              <Link
                key={section.id}
                href={section.href}
                className={`flex items-center justify-center w-10 h-10 mx-auto rounded-[var(--radius-sm)] transition-all ${
                  isSectionActive
                    ? "bg-[var(--primary-subtle)] text-[var(--primary)] font-medium shadow-xs border border-[var(--primary)]/20"
                    : "text-[var(--foreground-secondary)] hover:text-[var(--foreground-primary)] hover:bg-[var(--surface-hover)] border border-transparent"
                }`}
                title={`${section.name} (${section.items.length} options)`}
              >
                <SectionIcon className={`w-4 h-4 ${isSectionActive ? "text-[var(--primary)]" : ""}`} />
              </Link>
            );
          }

          return (
            <div key={section.id} className="space-y-0.5">
              {/* Primary Section Header Row */}
              <div
                className={`group flex items-center justify-between px-2.5 py-1.5 rounded-[var(--radius-sm)] cursor-pointer transition-all duration-[var(--motion-fast)] ${
                  isSectionActive
                    ? "bg-[var(--surface-elevated)] text-[var(--foreground-primary)] font-medium shadow-xs border border-[var(--border)]"
                    : "text-[var(--foreground-secondary)] hover:text-[var(--foreground-primary)] hover:bg-[var(--surface-hover)] border border-transparent"
                }`}
                onClick={() => {
                  if (onMobile) closeMobile();
                  router.push(section.href);
                }}
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <SectionIcon
                    className={`w-4 h-4 flex-shrink-0 transition-colors ${
                      isSectionActive ? "text-[var(--primary)]" : "text-[var(--foreground-tertiary)] group-hover:text-[var(--foreground-primary)]"
                    }`}
                  />
                  <span className="truncate text-[12.5px] tracking-tight">{section.name}</span>
                </div>

                <div className="flex items-center gap-1.5 flex-shrink-0">
                  {section.badge && (
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[var(--surface-secondary)] text-[var(--foreground-tertiary)]">
                      {section.badge.split(" ")[0]}
                    </span>
                  )}
                  {!isOverview && (
                    <button
                      type="button"
                      onClick={(e) => toggleSection(section.id, e)}
                      className="p-0.5 rounded hover:bg-[var(--surface-secondary)] text-[var(--foreground-tertiary)] hover:text-[var(--foreground-primary)] transition-colors"
                      title={isExpanded ? "Collapse section" : "Expand section"}
                      aria-label="Toggle section"
                    >
                      {isExpanded ? (
                        <ChevronDown className="w-3.5 h-3.5" />
                      ) : (
                        <ChevronRight className="w-3.5 h-3.5" />
                      )}
                    </button>
                  )}
                </div>
              </div>

              {/* Local Sub-Navigation nested under section (Only shown when expanded) */}
              {isExpanded && !isOverview && (
                <div className="pl-4 pr-1 py-1 space-y-0.5 border-l-2 border-[var(--border-subtle)] ml-3.5 my-1">
                  {section.items.map((item) => {
                    const ItemIcon = item.icon;
                    const isExact = pathname === item.href;
                    const isNestedFindings = item.href === "/results" && pathname.startsWith("/findings/");
                    const isItemActive = isExact || isNestedFindings;

                    return (
                      <Link
                        key={item.href}
                        href={item.href}
                        onClick={() => {
                          if (onMobile) closeMobile();
                        }}
                        className={`flex items-center justify-between px-2 py-1 rounded-[var(--radius-sm)] text-[12px] transition-all duration-[var(--motion-fast)] ${
                          isItemActive
                            ? "bg-[var(--primary-subtle)] text-[var(--primary-hover)] font-medium border border-[var(--primary)]/20"
                            : "text-[var(--foreground-secondary)] hover:text-[var(--foreground-primary)] hover:bg-[var(--surface-hover)] border border-transparent"
                        }`}
                        title={item.description || item.label}
                      >
                        <div className="flex items-center gap-2 min-w-0">
                          <ItemIcon
                            className={`w-3.5 h-3.5 flex-shrink-0 ${
                              isItemActive ? "text-[var(--primary)]" : "text-[var(--foreground-tertiary)]"
                            }`}
                          />
                          <span className="truncate">{item.label}</span>
                        </div>
                        {item.badge && (
                          <span className="text-[9.5px] px-1 py-0.2 rounded font-mono bg-[var(--surface-secondary)] text-[var(--foreground-tertiary)]">
                            {item.badge}
                          </span>
                        )}
                      </Link>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Bottom Documentation & Status Dock */}
      <div className="p-2 border-t border-[var(--border-subtle)] space-y-0.5 flex-shrink-0 bg-[var(--sidebar)]" suppressHydrationWarning>
        <button
          onClick={() => setIsDocsOpen(true)}
          suppressHydrationWarning
          className="w-full flex items-center gap-2.5 px-2.5 py-1.5 rounded-[var(--radius-sm)] text-[var(--foreground-secondary)] hover:text-[var(--foreground-primary)] hover:bg-[var(--surface-hover)] transition-colors text-left"
          title={collapsed && !onMobile ? "Documentation" : undefined}
        >
          <BookOpen className="w-4 h-4 flex-shrink-0 text-[var(--foreground-tertiary)]" />
          {(!collapsed || onMobile) && <span>Documentation</span>}
        </button>

        {/* Engine Heartbeat & RAM Only Indicator */}
        {(!collapsed || onMobile) && (
          <div className="pt-2 px-2 pb-1 flex items-center justify-between text-[11px] text-[var(--foreground-tertiary)] border-t border-[var(--border-subtle)] mt-1">
            <div className="flex items-center gap-1.5 font-mono">
              <span
                className={`w-1.5 h-1.5 rounded-full ${
                  isBackendOnline ? "bg-[var(--success)]" : "bg-[var(--danger)]"
                }`}
              />
              <span>{isBackendOnline ? "Engine Online" : "Offline"}</span>
            </div>
            <div className="flex items-center gap-1 font-mono text-[10px]">
              <HardDrive className="w-3 h-3 text-[var(--foreground-tertiary)]" />
              <span>RAM Only</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );

  return (
    <>
      {/* Mobile Backdrop */}
      {isMobileOpen && (
        <div
          className="md:hidden fixed inset-0 z-40 bg-black/50 backdrop-blur-xs transition-opacity"
          onClick={closeMobile}
        />
      )}

      {/* Mobile Drawer */}
      <aside
        className={`md:hidden fixed inset-y-0 left-0 z-50 w-[236px] bg-[var(--sidebar)] border-r border-[var(--border)] shadow-[var(--shadow-dialog)] transform transition-transform duration-[var(--motion-normal)] ease-out ${
          isMobileOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        {renderNav(false, true)}
      </aside>

      {/* Desktop Persistent Sidebar (236px) */}
      <aside
        className={`hidden md:block flex-shrink-0 transition-all duration-[var(--motion-normal)] ease-out z-20 ${
          isCollapsed ? "w-[56px]" : "w-[236px]"
        }`}
      >
        <div className="sticky top-0 h-screen overflow-hidden">
          {renderNav(isCollapsed, false)}
        </div>
      </aside>

      {/* Documentation Modal */}
      <DocumentationModal isOpen={isDocsOpen} onClose={() => setIsDocsOpen(false)} />
    </>
  );
}
