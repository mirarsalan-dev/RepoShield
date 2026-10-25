"use client";

import React, { useState, useEffect, Suspense, useMemo } from "react";
import Link from "next/link";
import {
  Globe,
  Shield,
  ShieldAlert,
  Lock,
  Unlock,
  AlertTriangle,
  Filter,
  FileCode,
  ExternalLink,
  Search,
  CheckCircle2,
  Server,
  Layers,
  ArrowRight,
  ClipboardCheck,
  HelpCircle,
  X,
  FileText,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { ScanResult, ApiSecurityReport, ApiEndpointItem, Severity, Finding } from "@/lib/types";
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import { EmptyState } from "@/components/common/EmptyState";
import { AnimatedDialog } from "@/components/motion";

function ApiSecurityContent() {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [methodFilter, setMethodFilter] = useState<string>("ALL");
  const [authFilter, setAuthFilter] = useState<string>("ALL");
  const [driftFilter, setDriftFilter] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [inspectedEndpoint, setInspectedEndpoint] = useState<ApiEndpointItem | null>(null);

  useEffect(() => {
    const history = storage.getScanHistory();
    setScans(history);
    if (history.length > 0) {
      setSelectedScan(history[0]);
    }
  }, []);

  const handleScanChange = (scanId: string) => {
    const scan = scans.find((s) => s.scan_id === scanId);
    if (scan) setSelectedScan(scan);
  };

  const report: ApiSecurityReport | undefined = selectedScan?.api_security_report;
  const endpoints: ApiEndpointItem[] = report?.endpoints || [];

  const filteredEndpoints = useMemo(() => {
    return endpoints.filter((ep) => {
      if (methodFilter !== "ALL" && ep.method !== methodFilter) return false;
      if (authFilter === "AUTH" && !ep.has_auth) return false;
      if (authFilter === "NO_AUTH" && ep.has_auth) return false;
      if (driftFilter !== "ALL" && (ep.contract_drift_status || "ALIGNED") !== driftFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesPath = ep.path.toLowerCase().includes(q);
        const matchesSummary = ep.summary?.toLowerCase().includes(q);
        const matchesFile = ep.file_path?.toLowerCase().includes(q);
        if (!matchesPath && !matchesSummary && !matchesFile) return false;
      }
      return true;
    });
  }, [endpoints, methodFilter, authFilter, driftFilter, searchQuery]);

  const getMethodBadgeClass = (method: string) => {
    switch (method.toUpperCase()) {
      case "GET":
        return "bg-blue-500/10 text-blue-500 border-blue-500/30";
      case "POST":
        return "bg-emerald-500/10 text-emerald-500 border-emerald-500/30";
      case "PUT":
      case "PATCH":
        return "bg-amber-500/10 text-amber-500 border-amber-500/30";
      case "DELETE":
        return "bg-rose-500/10 text-rose-500 border-rose-500/30";
      default:
        return "bg-[var(--surface-subtle)] text-[var(--muted-foreground)] border-[var(--border)]";
    }
  };

  const getDriftBadge = (drift?: string) => {
    switch (drift) {
      case "SHADOW_CODE_ONLY":
        return { label: "Shadow Route (Code Only)", color: "text-rose-500 bg-rose-500/10 border-rose-500/30" };
      case "SPEC_ONLY":
        return { label: "Ghost Route (Spec Only)", color: "text-amber-500 bg-amber-500/10 border-amber-500/30" };
      default:
        return { label: "Contract Aligned", color: "text-emerald-500 bg-emerald-500/10 border-emerald-500/30" };
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12 animate-in fade-in duration-300">
      {/* Top Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-[var(--border)]">
        <div className="space-y-1 min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2.5">
            <div className="w-8 h-8 rounded-[8px] bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-500 shrink-0 flex-shrink-0">
              <Globe className="w-4 h-4" />
            </div>
            <h1 className="text-xl font-semibold text-[var(--foreground)] tracking-tight">
              API Security Contract Analyzer
            </h1>
            <span className="text-[11px] font-mono px-2.5 py-0.5 rounded-full bg-blue-500/10 text-blue-500 border border-blue-500/30 whitespace-nowrap shrink-0 flex-shrink-0 inline-flex items-center">
              Contract Drift &amp; Exposure Audit
            </span>
          </div>
          <p className="text-[13px] text-[var(--muted-foreground)] mt-1">
            Reconciles declared OpenAPI specifications with source-level route definitions. Identifies shadow routes, missing authentication, and excessive response exposure.
          </p>
        </div>

        {/* Scan Selector */}
        {scans.length > 0 && (
          <select
            value={selectedScan?.scan_id || ""}
            onChange={(e) => handleScanChange(e.target.value)}
            className="px-3 py-1.5 text-[12px] rounded-[6px] bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)] font-mono focus:outline-none focus:ring-1 focus:ring-[var(--focus-ring)] shrink-0 flex-shrink-0 max-w-full sm:max-w-xs truncate"
          >
            {scans.map((s) => (
              <option key={s.scan_id} value={s.scan_id}>
                {s.owner}/{s.repo} ({s.api_security_report?.total_endpoints || 0} routes)
              </option>
            ))}
          </select>
        )}
      </div>

      {/* Contract & Specification Disclaimer */}
      <div className="p-3.5 rounded-[8px] bg-blue-500/10 border border-blue-500/20 text-blue-700 dark:text-blue-300 text-[12px] flex items-start gap-2.5">
        <HelpCircle className="w-4 h-4 flex-shrink-0 mt-0.5 text-blue-500" />
        <div className="leading-relaxed">
          <span className="font-semibold">Analysis Confidence &amp; Limitations:</span> A missing security declaration in OpenAPI indicates contract-level omission, not guaranteed runtime exposure. RepoShield clearly separates specification warnings from source-code implementation evidence.
        </div>
      </div>

      {!report || endpoints.length === 0 ? (
        <EmptyState
          title="No API Endpoints Detected"
          description="RepoShield did not discover OpenAPI / Swagger definitions or supported route declarations in this repository snapshot."
          actionText="Run New Scan"
          actionHref="/scan"
        />
      ) : (
        <div className="space-y-6">
          {/* Summary Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
            <div className="p-3 rounded-[8px] bg-[var(--surface)] border border-[var(--border)]">
              <span className="text-[11px] font-mono uppercase text-[var(--muted-foreground)]">
                Total Routes
              </span>
              <div className="text-xl font-bold text-[var(--foreground)] font-mono mt-0.5">
                {report.total_endpoints}
              </div>
              <p className="text-[10px] text-[var(--muted-foreground)] mt-0.5">
                Specs &amp; source routes
              </p>
            </div>

            <div className="p-3 rounded-[8px] bg-[var(--surface)] border border-[var(--border)]">
              <span className="text-[11px] font-mono uppercase text-amber-500">
                Unauthenticated
              </span>
              <div className="text-xl font-bold text-amber-500 font-mono mt-0.5">
                {report.endpoints_without_auth}
              </div>
              <p className="text-[10px] text-[var(--muted-foreground)] mt-0.5">
                No auth declared
              </p>
            </div>

            <div className="p-3 rounded-[8px] bg-[var(--surface)] border border-[var(--border)]">
              <span className="text-[11px] font-mono uppercase text-rose-500">
                Shadow Routes
              </span>
              <div className="text-xl font-bold text-rose-500 font-mono mt-0.5">
                {report.shadow_endpoints_count || 0}
              </div>
              <p className="text-[10px] text-[var(--muted-foreground)] mt-0.5">
                In code, omitted in spec
              </p>
            </div>

            <div className="p-3 rounded-[8px] bg-[var(--surface)] border border-[var(--border)]">
              <span className="text-[11px] font-mono uppercase text-amber-500">
                Ghost Routes
              </span>
              <div className="text-xl font-bold text-amber-500 font-mono mt-0.5">
                {report.ghost_endpoints_count || 0}
              </div>
              <p className="text-[10px] text-[var(--muted-foreground)] mt-0.5">
                In spec, not in code
              </p>
            </div>

            <div className="p-3 rounded-[8px] bg-[var(--surface)] border border-[var(--border)]">
              <span className="text-[11px] font-mono uppercase text-blue-500">
                Contract Findings
              </span>
              <div className="text-xl font-bold text-blue-500 font-mono mt-0.5">
                {report.findings.length}
              </div>
              <p className="text-[10px] text-[var(--muted-foreground)] mt-0.5">
                Active alerts
              </p>
            </div>
          </div>

          {/* Filter Bar */}
          <div className="p-3.5 rounded-[8px] bg-[var(--surface)] border border-[var(--border)] flex flex-wrap items-center justify-between gap-3 text-[12px]">
            <div className="flex items-center gap-2 flex-1 max-w-sm">
              <Search className="w-3.5 h-3.5 text-[var(--muted-foreground)]" />
              <input
                type="text"
                placeholder="Filter route by path (e.g. /api/users)..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-2 pr-3 py-1.5 text-[12px] rounded-[6px] bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)] focus:outline-none focus:ring-1 focus:ring-[var(--focus-ring)]"
              />
            </div>

            <div className="flex items-center gap-2.5 flex-wrap">
              <div className="flex items-center gap-1.5">
                <span className="text-[11px] text-[var(--muted-foreground)]">Drift:</span>
                <select
                  value={driftFilter}
                  onChange={(e) => setDriftFilter(e.target.value)}
                  className="px-2 py-1 text-[11px] rounded-[4px] bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)]"
                >
                  <option value="ALL">All Contract States</option>
                  <option value="ALIGNED">Contract Aligned</option>
                  <option value="SHADOW_CODE_ONLY">Shadow Routes (Code Only)</option>
                  <option value="SPEC_ONLY">Ghost Routes (Spec Only)</option>
                </select>
              </div>

              <div className="flex items-center gap-1.5">
                <span className="text-[11px] text-[var(--muted-foreground)]">Method:</span>
                <select
                  value={methodFilter}
                  onChange={(e) => setMethodFilter(e.target.value)}
                  className="px-2 py-1 text-[11px] rounded-[4px] bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)]"
                >
                  <option value="ALL">All Methods</option>
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                  <option value="DELETE">DELETE</option>
                  <option value="PATCH">PATCH</option>
                </select>
              </div>

              <div className="flex items-center gap-1.5">
                <span className="text-[11px] text-[var(--muted-foreground)]">Auth:</span>
                <select
                  value={authFilter}
                  onChange={(e) => setAuthFilter(e.target.value)}
                  className="px-2 py-1 text-[11px] rounded-[4px] bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)]"
                >
                  <option value="ALL">All Status</option>
                  <option value="AUTH">Authenticated</option>
                  <option value="NO_AUTH">No Auth Declared</option>
                </select>
              </div>
            </div>
          </div>

          {/* Endpoints Table */}
          <div className="overflow-hidden rounded-[10px] border border-[var(--border)] bg-[var(--surface)]">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-[12px]">
                <thead className="bg-[var(--surface-subtle)] border-b border-[var(--border)] text-[11px] font-semibold text-[var(--muted-foreground)] uppercase font-mono">
                  <tr>
                    <th className="py-2.5 px-4">Method</th>
                    <th className="py-2.5 px-4">Endpoint Path</th>
                    <th className="py-2.5 px-4">Contract Drift</th>
                    <th className="py-2.5 px-4">Authentication</th>
                    <th className="py-2.5 px-4">Validation</th>
                    <th className="py-2.5 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border)]">
                  {filteredEndpoints.map((ep) => {
                    const driftBadge = getDriftBadge(ep.contract_drift_status);

                    return (
                      <tr
                        key={ep.id}
                        onClick={() => setInspectedEndpoint(ep)}
                        className="hover:bg-[var(--surface-subtle)]/60 cursor-pointer transition-colors"
                      >
                        <td className="py-3 px-4">
                          <span
                            className={`font-mono text-[10px] font-bold px-2 py-0.5 rounded border ${getMethodBadgeClass(
                              ep.method
                            )}`}
                          >
                            {ep.method}
                          </span>
                        </td>

                        <td className="py-3 px-4 font-mono font-medium text-[var(--foreground)]">
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <span>{ep.path}</span>
                            {ep.is_sensitive_path && (
                              <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-amber-500/10 text-amber-500 border border-amber-500/30">
                                Sensitive
                              </span>
                            )}
                            {ep.excessive_data_exposure_risk && (
                              <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-rose-500/10 text-rose-500 border border-rose-500/30">
                                Data Exposure Risk
                              </span>
                            )}
                          </div>
                          {ep.file_path && (
                            <div className="font-mono text-[10px] text-[var(--muted-foreground)] mt-0.5 truncate">
                              {ep.file_path}:{ep.line_number || 1}
                            </div>
                          )}
                        </td>

                        <td className="py-3 px-4">
                          <span className={`px-2 py-0.5 text-[10px] font-medium rounded border ${driftBadge.color}`}>
                            {driftBadge.label}
                          </span>
                        </td>

                        <td className="py-3 px-4">
                          {ep.has_auth ? (
                            <span className="inline-flex items-center gap-1 text-emerald-500 font-medium">
                              <Lock className="w-3 h-3" />
                              <span>{ep.auth_schemes.join(", ") || "Enforced"}</span>
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-amber-500 font-medium">
                              <Unlock className="w-3 h-3" />
                              <span>No Auth</span>
                            </span>
                          )}
                        </td>

                        <td className="py-3 px-4">
                          {ep.has_input_validation ? (
                            <span className="text-emerald-500 text-[11px]">Validated</span>
                          ) : (
                            <span className="text-amber-500 text-[11px]">Missing Schema</span>
                          )}
                        </td>

                        <td className="py-3 px-4 text-right">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setInspectedEndpoint(ep);
                            }}
                            className="px-2.5 py-1 text-[11px] rounded bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)] hover:bg-[var(--surface-hover)]"
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Endpoint Inspection Drawer / Dialog */}
      {inspectedEndpoint && (
        <AnimatedDialog
          isOpen={!!inspectedEndpoint}
          onClose={() => setInspectedEndpoint(null)}
          className="w-full max-w-xl p-6 macos-window shadow-2xl max-h-[85vh] overflow-y-auto"
          ariaLabel="API Endpoint Security Details"
        >
          <div className="space-y-5 text-[13px]">
            <div className="flex items-center justify-between border-b border-[var(--border)] pb-3">
              <div className="flex items-center gap-2 flex-wrap pr-3">
                <span className={`font-mono text-[11px] font-bold px-2.5 py-0.5 rounded border shrink-0 ${getMethodBadgeClass(inspectedEndpoint.method)}`}>
                  {inspectedEndpoint.method}
                </span>
                <span className="font-mono text-sm font-semibold text-[var(--foreground)] break-all">{inspectedEndpoint.path}</span>
              </div>
              <button
                onClick={() => setInspectedEndpoint(null)}
                className="p-1 rounded-[6px] text-[var(--muted-foreground)] hover:text-[var(--foreground)] hover:bg-[var(--surface-hover)] transition-colors shrink-0"
                aria-label="Close dialog"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 font-mono text-[12px]">
              <div className="p-3.5 rounded-[8px] bg-[var(--surface-subtle)] border border-[var(--border)] space-y-2">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1">
                  <span className="text-[var(--muted-foreground)]">Source Location: </span>
                  <span className="text-[var(--foreground)] font-mono text-right truncate">
                    {inspectedEndpoint.file_path || "OpenAPI Specification"}:{inspectedEndpoint.line_number || 1}
                  </span>
                </div>
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1">
                  <span className="text-[var(--muted-foreground)]">Discovery Type: </span>
                  <span className="text-[var(--foreground)] font-mono">{inspectedEndpoint.source_type}</span>
                </div>
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1">
                  <span className="text-[var(--muted-foreground)]">Contract Status: </span>
                  <span className="text-[var(--foreground)] font-mono">{inspectedEndpoint.contract_drift_status || "ALIGNED"}</span>
                </div>
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1">
                  <span className="text-[var(--muted-foreground)]">Auth Schemes: </span>
                  <span className="text-[var(--foreground)] font-mono">{inspectedEndpoint.auth_schemes.join(", ") || "None Declared"}</span>
                </div>
              </div>

              {inspectedEndpoint.summary && (
                <div className="font-sans text-[12px] text-[var(--muted-foreground)] p-3 rounded-[6px] bg-[var(--surface)] border border-[var(--border)]">
                  <span className="font-semibold text-[var(--foreground)]">Summary: </span>
                  {inspectedEndpoint.summary}
                </div>
              )}

              <div className="p-3.5 rounded-[8px] bg-blue-500/10 border border-blue-500/20 font-sans text-[12px] text-blue-700 dark:text-blue-300">
                <span className="font-semibold">Security Guidance: </span>
                {inspectedEndpoint.has_auth
                  ? "Authentication requirements are formally declared. Ensure route parameters enforce input bounds and authorization checks (BOLA/IDOR prevention)."
                  : "Endpoint declares no security requirement. If this route modifies data or exposes internal resources, bind authentication middleware immediately."}
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-[var(--border)]">
              <Link
                href={`/review-workbench`}
                className="px-3.5 py-1.5 text-[12px] rounded-[6px] bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)] hover:bg-[var(--surface-hover)] transition-colors"
              >
                Review in Workbench
              </Link>
              <button
                onClick={() => setInspectedEndpoint(null)}
                className="px-4 py-1.5 text-[12px] rounded-[6px] bg-[var(--accent)] text-white hover:opacity-90 font-medium transition-opacity"
              >
                Done
              </button>
            </div>
          </div>
        </AnimatedDialog>
      )}
    </div>
  );
}

export default function ApiSecurityPage() {
  return (
    <Suspense fallback={<div className="p-8 text-center text-[var(--muted-foreground)]">Loading API Security...</div>}>
      <ApiSecurityContent />
    </Suspense>
  );
}
