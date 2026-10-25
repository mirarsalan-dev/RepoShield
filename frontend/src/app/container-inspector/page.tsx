"use client";

import React, { useState, useEffect, useMemo } from "react";
import Link from "next/link";
import {
  Boxes,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Info,
  Layers,
  Server,
  Lock,
  Unlock,
  Radio,
  FileCode,
  Download,
  ExternalLink,
  RotateCcw,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { api } from "@/lib/api";
import { ScanResult, Finding, ContainerInspectionReport } from "@/lib/types";
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import { EmptyState } from "@/components/common/EmptyState";
import { formatTimeAgo } from "@/lib/utils";

export default function ContainerInspectorPage() {
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [report, setReport] = useState<ContainerInspectionReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<"layers" | "ports" | "sbom">("layers");

  useEffect(() => {
    const saved = storage.getScanHistory();
    setHistory(saved);
    if (saved.length > 0) {
      setSelectedScan(saved[0]);
    }
  }, []);

  useEffect(() => {
    if (!selectedScan) return;

    let mounted = true;
    async function loadContainerReport() {
      if (!selectedScan) return;
      setLoading(true);
      try {
        let rep: ContainerInspectionReport;
        try {
          rep = await api.getScanContainer(selectedScan.scan_id);
        } catch {
          rep = await api.generateCustomContainer(selectedScan);
        }
        if (mounted) {
          setReport(rep);
        }
      } catch (err) {
        console.warn("Failed to load container report:", err);
      } finally {
        if (mounted) setLoading(false);
      }
    }

    loadContainerReport();
    return () => {
      mounted = false;
    };
  }, [selectedScan]);

  if (!selectedScan && history.length === 0) {
    return (
      <EmptyState
        icon={Boxes}
        title="No Container Audits Available"
        description="Scan any repository containing Dockerfiles or container specifications to inspect image layers and privilege postures."
        actionText="Scan a Repository"
        actionHref="/scan"
      />
    );
  }

  return (
    <div className="space-y-4">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[var(--border-color)]">
        <div>
          <h1 className="text-[22px] font-semibold tracking-tight text-[var(--text-primary)]">
            Container Image &amp; Dockerfile Inspector
          </h1>
          <p className="text-[13px] text-[var(--text-secondary)] mt-0.5">
            Static container configuration auditing, base image pinning, root privilege checks, and port exposure analysis.
          </p>
        </div>

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
      </div>

      {/* KPI Cards Panel */}
      <div className="macos-panel p-3.5 grid grid-cols-2 sm:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-[var(--border-subtle)] text-[12px]">
        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Dockerfiles Found</div>
          <div className="text-xl font-semibold text-[var(--text-primary)]">
            {report?.dockerfiles_found ?? 0}
          </div>
        </div>

        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Privilege Posture</div>
          <div className="flex items-center gap-1.5 mt-0.5">
            {report?.runs_as_root ? (
              <span className="text-[#FF453A] font-semibold text-[13px] flex items-center gap-1">
                <Unlock className="w-3.5 h-3.5" />
                Root Execution (UID 0)
              </span>
            ) : (
              <span className="text-[#34C759] font-semibold text-[13px] flex items-center gap-1">
                <Lock className="w-3.5 h-3.5" />
                Non-Root Enforced
              </span>
            )}
          </div>
        </div>

        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Base Image Pinning</div>
          <div className="text-[13px] font-semibold text-[var(--text-primary)] mt-0.5 truncate">
            {report?.base_image_has_digest ? (
              <span className="text-[#34C759]">Pinned by Digest (SHA256)</span>
            ) : report?.base_image_pinned ? (
              <span className="text-[#0A84FF]">Pinned by Version Tag</span>
            ) : (
              <span className="text-[#FF9500]">Unpinned / Mutable Tag</span>
            )}
          </div>
        </div>

        <div className="p-2 space-y-0.5">
          <div className="text-[var(--text-secondary)]">Exposed Port Listeners</div>
          <div className="text-xl font-semibold text-[var(--text-primary)]">
            {report?.exposed_ports.length ?? 0}
          </div>
        </div>
      </div>

      {/* Safety & Execution Isolation Banner */}
      <div className="p-3.5 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] flex items-start gap-3">
        <Info className="w-4 h-4 text-[#0A84FF] shrink-0 mt-0.5" />
        <div className="text-[12px] text-[var(--text-secondary)] space-y-1">
          <div className="font-medium text-[var(--text-primary)]">
            Execution Safety &amp; Static Parser Guarantee
          </div>
          <p>
            {report?.safety_disclosure}
          </p>
          <div className="text-[11px] text-[var(--text-muted)] pt-0.5">
            Offline mode active: Base image instructions and exposed ports are verified using declarative static syntax analysis.
          </div>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex items-center gap-2 border-b border-[var(--border-subtle)] pb-2 text-[12px]">
        <button
          onClick={() => setActiveTab("layers")}
          className={`px-3 py-1.5 rounded-[6px] font-medium transition-colors ${
            activeTab === "layers"
              ? "bg-[var(--accent)] text-white"
              : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
          }`}
        >
          Layer Risks ({report?.layer_risks.length ?? 0})
        </button>
        <button
          onClick={() => setActiveTab("ports")}
          className={`px-3 py-1.5 rounded-[6px] font-medium transition-colors ${
            activeTab === "ports"
              ? "bg-[var(--accent)] text-white"
              : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
          }`}
        >
          Exposed Listeners ({report?.exposed_ports.length ?? 0})
        </button>
        <button
          onClick={() => setActiveTab("sbom")}
          className={`px-3 py-1.5 rounded-[6px] font-medium transition-colors ${
            activeTab === "sbom"
              ? "bg-[var(--accent)] text-white"
              : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
          }`}
        >
          Container SBOM ({report?.container_sbom.length ?? 0})
        </button>
      </div>

      {/* Tab 1: Layer Risks */}
      {activeTab === "layers" && (
        <div className="space-y-3">
          {loading ? (
            <div className="macos-panel p-8 text-center text-[12px] text-[var(--text-secondary)]">
              Auditing container build layers and privilege instructions...
            </div>
          ) : !report || report.layer_risks.length === 0 ? (
            <div className="macos-panel p-10 text-center space-y-2">
              <ShieldCheck className="w-8 h-8 text-[#34C759] mx-auto" />
              <div className="text-[14px] font-medium text-[var(--text-primary)]">
                No Critical Container Layer Risks Detected
              </div>
              <p className="text-[12px] text-[var(--text-secondary)] max-w-md mx-auto">
                No root user misconfigurations, unchecksummed script pipelines, or dangerous build steps were detected in inspected Dockerfiles.
              </p>
            </div>
          ) : (
            report.layer_risks.map((risk, idx) => (
              <div
                key={idx}
                className="macos-panel p-4 space-y-3 border border-[var(--border-color)]"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={risk.severity} />
                    <span className="font-mono text-[12px] font-semibold text-[var(--text-primary)] bg-[var(--surface)] px-2 py-0.5 rounded border border-[var(--border-subtle)]">
                      {risk.instruction} {risk.argument}
                    </span>
                  </div>
                </div>

                <div className="text-[13px] font-medium text-[var(--text-primary)]">
                  {risk.risk_summary}
                </div>

                <div className="text-[12px] text-[var(--text-secondary)] bg-[var(--bg-secondary)] p-2.5 rounded-[6px] border border-[var(--border-subtle)] space-y-1">
                  <div className="font-semibold text-[var(--text-primary)] flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5 text-[#34C759]" />
                    <span>Recommended Remediation:</span>
                  </div>
                  <p>{risk.recommendation}</p>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* Tab 2: Exposed Ports */}
      {activeTab === "ports" && (
        <div className="macos-panel overflow-hidden">
          <table className="w-full text-left border-collapse text-[13px]">
            <thead>
              <tr className="border-b border-[var(--border-color)] bg-[var(--bg-secondary)] text-[var(--text-secondary)] text-[11px] font-medium select-none">
                <th className="py-2 px-3.5 w-24">Port</th>
                <th className="py-2 px-3.5 w-24">Protocol</th>
                <th className="py-2 px-3.5 w-32">Risk Level</th>
                <th className="py-2 px-3.5">Security Implications &amp; Guidelines</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border-subtle)]">
              {!report || report.exposed_ports.length === 0 ? (
                <tr>
                  <td colSpan={4} className="py-8 text-center text-[var(--text-secondary)] text-[12px]">
                    No ports explicitly declared via EXPOSE instructions in inspected files.
                  </td>
                </tr>
              ) : (
                report.exposed_ports.map((p, idx) => (
                  <tr key={idx} className="hover:bg-[var(--bg-hover)] transition-colors">
                    <td className="py-2.5 px-3.5 font-mono font-semibold text-[var(--text-primary)]">
                      {p.port}
                    </td>
                    <td className="py-2.5 px-3.5 font-mono text-[12px] text-[var(--text-secondary)] uppercase">
                      {p.protocol}
                    </td>
                    <td className="py-2.5 px-3.5">
                      <span
                        className={`text-[11px] font-medium px-2 py-0.5 rounded ${
                          p.risk_level === "HIGH_RISK"
                            ? "bg-red-500/10 text-red-500 border border-red-500/20"
                            : p.risk_level === "CAUTION"
                            ? "bg-amber-500/10 text-amber-500 border border-amber-500/20"
                            : "bg-blue-500/10 text-blue-500 border border-blue-500/20"
                        }`}
                      >
                        {p.risk_level.replace("_", " ")}
                      </span>
                    </td>
                    <td className="py-2.5 px-3.5 text-[12px] text-[var(--text-secondary)]">
                      {p.description}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Tab 3: Container SBOM */}
      {activeTab === "sbom" && (
        <div className="space-y-4">
          <div className="macos-panel overflow-hidden">
            <table className="w-full text-left border-collapse text-[13px]">
              <thead>
                <tr className="border-b border-[var(--border-color)] bg-[var(--bg-secondary)] text-[var(--text-secondary)] text-[11px] font-medium select-none">
                  <th className="py-2 px-3.5">Component</th>
                  <th className="py-2 px-3.5">Type</th>
                  <th className="py-2 px-3.5">Version / Tag</th>
                  <th className="py-2 px-3.5">Source File</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-subtle)]">
                {!report || report.container_sbom.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="py-8 text-center text-[var(--text-secondary)] text-[12px]">
                      No container base image or package manager directives identified in inspected files.
                    </td>
                  </tr>
                ) : (
                  report.container_sbom.map((item, idx) => (
                    <tr key={idx} className="hover:bg-[var(--bg-hover)] transition-colors">
                      <td className="py-2.5 px-3.5 font-semibold text-[var(--text-primary)]">
                        {item.name}
                      </td>
                      <td className="py-2.5 px-3.5 text-[12px] text-[var(--text-secondary)] font-mono">
                        {item.type}
                      </td>
                      <td className="py-2.5 px-3.5 font-mono text-[12px] text-[var(--text-primary)]">
                        {item.version}
                      </td>
                      <td className="py-2.5 px-3.5 font-mono text-[12px] text-[var(--text-secondary)]">
                        {item.location}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Unsupported Checks Disclosures */}
      {report?.unsupported_checks && report.unsupported_checks.length > 0 && (
        <div className="p-3.5 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] space-y-1.5 text-[12px]">
          <div className="font-semibold text-[var(--text-primary)] flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
            <span>Documented Scanner Limitations &amp; Unsupported Checks:</span>
          </div>
          <ul className="list-disc list-inside space-y-0.5 text-[var(--text-muted)] pl-2">
            {report.unsupported_checks.map((uc, i) => (
              <li key={i}>{uc}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
