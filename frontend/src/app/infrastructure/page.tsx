"use client";

import React, { useState, useEffect, Suspense } from "react";
import Link from "next/link";
import {
  Server,
  Layers,
  Cpu,
  Shield,
  FileCode,
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  Wrench,
  Search,
  Filter,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { ScanResult, Finding, Severity } from "@/lib/types";
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import { MacTrafficLights } from "@/components/common/Icons";

function InfrastructureContent() {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [typeFilter, setTypeFilter] = useState<string>("ALL");

  useEffect(() => {
    const history = storage.getScanHistory();
    setScans(history);
    if (history.length > 0) {
      setSelectedScan(history[0]);
    }
  }, []);

  const handleScanChange = (scanId: string) => {
    const scan = scans.find((s) => s.scan_id === scanId);
    if (scan) {
      setSelectedScan(scan);
      setSelectedFinding(null);
    }
  };

  const infraFindings = (selectedScan?.findings || []).filter(
    (f) => f.category === "INFRASTRUCTURE"
  );

  const filteredFindings = infraFindings.filter((f) => {
    if (typeFilter === "ALL") return true;
    if (typeFilter === "DOCKER" && f.file_path.toLowerCase().includes("docker")) return true;
    if (typeFilter === "K8S" && (f.file_path.endsWith(".yaml") || f.file_path.endsWith(".yml")) && !f.file_path.includes(".github")) return true;
    if (typeFilter === "TERRAFORM" && f.file_path.endsWith(".tf")) return true;
    if (typeFilter === "CI_CD" && f.file_path.includes(".github")) return true;
    return false;
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Top Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-[var(--border-subtle)]">
        <div className="space-y-1 min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="p-1.5 rounded-[6px] bg-[var(--accent)]/10 text-[var(--accent)] shrink-0 flex-shrink-0">
              <Server className="w-5 h-5" />
            </span>
            <h1 className="text-[20px] font-semibold text-[var(--text-primary)] tracking-tight">
              Infrastructure-as-Code Security
            </h1>
            <span className="text-[11px] font-mono px-2.5 py-0.5 rounded-full bg-[var(--accent)]/15 text-[var(--accent)] border border-[var(--accent)]/30 whitespace-nowrap shrink-0 flex-shrink-0 inline-flex items-center">
              Docker • K8s • Terraform • CI/CD
            </span>
          </div>
          <p className="text-[13px] text-[var(--text-secondary)] mt-1">
            Audits Dockerfiles, Kubernetes manifests, Terraform configurations, and CI/CD pipelines for privilege escalation and misconfigurations.
          </p>
        </div>

        {/* Scan Selector */}
        {scans.length > 0 && (
          <div className="flex items-center gap-3">
            <span className="text-[12px] text-[var(--text-secondary)]">Target:</span>
            <select
              value={selectedScan?.scan_id || ""}
              onChange={(e) => handleScanChange(e.target.value)}
              className="macos-input text-[12px] py-1 px-2.5 max-w-[220px]"
            >
              {scans.map((s) => (
                <option key={s.scan_id} value={s.scan_id}>
                  {s.owner}/{s.repo} ({s.findings.filter((f) => f.category === "INFRASTRUCTURE").length} IaC issues)
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {infraFindings.length === 0 ? (
        <div className="macos-panel p-12 text-center max-w-lg mx-auto space-y-3">
          <Shield className="w-10 h-10 text-[var(--system-green)] mx-auto" />
          <h3 className="text-[15px] font-semibold text-[var(--text-primary)]">
            Zero Infrastructure Misconfigurations
          </h3>
          <p className="text-[13px] text-[var(--text-secondary)] leading-relaxed">
            No container privilege escalations, dangerous workflow triggers, or open cloud security group rules detected in scanned infrastructure files.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Finding List */}
          <div className="lg:col-span-5 space-y-3">
            <div className="flex items-center justify-between px-1">
              <span className="text-[12px] font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
                IaC Findings ({filteredFindings.length})
              </span>
              <div className="flex items-center gap-1.5">
                <Filter className="w-3 h-3 text-[var(--text-muted)]" />
                <select
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value)}
                  className="macos-input text-[11px] py-0.5 px-1.5"
                >
                  <option value="ALL">All Types</option>
                  <option value="DOCKER">Docker</option>
                  <option value="K8S">Kubernetes</option>
                  <option value="TERRAFORM">Terraform</option>
                  <option value="CI_CD">GitHub Actions</option>
                </select>
              </div>
            </div>

            <div className="macos-panel divide-y divide-[var(--border-subtle)] max-h-[640px] overflow-y-auto">
              {filteredFindings.map((f) => {
                const isSelected = selectedFinding?.id === f.id;
                return (
                  <button
                    key={f.id}
                    onClick={() => setSelectedFinding(f)}
                    className={`w-full text-left p-3.5 transition-colors ${
                      isSelected
                        ? "bg-[var(--accent)]/10 border-l-2 border-[var(--accent)]"
                        : "hover:bg-[var(--bg-hover)]"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <SeverityBadge severity={f.severity} />
                      <span className="text-[11px] font-mono text-[var(--text-muted)] truncate">
                        {f.file_path}
                      </span>
                    </div>
                    <div className="text-[13px] font-medium text-[var(--text-primary)] mt-1.5">
                      {f.title}
                    </div>
                    <div className="text-[11px] text-[var(--text-secondary)] mt-0.5 line-clamp-1">
                      {f.remediation}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Right Column: Finding Detail & Remediation */}
          <div className="lg:col-span-7 space-y-5">
            {selectedFinding ? (
              <div className="macos-panel p-5 space-y-5">
                <div className="flex items-start justify-between gap-3 pb-3 border-b border-[var(--border-subtle)]">
                  <div>
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={selectedFinding.severity} />
                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[var(--bg-secondary)] border border-[var(--border-subtle)] text-[var(--text-secondary)]">
                        {selectedFinding.file_path}
                        {selectedFinding.line_start ? `:${selectedFinding.line_start}` : ""}
                      </span>
                    </div>
                    <h2 className="text-[16px] font-semibold text-[var(--text-primary)] mt-1.5">
                      {selectedFinding.title}
                    </h2>
                  </div>
                  <Link
                    href={`/fix-validation?findingId=${selectedFinding.id}`}
                    className="macos-button text-[12px] flex items-center gap-1.5 text-[var(--accent)] hover:bg-[var(--accent)]/10 flex-shrink-0"
                  >
                    <Wrench className="w-3.5 h-3.5" />
                    <span>Validate in Lab</span>
                  </Link>
                </div>

                <div className="space-y-1.5">
                  <div className="text-[11px] font-semibold text-[var(--text-secondary)] uppercase">
                    Risk Explanation
                  </div>
                  <p className="text-[13px] text-[var(--text-primary)] leading-relaxed">
                    {selectedFinding.description}
                  </p>
                </div>

                {selectedFinding.evidence && (
                  <div className="space-y-1.5">
                    <div className="text-[11px] font-semibold text-[var(--text-secondary)] uppercase">
                      Offending Configuration Snippet
                    </div>
                    <pre className="p-3 rounded-[6px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] font-mono text-[11px] text-[var(--text-primary)] overflow-x-auto whitespace-pre">
                      {selectedFinding.evidence}
                    </pre>
                  </div>
                )}

                <div className="p-3.5 rounded-[8px] bg-[var(--accent)]/10 border border-[var(--accent)]/20 space-y-2">
                  <div className="text-[12px] font-semibold text-[var(--accent)] flex items-center gap-1.5">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Recommended Secure Configuration</span>
                  </div>
                  <p className="text-[12px] text-[var(--text-primary)]">
                    {selectedFinding.remediation}
                  </p>
                  {selectedFinding.secure_code_example && (
                    <pre className="p-2.5 rounded-[6px] bg-[var(--bg-primary)] border border-[var(--border-subtle)] font-mono text-[11px] text-[var(--text-primary)] overflow-x-auto whitespace-pre mt-2">
                      {selectedFinding.secure_code_example}
                    </pre>
                  )}
                </div>
              </div>
            ) : (
              <div className="macos-panel p-10 text-center text-[var(--text-muted)] space-y-2">
                <FileCode className="w-8 h-8 mx-auto" />
                <p className="text-[13px]">Select an IaC finding on the left to inspect configuration details.</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function InfrastructurePage() {
  return (
    <Suspense fallback={<div className="p-8 text-center text-[var(--text-muted)]">Loading Infrastructure Security...</div>}>
      <InfrastructureContent />
    </Suspense>
  );
}
