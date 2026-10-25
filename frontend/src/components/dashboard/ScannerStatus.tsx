"use client";

import React, { useEffect, useState } from "react";
import { CheckCircle2, AlertTriangle, XCircle, ShieldCheck, Activity } from "lucide-react";
import { api } from "@/lib/api";
import { SystemHealth, ScanResult } from "@/lib/types";

interface ScannerStatusProps {
  currentScan?: ScanResult | null;
}

export function ScannerStatus({ currentScan }: ScannerStatusProps) {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;
    async function loadHealth() {
      try {
        const h = await api.getHealth();
        if (isMounted) setHealth(h);
      } catch {
        // Handled via fallback
      } finally {
        if (isMounted) setIsLoading(false);
      }
    }
    loadHealth();
  }, []);

  const scannersList = [
    {
      id: "gitleaks",
      name: "Gitleaks (Secrets)",
      category: "Secret Detection",
      healthData: health?.scanners?.gitleaks,
    },
    {
      id: "semgrep",
      name: "Semgrep (SAST)",
      category: "Code Analysis",
      healthData: health?.scanners?.semgrep,
    },
    {
      id: "osv",
      name: "Google OSV (SCA)",
      category: "Dependency Intelligence",
      healthData: health?.scanners?.osv,
    },
  ];

  return (
    <div className="macos-panel p-4 space-y-3.5 border border-[var(--border)] rounded-[var(--radius-md)] bg-[var(--surface)]">
      <div className="flex items-center justify-between pb-2 border-b border-[var(--border)]">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-[var(--primary)]" />
          <h3 className="text-[13px] font-semibold text-[var(--foreground)]">
            Scanner Engine Status
          </h3>
        </div>
        <span className="text-[11px] font-mono text-[var(--foreground-tertiary)]">
          Real-time Engine Diagnostics
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
        {scannersList.map((scanner) => {
          const isEngineAvailable = scanner.healthData?.available ?? false;
          const version = scanner.healthData?.version;

          // Check if scanner was executed in the currently selected scan
          let executionStatus = "Not run in this scan";
          let findingCountForScanner = 0;

          if (currentScan) {
            const hasDetectorFindings = currentScan.findings.some(
              (f) =>
                f.detector_name?.toLowerCase().includes(scanner.id) ||
                (scanner.id === "osv" && f.category === "DEPENDENCIES") ||
                (scanner.id === "gitleaks" && f.category === "SECRETS") ||
                (scanner.id === "semgrep" && f.category === "SAST")
            );

            findingCountForScanner = currentScan.findings.filter(
              (f) =>
                f.detector_name?.toLowerCase().includes(scanner.id) ||
                (scanner.id === "osv" && f.category === "DEPENDENCIES") ||
                (scanner.id === "gitleaks" && f.category === "SECRETS") ||
                (scanner.id === "semgrep" && f.category === "SAST")
            ).length;

            if (currentScan.status === "COMPLETED") {
              executionStatus = hasDetectorFindings
                ? `Executed • ${findingCountForScanner} issue${findingCountForScanner === 1 ? "" : "s"}`
                : "Executed • 0 issues found";
            } else if (currentScan.status !== "FAILED" && currentScan.status !== "CANCELLED") {
              executionStatus = "Executing analysis...";
            }
          }

          return (
            <div
              key={scanner.id}
              className="p-3 rounded-[var(--radius-sm)] border border-[var(--border)] bg-[var(--surface-secondary)] space-y-2"
            >
              <div className="flex items-start justify-between">
                <div>
                  <div className="text-[13px] font-medium text-[var(--foreground)]">
                    {scanner.name}
                  </div>
                  <div className="text-[11px] text-[var(--foreground-tertiary)]">
                    {scanner.category}
                  </div>
                </div>

                {isEngineAvailable ? (
                  <span className="inline-flex items-center gap-1 text-[11px] font-medium text-[var(--success)]">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Ready</span>
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 text-[11px] font-medium text-[var(--warning)]">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>Unavailable</span>
                  </span>
                )}
              </div>

              <div className="pt-1 border-t border-[var(--border)]/60 flex items-center justify-between text-[11px]">
                <span className="font-mono text-[var(--foreground-tertiary)]">
                  {version ? `v${version}` : "Built-in"}
                </span>
                <span
                  className={`font-mono ${
                    executionStatus.includes("issue") && findingCountForScanner > 0
                      ? "text-[var(--danger)]"
                      : "text-[var(--foreground-secondary)]"
                  }`}
                >
                  {executionStatus}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
