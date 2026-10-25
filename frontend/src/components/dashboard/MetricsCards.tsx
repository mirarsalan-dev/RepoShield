import React from "react";
import { RiskScore } from "@/lib/types";
import { GitBranch, AlertCircle, ShieldAlert, CheckCircle2 } from "lucide-react";

interface MetricsCardsProps {
  riskScore?: RiskScore;
  totalRepositoriesScanned?: number;
  resolvedCount?: number;
}

export function MetricsCards({
  riskScore,
  totalRepositoriesScanned = 1,
  resolvedCount = 0,
}: MetricsCardsProps) {
  if (!riskScore) return null;

  const criticalAndHigh = (riskScore.critical_count || 0) + (riskScore.high_count || 0);

  return (
    <div className="macos-panel border border-[var(--border)] rounded-[var(--radius-md)] bg-[var(--surface)] p-3.5 grid grid-cols-2 lg:grid-cols-4 divide-y sm:divide-y-0 divide-[var(--border)] sm:divide-x">
      {/* 1. Repositories Scanned */}
      <div className="p-3.5 space-y-1">
        <div className="flex items-center gap-1.5 text-[12px] text-[var(--foreground-secondary)] font-medium">
          <GitBranch className="w-3.5 h-3.5 text-[var(--primary)]" />
          <span>Repositories scanned</span>
        </div>
        <div className="text-2xl font-semibold text-[var(--foreground)] tracking-tight">
          {totalRepositoriesScanned}
        </div>
        <div className="text-[11px] text-[var(--foreground-tertiary)]">
          Analyzed in local workspace
        </div>
      </div>

      {/* 2. Open Findings */}
      <div className="p-3.5 space-y-1">
        <div className="flex items-center gap-1.5 text-[12px] text-[var(--foreground-secondary)] font-medium">
          <AlertCircle className="w-3.5 h-3.5 text-[var(--warning)]" />
          <span>Open findings</span>
        </div>
        <div className="text-2xl font-semibold text-[var(--foreground)] tracking-tight">
          {riskScore.total_findings}
        </div>
        <div className="text-[11px] text-[var(--foreground-tertiary)]">
          Across code, secrets &amp; dependencies
        </div>
      </div>

      {/* 3. Critical & High Findings */}
      <div className="p-3.5 space-y-1">
        <div className="flex items-center gap-1.5 text-[12px] text-[var(--foreground-secondary)] font-medium">
          <ShieldAlert className="w-3.5 h-3.5 text-[var(--danger)]" />
          <span>Critical &amp; High</span>
        </div>
        <div className="text-2xl font-semibold text-[var(--danger)] tracking-tight">
          {criticalAndHigh}
        </div>
        <div className="text-[11px] text-[var(--foreground-tertiary)]">
          {riskScore.critical_count} critical, {riskScore.high_count} high
        </div>
      </div>

      {/* 4. Recently Resolved Findings */}
      <div className="p-3.5 space-y-1">
        <div className="flex items-center gap-1.5 text-[12px] text-[var(--foreground-secondary)] font-medium">
          <CheckCircle2 className="w-3.5 h-3.5 text-[var(--success)]" />
          <span>Resolved findings</span>
        </div>
        <div className="text-2xl font-semibold text-[var(--success)] tracking-tight">
          {resolvedCount}
        </div>
        <div className="text-[11px] text-[var(--foreground-tertiary)]">
          {resolvedCount > 0 ? "Verified fixed in baseline" : "Awaiting baseline comparison"}
        </div>
      </div>
    </div>
  );
}
