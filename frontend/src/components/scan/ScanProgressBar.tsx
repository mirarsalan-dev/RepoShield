import React from "react";
import { ScanState } from "@/lib/types";
import { Loader2, CheckCircle2, XCircle, Clock } from "lucide-react";

interface ScanProgressBarProps {
  progress: number;
  currentStep: string;
  status: ScanState;
  elapsedSeconds?: number;
}

const STAGES = [
  { name: "Validation", minProgress: 10 },
  { name: "Repository Info", minProgress: 25 },
  { name: "Secrets Detection", minProgress: 45 },
  { name: "Dependencies (SCA)", minProgress: 65 },
  { name: "Code Analysis (SAST)", minProgress: 85 },
  { name: "Report Synthesis", minProgress: 100 },
];

export function ScanProgressBar({
  progress,
  currentStep,
  status,
  elapsedSeconds,
}: ScanProgressBarProps) {
  const isFailed = status === "FAILED" || status === "CANCELLED";
  const isCompleted = status === "COMPLETED";

  return (
    <div className="macos-panel p-4.5 space-y-3.5 border border-[var(--border)] rounded-[var(--radius-md)] bg-[var(--surface)]">
      {/* Top Labels: Status & Elapsed Time */}
      <div className="flex items-center justify-between text-[13px]">
        <div className="flex items-center gap-2">
          {isCompleted ? (
            <CheckCircle2 className="w-4 h-4 text-[var(--success)]" />
          ) : isFailed ? (
            <XCircle className="w-4 h-4 text-[var(--danger)]" />
          ) : (
            <Loader2 className="w-4 h-4 text-[var(--primary)] animate-spin" />
          )}
          <span className="font-medium text-[var(--foreground)]">
            {isCompleted
              ? "Scan Completed"
              : isFailed
              ? "Scan Terminated"
              : currentStep || "Analyzing repository security..."}
          </span>
        </div>

        <div className="flex items-center gap-3 font-mono text-[12px] text-[var(--foreground-secondary)]">
          {elapsedSeconds !== undefined && (
            <span className="flex items-center gap-1">
              <Clock className="w-3 h-3 text-[var(--foreground-tertiary)]" />
              <span>{elapsedSeconds.toFixed(1)}s</span>
            </span>
          )}
          <span className="font-semibold text-[var(--foreground)]">
            {Math.round(progress)}%
          </span>
        </div>
      </div>

      {/* Smooth Progress Track */}
      <div className="w-full h-2 rounded-full bg-[var(--surface-secondary)] overflow-hidden border border-[var(--border)]/50">
        <div
          className={`h-full rounded-full transition-all duration-[var(--motion-normal)] ease-out ${
            isCompleted
              ? "bg-[var(--success)]"
              : isFailed
              ? "bg-[var(--danger)]"
              : "bg-[var(--primary)]"
          }`}
          style={{ width: `${Math.max(4, Math.min(100, progress))}%` }}
        />
      </div>

      {/* Stage Checklist */}
      <div className="grid grid-cols-2 sm:grid-cols-6 gap-2 text-center text-[11px] text-[var(--foreground-tertiary)] pt-1">
        {STAGES.map((s) => {
          const isPassed = progress >= s.minProgress;
          return (
            <div
              key={s.name}
              className={`flex flex-col items-center gap-1.5 p-1 rounded-[var(--radius-sm)] ${
                isPassed ? "text-[var(--foreground)] font-medium" : ""
              }`}
            >
              <span
                className={`w-2 h-2 rounded-full transition-colors duration-[var(--motion-fast)] ${
                  isPassed ? "bg-[var(--primary)]" : "bg-[var(--border-strong)]"
                }`}
              />
              <span className="truncate">{s.name}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
