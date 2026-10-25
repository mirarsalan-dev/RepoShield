import React from "react";
import { Severity } from "@/lib/types";
import { getSeverityBadgeClass, getSeverityDotClass } from "@/lib/utils";

interface SeverityBadgeProps {
  severity: Severity;
  className?: string;
  showDot?: boolean;
}

export function SeverityBadge({
  severity,
  className = "",
  showDot = true,
}: SeverityBadgeProps) {
  const badgeClass = getSeverityBadgeClass(severity);
  const dotClass = getSeverityDotClass(severity);

  // Capitalize properly: Critical, High, Medium, Low, Info
  const formattedSeverity =
    severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase();

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-[var(--radius-sm)] border text-[11.5px] font-medium leading-none select-none ${badgeClass} ${className}`}
    >
      {showDot && (
        <span className={`w-1.5 h-1.5 rounded-full ${dotClass} flex-shrink-0`} />
      )}
      <span>{formattedSeverity}</span>
    </span>
  );
}
