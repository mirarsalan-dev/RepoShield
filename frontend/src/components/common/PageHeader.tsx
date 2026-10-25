import React, { ReactNode } from "react";

interface PageHeaderProps {
  title: string;
  description?: string;
  badge?: ReactNode;
  actions?: ReactNode;
  className?: string;
}

export function PageHeader({
  title,
  description,
  badge,
  actions,
  className = "",
}: PageHeaderProps) {
  return (
    <div
      className={`flex flex-col sm:flex-row sm:items-center justify-between gap-3.5 pb-4 border-b border-[var(--border)] ${className}`}
    >
      <div className="space-y-0.5 min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2.5">
          <h1 className="text-[26px] font-semibold tracking-tight text-[var(--foreground)] leading-tight shrink-0">
            {title}
          </h1>
          {badge}
        </div>
        {description && (
          <p className="text-[13px] text-[var(--foreground-secondary)] leading-relaxed">
            {description}
          </p>
        )}
      </div>

      {actions && (
        <div className="flex flex-wrap items-center gap-2 flex-shrink-0">
          {actions}
        </div>
      )}
    </div>
  );
}
