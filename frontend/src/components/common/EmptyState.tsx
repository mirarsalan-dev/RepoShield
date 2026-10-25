import React from "react";
import Link from "next/link";
import { LucideIcon, ShieldQuestion } from "lucide-react";

interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description: string;
  actionText?: string;
  actionHref?: string;
  onAction?: () => void;
  className?: string;
}

export function EmptyState({
  icon: Icon = ShieldQuestion,
  title,
  description,
  actionText,
  actionHref,
  onAction,
  className = "",
}: EmptyStateProps) {
  return (
    <div
      className={`macos-panel p-9 text-center max-w-md mx-auto my-10 space-y-3.5 border border-[var(--border)] rounded-[var(--radius-md)] bg-[var(--surface)] ${className}`}
    >
      <div className="w-10 h-10 rounded-[var(--radius-md)] bg-[var(--surface-secondary)] border border-[var(--border)] flex items-center justify-center mx-auto text-[var(--foreground-secondary)]">
        <Icon className="w-5 h-5 text-[var(--primary)]" />
      </div>
      <div className="space-y-1">
        <h3 className="text-[15px] font-semibold text-[var(--foreground)] tracking-tight">
          {title}
        </h3>
        <p className="text-[13px] text-[var(--foreground-secondary)] leading-normal max-w-sm mx-auto">
          {description}
        </p>
      </div>

      {actionText && (actionHref || onAction) && (
        <div className="pt-2">
          {actionHref ? (
            <Link href={actionHref} className="btn-primary">
              {actionText}
            </Link>
          ) : (
            <button onClick={onAction} className="btn-primary">
              {actionText}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
