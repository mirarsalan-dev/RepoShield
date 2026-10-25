import React from "react";
import { AlertCircle, RotateCcw } from "lucide-react";

interface ErrorStateProps {
  title?: string;
  message: string;
  onRetry?: () => void;
  className?: string;
}

export function ErrorState({
  title = "An error occurred",
  message,
  onRetry,
  className = "",
}: ErrorStateProps) {
  return (
    <div
      role="alert"
      className={`macos-panel p-6 max-w-lg mx-auto my-8 border border-[var(--danger)]/30 rounded-[var(--radius-md)] bg-[var(--surface)] text-center space-y-3 ${className}`}
    >
      <div className="w-10 h-10 rounded-[var(--radius-md)] bg-[var(--danger)]/10 text-[var(--danger)] flex items-center justify-center mx-auto">
        <AlertCircle className="w-5 h-5" />
      </div>
      <div>
        <h3 className="text-[15px] font-semibold text-[var(--foreground)] tracking-tight">
          {title}
        </h3>
        <p className="text-[13px] text-[var(--foreground-secondary)] mt-1 max-w-md mx-auto leading-relaxed">
          {message}
        </p>
      </div>

      {onRetry && (
        <div className="pt-2">
          <button onClick={onRetry} className="btn-secondary">
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Try Again</span>
          </button>
        </div>
      )}
    </div>
  );
}
