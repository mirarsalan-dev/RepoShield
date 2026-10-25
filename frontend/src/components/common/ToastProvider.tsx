"use client";

import React, { createContext, useContext, useState, useCallback, ReactNode } from "react";
import { CheckCircle2, AlertCircle, AlertTriangle, Info, X } from "lucide-react";

export type ToastType = "success" | "error" | "warning" | "info";

export interface ToastItem {
  id: string;
  type: ToastType;
  title: string;
  description?: string;
  duration?: number;
}

interface ToastContextType {
  toast: (item: Omit<ToastItem, "id">) => void;
  success: (title: string, description?: string) => void;
  error: (title: string, description?: string) => void;
  warning: (title: string, description?: string) => void;
  info: (title: string, description?: string) => void;
  dismiss: (id: string) => void;
}

const ToastContext = createContext<ToastContextType | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const addToast = useCallback(
    ({ type, title, description, duration }: Omit<ToastItem, "id">) => {
      const id = Math.random().toString(36).substring(2, 9);
      const autoDismissDuration =
        duration ?? (type === "error" ? 7000 : type === "warning" ? 5000 : 3500);

      setToasts((prev) => {
        // Keep maximum 4 concurrent toasts to prevent stacking overload
        const slice = prev.length >= 4 ? prev.slice(1) : prev;
        return [...slice, { id, type, title, description, duration: autoDismissDuration }];
      });

      if (autoDismissDuration > 0) {
        setTimeout(() => {
          dismiss(id);
        }, autoDismissDuration);
      }
    },
    [dismiss]
  );

  const success = useCallback(
    (title: string, description?: string) => addToast({ type: "success", title, description }),
    [addToast]
  );

  const error = useCallback(
    (title: string, description?: string) => addToast({ type: "error", title, description }),
    [addToast]
  );

  const warning = useCallback(
    (title: string, description?: string) => addToast({ type: "warning", title, description }),
    [addToast]
  );

  const info = useCallback(
    (title: string, description?: string) => addToast({ type: "info", title, description }),
    [addToast]
  );

  return (
    <ToastContext.Provider value={{ toast: addToast, success, error, warning, info, dismiss }}>
      {children}
      {/* Toast Render Viewport */}
      <div
        aria-live="polite"
        aria-atomic="true"
        className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none select-none px-3"
      >
        {toasts.map((t) => {
          const Icon =
            t.type === "success"
              ? CheckCircle2
              : t.type === "error"
              ? AlertCircle
              : t.type === "warning"
              ? AlertTriangle
              : Info;

          const iconColor =
            t.type === "success"
              ? "text-[var(--success)]"
              : t.type === "error"
              ? "text-[var(--danger)]"
              : t.type === "warning"
              ? "text-[var(--warning)]"
              : "text-[var(--info)]";

          return (
            <div
              key={t.id}
              role="alert"
              className="pointer-events-auto flex items-start gap-3 p-3.5 rounded-[var(--radius-md)] bg-[var(--surface)] border border-[var(--border)] text-[var(--foreground)] shadow-[var(--shadow-popover)] transition-all duration-200 animate-in fade-in slide-in-from-bottom-2"
            >
              <Icon className={`w-4 h-4 flex-shrink-0 mt-0.5 ${iconColor}`} />
              <div className="flex-1 min-w-0">
                <div className="text-[13px] font-medium leading-snug">{t.title}</div>
                {t.description && (
                  <div className="text-[12px] text-[var(--foreground-secondary)] mt-0.5 leading-relaxed">
                    {t.description}
                  </div>
                )}
              </div>
              <button
                onClick={() => dismiss(t.id)}
                className="p-1 rounded-[var(--radius-sm)] text-[var(--foreground-tertiary)] hover:text-[var(--foreground)] hover:bg-[var(--surface-hover)] transition-colors flex-shrink-0"
                aria-label="Dismiss notification"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error("useToast must be used within a ToastProvider");
  }
  return context;
}
