"use client";

import React, { useEffect, useRef, useState } from "react";
import { Terminal, Copy, Check } from "lucide-react";

interface ScanTerminalProps {
  logs: string[];
  activeStep?: string;
  isScanning?: boolean;
}

export function ScanTerminal({ logs, activeStep, isScanning = false }: ScanTerminalProps) {
  const terminalEndRef = useRef<HTMLDivElement>(null);
  const [copied, setCopied] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);

  useEffect(() => {
    if (autoScroll && terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs, autoScroll]);

  const handleCopy = () => {
    navigator.clipboard.writeText(logs.join("\n"));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="macos-panel overflow-hidden flex flex-col h-[280px] font-mono text-[12px]">
      {/* Title Bar */}
      <div className="flex items-center justify-between px-3.5 py-2 bg-[var(--bg-secondary)] border-b border-[var(--border-subtle)] select-none">
        <div className="flex items-center gap-2">
          <Terminal className="w-3.5 h-3.5 text-[var(--text-secondary)]" />
          <span className="text-[12px] font-medium text-[var(--text-primary)]">
            Execution Console
          </span>
        </div>

        <div className="flex items-center gap-2 text-[11px]">
          <button
            onClick={handleCopy}
            className="flex items-center gap-1 text-[var(--text-secondary)] hover:text-[var(--text-primary)] px-2 py-0.5 rounded hover:bg-[var(--bg-hover)] transition-colors"
          >
            {copied ? (
              <>
                <Check className="w-3 h-3 text-[#34C759]" />
                <span className="text-[#34C759]">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3 h-3" />
                <span>Copy</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Log Feed */}
      <div className="flex-1 p-3.5 overflow-y-auto space-y-1 bg-[var(--bg-surface)] text-[var(--text-secondary)] select-text leading-relaxed">
        {logs.length === 0 ? (
          <div className="text-[var(--text-muted)] italic">Awaiting scanner invocation...</div>
        ) : (
          logs.map((log, idx) => {
            const isError = log.includes("failed") || log.includes("error") || log.includes("FAILED");
            const isSuccess = log.includes("complete") || log.includes("success") || log.includes("COMPLETED");

            return (
              <div
                key={idx}
                className={`break-all ${
                  isError
                    ? "text-[#FF3B30] dark:text-[#FF453A]"
                    : isSuccess
                    ? "text-[#34C759] dark:text-[#30D158]"
                    : "text-[var(--text-primary)]"
                }`}
              >
                {log}
              </div>
            );
          })
        )}
        {isScanning && (
          <div className="flex items-center gap-1 text-[var(--text-muted)] pt-0.5">
            <span className="text-[var(--accent)]">›</span>
            <span className="text-[var(--text-secondary)] italic">{activeStep || "Processing..."}</span>
          </div>
        )}
        <div ref={terminalEndRef} />
      </div>

      {/* Footer Bar */}
      <div className="px-3.5 py-1.5 bg-[var(--bg-secondary)] border-t border-[var(--border-subtle)] flex items-center justify-between text-[11px] text-[var(--text-muted)]">
        <span>{logs.length} lines</span>
        <button
          onClick={() => setAutoScroll(!autoScroll)}
          className={`hover:text-[var(--text-primary)] ${autoScroll ? "text-[var(--accent)]" : "text-[var(--text-muted)]"}`}
        >
          Auto-scroll: {autoScroll ? "On" : "Off"}
        </button>
      </div>
    </div>
  );
}
