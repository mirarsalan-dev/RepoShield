"use client";

import React from "react";
import Link from "next/link";
import {
  X,
  Shield,
  Key,
  Package,
  Code2,
  HardDrive,
  Lock,
  ArrowRight,
} from "lucide-react";
import { MacTrafficLights, ShieldLogo } from "./Icons";
import { AnimatedDialog } from "@/components/motion";

interface DocumentationModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function DocumentationModal({ isOpen, onClose }: DocumentationModalProps) {
  return (
    <AnimatedDialog
      isOpen={isOpen}
      onClose={onClose}
      className="w-full max-w-2xl max-h-[85vh] overflow-y-auto macos-panel p-6 shadow-2xl flex flex-col space-y-5"
      ariaLabel="RepoShield Architecture & User Manual"
    >
        {/* Header */}
        <div className="flex items-center justify-between pb-3 border-b border-[var(--border-subtle)]">
          <div className="flex items-center gap-3">
            <MacTrafficLights />
            <div className="flex items-center gap-2">
              <ShieldLogo className="w-4 h-4 text-[var(--accent)]" />
              <h2 className="text-[15px] font-semibold text-[var(--text-primary)]">
                RepoShield Architecture &amp; User Manual
              </h2>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1 rounded-[6px] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-secondary)]"
            aria-label="Close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="space-y-5 text-[13px] text-[var(--text-secondary)] leading-relaxed">
          {/* Zero Database Privacy */}
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-[14px] font-semibold text-[var(--text-primary)]">
              <HardDrive className="w-4 h-4 text-[var(--accent)]" />
              <span>Zero-Database Architecture</span>
            </div>
            <p>
              RepoShield enforces strict zero-database isolation. No credentials, tokens, or repository code are ever persisted in databases (PostgreSQL, MySQL, MongoDB, Firebase, Supabase, Redis, or SQLite).
            </p>
            <ul className="list-disc pl-5 space-y-1 text-[var(--text-primary)] text-[12px]">
              <li>
                <strong>Ephemeral In-Memory Workers:</strong> Active scans execute in temporary sandboxes on the backend and are automatically purged upon completion (<code className="font-mono text-[var(--accent)]">SCAN_TTL_SECONDS = 1800</code>).
              </li>
              <li>
                <strong>Client Browser LocalStorage:</strong> Scan history, preferences, and redacted findings reside exclusively within your current browser&apos;s <code className="font-mono text-[var(--accent)]">localStorage</code>.
              </li>
            </ul>
          </div>

          {/* Integrated Engines */}
          <div className="space-y-3 pt-3 border-t border-[var(--border-subtle)]">
            <div className="text-[14px] font-semibold text-[var(--text-primary)] flex items-center gap-2">
              <Shield className="w-4 h-4 text-[var(--system-green)]" />
              <span>Integrated Scanner Suite</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="p-3 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] space-y-1">
                <div className="flex items-center gap-1.5 font-medium text-[var(--text-primary)] text-[12px]">
                  <Key className="w-3.5 h-3.5 text-[var(--system-red)]" />
                  <span>Gitleaks</span>
                </div>
                <p className="text-[11px] text-[var(--text-secondary)]">
                  Scans commits and trees for API tokens, passwords, and private keys. Findings are automatically pre-redacted.
                </p>
              </div>

              <div className="p-3 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] space-y-1">
                <div className="flex items-center gap-1.5 font-medium text-[var(--text-primary)] text-[12px]">
                  <Package className="w-3.5 h-3.5 text-[var(--system-orange)]" />
                  <span>Google OSV</span>
                </div>
                <p className="text-[11px] text-[var(--text-secondary)]">
                  Queries the live Google OSV batch API for npm and PyPI vulnerabilities with CVE, GHSA, and CVSS mappings.
                </p>
              </div>

              <div className="p-3 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] space-y-1">
                <div className="flex items-center gap-1.5 font-medium text-[var(--text-primary)] text-[12px]">
                  <Code2 className="w-3.5 h-3.5 text-[var(--accent)]" />
                  <span>Semgrep SAST</span>
                </div>
                <p className="text-[11px] text-[var(--text-secondary)]">
                  Static analysis checking Python, JS, and TypeScript for command injections, XSS, and SQLi flaws safely.
                </p>
              </div>
            </div>
          </div>

          {/* Rate Limits */}
          <div className="space-y-1.5 pt-3 border-t border-[var(--border-subtle)]">
            <div className="flex items-center gap-2 text-[14px] font-semibold text-[var(--text-primary)]">
              <Lock className="w-4 h-4 text-[var(--accent)]" />
              <span>GitHub API Rate Limits</span>
            </div>
            <p className="text-[12px]">
              Anonymous requests to the GitHub API are limited to 60 requests per hour per IP. To expand limits to 5,000 requests/hr, add a read-only GitHub Personal Access Token in the <a href="/settings" onClick={onClose} className="text-[var(--accent)] underline">Settings</a> page.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between pt-3 border-t border-[var(--border-subtle)]">
          <Link
            href="/how-it-works"
            onClick={onClose}
            className="inline-flex items-center gap-1.5 text-[12px] font-medium text-[var(--primary)] hover:underline"
          >
            <span>Explore Full Architecture &amp; Pipeline</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
          <button
            onClick={onClose}
            className="macos-button"
          >
            Close
          </button>
          </div>
    </AnimatedDialog>
  );
}
