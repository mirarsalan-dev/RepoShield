"use client";

import React from "react";
import Link from "next/link";
import {
  Key,
  Package,
  Code2,
  ArrowRight,
  ShieldCheck,
  CheckCircle2,
  GitBranch,
  SearchCode,
  Lock,
  ChevronRight,
} from "lucide-react";
import { MacTrafficLights, ShieldLogo } from "@/components/common/Icons";

export default function LandingPage() {
  return (
    <div className="space-y-16 py-4 max-w-5xl mx-auto">
      {/* Hero Section */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center pt-6">
        {/* Left Column: Heading, Supporting Text & CTAs */}
        <div className="lg:col-span-6 space-y-5">
          <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-[6px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] text-[12px] text-[var(--text-secondary)]">
            <ShieldCheck className="w-3.5 h-3.5 text-[var(--accent)]" />
            <span>Developer Security Platform</span>
          </div>

          <h1 className="text-[34px] md:text-[40px] font-semibold tracking-tight text-[var(--text-primary)] leading-[1.15]">
            Find vulnerabilities before they ship.
          </h1>

          <p className="text-[15px] text-[var(--text-secondary)] leading-relaxed max-w-md">
            Analyze GitHub repositories for exposed secrets, vulnerable dependencies, and insecure code.
          </p>

          <div className="flex items-center gap-3 pt-2">
            <Link
              href="/scan"
              className="macos-button macos-button-primary h-9 px-4 text-[13px]"
            >
              <SearchCode className="w-4 h-4" />
              <span>Scan a Repository</span>
            </Link>

            <Link
              href="/how-it-works"
              className="macos-button h-9 px-4 text-[13px]"
            >
              <span>How it works</span>
            </Link>
          </div>

          <div className="flex items-center gap-4 text-[12px] text-[var(--text-muted)] pt-2">
            <span className="flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5 text-[#34C759] dark:text-[#30D158]" />
              <span>Zero database storage</span>
            </span>
            <span className="flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5 text-[#34C759] dark:text-[#30D158]" />
              <span>Gitleaks • Semgrep • OSV</span>
            </span>
          </div>
        </div>

        {/* Right Column: Realistic macOS Window Preview */}
        <div className="lg:col-span-6">
          <div className="macos-window overflow-hidden shadow-xl border border-[var(--border-color)]">
            {/* Title Bar */}
            <div className="h-9 px-3.5 bg-[var(--bg-secondary)] border-b border-[var(--border-color)] flex items-center justify-between select-none">
              <div className="flex items-center gap-2">
                <MacTrafficLights />
                <span className="text-[11px] font-medium text-[var(--text-secondary)] pl-2">
                  RepoShield — pallets/flask
                </span>
              </div>
              <span className="text-[10px] font-mono text-[var(--text-muted)]">
                main:b2e1f48
              </span>
            </div>

            {/* Window Content / Mock Table */}
            <div className="p-3.5 bg-[var(--bg-surface)] space-y-2.5 text-[12px]">
              {/* Summary mini bar */}
              <div className="flex items-center justify-between p-2 rounded-[6px] bg-[var(--bg-secondary)] text-[11px]">
                <div className="flex items-center gap-2">
                  <span className="text-[var(--text-secondary)]">Security Posture:</span>
                  <span className="font-medium text-[#FF3B30] dark:text-[#FF453A]">High Risk (97.1)</span>
                </div>
                <div className="flex items-center gap-3 font-mono text-[var(--text-muted)]">
                  <span>33 findings</span>
                  <span>•</span>
                  <span>1.4s scan</span>
                </div>
              </div>

              {/* Sample Table Rows */}
              <div className="border border-[var(--border-subtle)] rounded-[6px] divide-y divide-[var(--border-subtle)] overflow-hidden">
                <div className="px-3 py-2 flex items-center justify-between bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)]">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="w-2 h-2 rounded-full bg-[#FF3B30] flex-shrink-0" />
                    <span className="font-medium text-[var(--text-primary)] truncate">AWS Access Token Leaked</span>
                  </div>
                  <span className="text-[11px] font-mono text-[var(--text-muted)]">tests/conftest.py:L14</span>
                </div>

                <div className="px-3 py-2 flex items-center justify-between bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)]">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="w-2 h-2 rounded-full bg-[#FF9500] flex-shrink-0" />
                    <span className="font-medium text-[var(--text-primary)] truncate">jinja2 ReDoS (CVE-2020-28493)</span>
                  </div>
                  <span className="text-[11px] font-mono text-[var(--text-muted)]">requirements.txt</span>
                </div>

                <div className="px-3 py-2 flex items-center justify-between bg-[var(--bg-surface)] hover:bg-[var(--bg-hover)]">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="w-2 h-2 rounded-full bg-[#FF9500] flex-shrink-0" />
                    <span className="font-medium text-[var(--text-primary)] truncate">Command Injection in exec()</span>
                  </div>
                  <span className="text-[11px] font-mono text-[var(--text-muted)]">src/flask/cli.py:L88</span>
                </div>
              </div>

              <div className="flex items-center justify-between pt-1 text-[11px] text-[var(--text-muted)]">
                <span>Deterministic scoring algorithm</span>
                <span className="font-mono">100% credential redaction</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Capabilities Section (3 Columns) */}
      <div className="space-y-4 pt-8 border-t border-[var(--border-color)]">
        <div className="space-y-1">
          <h2 className="text-[18px] font-semibold text-[var(--text-primary)] tracking-tight">
            Security Analysis Engines
          </h2>
          <p className="text-[13px] text-[var(--text-secondary)]">
            Built directly on top of established open-source security intelligence tools.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
          {/* 1. Secret Detection */}
          <div className="macos-panel p-4 space-y-2.5">
            <div className="w-8 h-8 rounded-[6px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] flex items-center justify-center text-[var(--accent)]">
              <Key className="w-4 h-4" />
            </div>
            <h3 className="text-[14px] font-semibold text-[var(--text-primary)]">
              Secret Detection
            </h3>
            <p className="text-[13px] text-[var(--text-secondary)] leading-relaxed">
              Scans commit history and active source trees for leaked API keys, tokens, SSH private keys, and certificates with Gitleaks.
            </p>
          </div>

          {/* 2. Dependency Analysis */}
          <div className="macos-panel p-4 space-y-2.5">
            <div className="w-8 h-8 rounded-[6px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] flex items-center justify-center text-[var(--accent)]">
              <Package className="w-4 h-4" />
            </div>
            <h3 className="text-[14px] font-semibold text-[var(--text-primary)]">
              Dependency Analysis
            </h3>
            <p className="text-[13px] text-[var(--text-secondary)] leading-relaxed">
              Cross-references declared package manifests with the live Google OSV vulnerability database for known CVEs and GHSA advisories.
            </p>
          </div>

          {/* 3. Static Code Analysis */}
          <div className="macos-panel p-4 space-y-2.5">
            <div className="w-8 h-8 rounded-[6px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] flex items-center justify-center text-[var(--accent)]">
              <Code2 className="w-4 h-4" />
            </div>
            <h3 className="text-[14px] font-semibold text-[var(--text-primary)]">
              Static Code Analysis
            </h3>
            <p className="text-[13px] text-[var(--text-secondary)] leading-relaxed">
              Executes Semgrep abstract syntax tree (AST) security rules to detect SQL injection, SSRF, path traversals, and unsafe functions.
            </p>
          </div>
        </div>
      </div>

      {/* How it Works Section */}
      <div id="how-it-works" className="space-y-4 pt-6 border-t border-[var(--border-color)]">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <div className="space-y-1">
            <h2 className="text-[18px] font-semibold text-[var(--text-primary)] tracking-tight">
              How It Works
            </h2>
            <p className="text-[13px] text-[var(--text-secondary)]">
              A three-step verification workflow with zero data retention.
            </p>
          </div>
          <Link
            href="/how-it-works"
            className="text-[12px] font-medium text-[var(--accent)] hover:underline flex items-center gap-1 self-start sm:self-auto"
          >
            <span>Explore deep dive</span>
            <ChevronRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2 text-[13px]">
          <div className="p-4 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] space-y-1.5">
            <div className="text-[11px] font-mono text-[var(--accent)] font-semibold">Step 01</div>
            <div className="font-semibold text-[var(--text-primary)]">Specify Repository</div>
            <div className="text-[var(--text-secondary)] text-[12px] leading-relaxed">
              Provide any public GitHub repository URL. RepoShield retrieves metadata and performs Zip-Slip safe extraction.
            </div>
          </div>

          <div className="p-4 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] space-y-1.5">
            <div className="text-[11px] font-mono text-[var(--accent)] font-semibold">Step 02</div>
            <div className="font-semibold text-[var(--text-primary)]">Concurrent Analysis</div>
            <div className="text-[var(--text-secondary)] text-[12px] leading-relaxed">
              Scanners analyze credentials, package versions, and code in an isolated temporary in-memory session.
            </div>
          </div>

          <div className="p-4 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] space-y-1.5">
            <div className="text-[11px] font-mono text-[var(--accent)] font-semibold">Step 03</div>
            <div className="font-semibold text-[var(--text-primary)]">Review &amp; Export</div>
            <div className="text-[var(--text-secondary)] text-[12px] leading-relaxed">
              Inspect redacted evidence, copy remediation instructions, or export audit reports in PDF, CSV, or JSON.
            </div>
          </div>
        </div>
      </div>

      {/* Final Action Strip */}
      <div className="macos-panel p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h3 className="text-[16px] font-semibold text-[var(--text-primary)]">
            Ready to inspect your repository?
          </h3>
          <p className="text-[13px] text-[var(--text-secondary)] mt-0.5">
            Instant security assessment without server database configuration.
          </p>
        </div>

        <Link
          href="/scan"
          className="macos-button macos-button-primary h-9 px-4 text-[13px] self-start sm:self-auto"
        >
          <SearchCode className="w-4 h-4" />
          <span>Analyze a Repository</span>
        </Link>
      </div>
    </div>
  );
}
