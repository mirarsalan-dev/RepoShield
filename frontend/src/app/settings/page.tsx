"use client";

import React, { useState, useEffect } from "react";
import {
  Key,
  HardDrive,
  Save,
  Check,
  ExternalLink,
  Trash2,
  Sliders,
  CheckCircle2,
  Sun,
  Moon,
  Monitor,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { useTheme } from "@/components/common/ThemeContext";

export default function SettingsPage() {
  const { theme, setTheme } = useTheme();
  const [githubToken, setGithubToken] = useState("");
  const [enableSecrets, setEnableSecrets] = useState(true);
  const [enableDeps, setEnableDeps] = useState(true);
  const [enableSast, setEnableSast] = useState(true);
  const [savedSuccess, setSavedSuccess] = useState(false);
  const [historyCount, setHistoryCount] = useState(0);

  useEffect(() => {
    const s = storage.getSettings();
    setGithubToken(s.githubToken || "");
    setEnableSecrets(s.enableSecrets);
    setEnableDeps(s.enableDependencies);
    setEnableSast(s.enableSast);

    const history = storage.getScanHistory();
    setHistoryCount(history.length);
  }, []);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    storage.saveSettings({
      githubToken: githubToken.trim(),
      enableSecrets,
      enableDependencies: enableDeps,
      enableSast,
    });
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 2500);
  };

  const handleClearHistory = () => {
    if (confirm("Purge all local scan records from browser storage?")) {
      storage.clearAllHistory();
      setHistoryCount(0);
    }
  };

  return (
    <div className="space-y-6 max-w-3xl mx-auto">
      {/* Page Header */}
      <div className="pb-4 border-b border-[var(--border-subtle)]">
        <h1 className="text-[26px] font-semibold tracking-tight text-[var(--foreground-primary)]">
          Settings
        </h1>
        <p className="text-[13px] text-[var(--foreground-secondary)] mt-0.5">
          Configure appearance, API credentials, default scanner engine policies, and local browser storage.
        </p>
      </div>

      {/* Section 0: macOS Appearance & Theme */}
      <div className="space-y-2">
        <div className="text-[12px] font-medium text-[var(--foreground-secondary)] uppercase tracking-wider px-1">
          Appearance
        </div>
        <div className="macos-panel p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-[13px] font-medium text-[var(--foreground-primary)]">
                Interface Appearance
              </div>
              <div className="text-[12px] text-[var(--foreground-secondary)] mt-0.5">
                Select your preferred macOS desktop theme or follow system settings.
              </div>
            </div>
            {/* macOS Segmented Theme Selector */}
            <div className="inline-flex items-center p-1 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border)]">
              <button
                type="button"
                onClick={() => setTheme("light")}
                className={`flex items-center gap-1.5 px-3 py-1 text-[12px] font-medium rounded-[4px] transition-all ${
                  theme === "light"
                    ? "bg-[var(--surface)] text-[var(--foreground-primary)] shadow-xs border border-[var(--border-subtle)]"
                    : "text-[var(--foreground-secondary)] hover:text-[var(--foreground-primary)]"
                }`}
              >
                <Sun className="w-3.5 h-3.5 text-[#FF9F0A]" />
                <span>Light</span>
              </button>
              <button
                type="button"
                onClick={() => setTheme("dark")}
                className={`flex items-center gap-1.5 px-3 py-1 text-[12px] font-medium rounded-[4px] transition-all ${
                  theme === "dark"
                    ? "bg-[var(--primary)] text-white shadow-xs"
                    : "text-[var(--foreground-secondary)] hover:text-[var(--foreground-primary)]"
                }`}
              >
                <Moon className="w-3.5 h-3.5" />
                <span>Dark</span>
              </button>
              <button
                type="button"
                onClick={() => setTheme("system")}
                className={`flex items-center gap-1.5 px-3 py-1 text-[12px] font-medium rounded-[4px] transition-all ${
                  theme === "system"
                    ? "bg-[var(--surface)] text-[var(--foreground-primary)] shadow-xs border border-[var(--border-subtle)]"
                    : "text-[var(--foreground-secondary)] hover:text-[var(--foreground-primary)]"
                }`}
              >
                <Monitor className="w-3.5 h-3.5" />
                <span>System</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      <form onSubmit={handleSave} className="space-y-6">
        {/* Section 1: GitHub API Authentication */}
        <div className="space-y-2">
          <div className="text-[12px] font-medium text-[var(--text-secondary)] uppercase tracking-wider px-1">
            Authentication &amp; Rate Limits
          </div>
          <div className="macos-panel p-4 space-y-3">
            <div className="flex items-center justify-between">
              <label htmlFor="githubToken" className="text-[13px] font-medium text-[var(--text-primary)] flex items-center gap-2">
                <Key className="w-4 h-4 text-[var(--accent)]" />
                <span>GitHub Personal Access Token (Optional)</span>
              </label>
              <a
                href="https://github.com/settings/tokens"
                target="_blank"
                rel="noreferrer"
                className="text-[12px] text-[var(--accent)] hover:underline flex items-center gap-1"
              >
                <span>Generate token</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>

            <p className="text-[12px] text-[var(--text-secondary)] leading-normal">
              Anonymous requests to the GitHub API are capped at 60 requests/hr per IP. Adding a read-only Personal Access Token increases your rate limit to 5,000 requests/hr for deeper repository inspections.
            </p>

            <div>
              <input
                id="githubToken"
                type="password"
                value={githubToken}
                onChange={(e) => setGithubToken(e.target.value)}
                placeholder="ghp_••••••••••••••••••••••••••••••••••••"
                suppressHydrationWarning
                className="macos-input w-full font-mono text-[12px]"
              />
              <p className="text-[11px] text-[var(--text-secondary)] mt-1.5">
                Token is stored strictly in your browser&apos;s <code className="font-mono text-[var(--text-primary)]">localStorage</code> and transmitted exclusively via authorized scan requests.
              </p>
            </div>
          </div>
        </div>

        {/* Section 2: Default Scanner Engines */}
        <div className="space-y-2">
          <div className="text-[12px] font-medium text-[var(--text-secondary)] uppercase tracking-wider px-1">
            Default Scanner Engines
          </div>
          <div className="macos-panel divide-y divide-[var(--border-subtle)] overflow-hidden">
            {/* Gitleaks */}
            <div className="p-3.5 flex items-center justify-between hover:bg-[var(--bg-secondary)] transition-colors">
              <div className="space-y-0.5 pr-4">
                <div className="text-[13px] font-medium text-[var(--text-primary)]">
                  Gitleaks (Secret Detection)
                </div>
                <div className="text-[12px] text-[var(--text-secondary)]">
                  Scans commits and source trees for leaked API keys, tokens, and private keys.
                </div>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={enableSecrets}
                  onChange={(e) => setEnableSecrets(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-9 h-5 bg-[var(--border-strong)] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-[var(--accent)]" />
              </label>
            </div>

            {/* Google OSV */}
            <div className="p-3.5 flex items-center justify-between hover:bg-[var(--bg-secondary)] transition-colors">
              <div className="space-y-0.5 pr-4">
                <div className="text-[13px] font-medium text-[var(--text-primary)]">
                  Google OSV (Dependency Vulnerabilities)
                </div>
                <div className="text-[12px] text-[var(--text-secondary)]">
                  Cross-references manifest packages with authoritative CVE and GHSA advisories.
                </div>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={enableDeps}
                  onChange={(e) => setEnableDeps(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-9 h-5 bg-[var(--border-strong)] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-[var(--accent)]" />
              </label>
            </div>

            {/* Semgrep */}
            <div className="p-3.5 flex items-center justify-between hover:bg-[var(--bg-secondary)] transition-colors">
              <div className="space-y-0.5 pr-4">
                <div className="text-[13px] font-medium text-[var(--text-primary)]">
                  Semgrep OSS (Static Application Security)
                </div>
                <div className="text-[12px] text-[var(--text-secondary)]">
                  Abstract syntax tree (AST) rules checking for injections, XSS, and security flaws.
                </div>
              </div>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={enableSast}
                  onChange={(e) => setEnableSast(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="w-9 h-5 bg-[var(--border-strong)] peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-[var(--accent)]" />
              </label>
            </div>
          </div>
        </div>

        {/* Section 3: Browser Storage & Cache */}
        <div className="space-y-2">
          <div className="text-[12px] font-medium text-[var(--text-secondary)] uppercase tracking-wider px-1">
            Storage &amp; Privacy
          </div>
          <div className="macos-panel p-4 space-y-3">
            <div className="flex items-center gap-2 text-[13px] font-medium text-[var(--text-primary)]">
              <HardDrive className="w-4 h-4 text-[var(--accent)]" />
              <span>Browser Local Storage Management</span>
            </div>
            <p className="text-[12px] text-[var(--text-secondary)] leading-relaxed">
              RepoShield enforces a strict zero-database policy. No scan results, credentials, or tokens are ever retained on remote servers. All historical scans reside strictly within this browser instance.
            </p>

            <div className="p-3 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] flex items-center justify-between text-[12px]">
              <div>
                <span className="text-[var(--text-secondary)]">Cached Local Scans: </span>
                <span className="font-semibold text-[var(--text-primary)]">{historyCount} records</span>
              </div>
              <button
                type="button"
                onClick={handleClearHistory}
                disabled={historyCount === 0}
                className="macos-button hover:text-[var(--system-red)] disabled:opacity-40"
              >
                <Trash2 className="w-3.5 h-3.5 mr-1" />
                <span>Purge Cache</span>
              </button>
            </div>
          </div>
        </div>

        {/* Action Bar */}
        <div className="flex items-center justify-between pt-2">
          {savedSuccess ? (
            <div className="flex items-center gap-1.5 text-[12px] font-medium text-[var(--system-green)]">
              <CheckCircle2 className="w-4 h-4" />
              <span>Preferences saved to local storage</span>
            </div>
          ) : (
            <span className="text-[12px] text-[var(--text-secondary)]">
              Settings persist across sessions in local storage.
            </span>
          )}

          <button
            type="submit"
            className="macos-button macos-button-primary"
          >
            <Save className="w-3.5 h-3.5 mr-1" />
            <span>Save Preferences</span>
          </button>
        </div>
      </form>
    </div>
  );
}
