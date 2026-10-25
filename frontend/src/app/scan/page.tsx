"use client";

import React, { useState, useEffect, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import {
  Search,
  GitBranch,
  ShieldAlert,
  Key,
  Package,
  Code2,
  CheckCircle2,
  AlertCircle,
  Play,
  RotateCcw,
  ExternalLink,
  Star,
  GitFork,
  Clock,
  Layers,
  ArrowRight,
  StopCircle,
  HelpCircle,
} from "lucide-react";
import { api } from "@/lib/api";
import { storage } from "@/lib/storage";
import {
  RepositoryMetadata,
  BranchInfo,
  ScanResult,
  ScanState,
} from "@/lib/types";
import { PageHeader } from "@/components/common/PageHeader";
import { ScanProgressBar } from "@/components/scan/ScanProgressBar";
import { ScanTerminal } from "@/components/scan/ScanTerminal";
import { GithubIcon } from "@/components/common/Icons";
import { useToast } from "@/components/common/ToastProvider";

function ScanContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const initialUrl = searchParams.get("repo") || "";
  const toast = useToast();

  // Form inputs
  const [repoUrl, setRepoUrl] = useState(initialUrl);
  const [selectedBranch, setSelectedBranch] = useState("main");
  const [commitSha, setCommitSha] = useState("");
  const [enableSecrets, setEnableSecrets] = useState(true);
  const [enableDeps, setEnableDeps] = useState(true);
  const [enableSast, setEnableSast] = useState(true);
  const [enableInfrastructure, setEnableInfrastructure] = useState(true);

  // Metadata & validation state
  const [isValidating, setIsValidating] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [repoMetadata, setRepoMetadata] = useState<RepositoryMetadata | null>(null);
  const [branches, setBranches] = useState<BranchInfo[]>([]);

  // Scan execution state
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);

  useEffect(() => {
    const s = storage.getSettings();
    setEnableSecrets(s.enableSecrets);
    setEnableDeps(s.enableDependencies);
    setEnableSast(s.enableSast);
  }, []);

  useEffect(() => {
    if (initialUrl) {
      validateAndFetchInfo(initialUrl);
    }
  }, [initialUrl]);

  useEffect(() => {
    let interval: NodeJS.Timeout;
    if (isScanning) {
      const startTime = Date.now();
      interval = setInterval(() => {
        setElapsedSeconds((Date.now() - startTime) / 1000);
      }, 200);
    }
    return () => clearInterval(interval);
  }, [isScanning]);

  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (activeScanId && isScanning) {
      const poll = async () => {
        try {
          const res = await api.getScanStatus(activeScanId);
          setScanResult(res);

          if (res.status === "COMPLETED") {
            setIsScanning(false);
            storage.saveScan(res);
            toast.success(
              "Scan Completed",
              `Found ${res.findings.length} findings in ${res.owner}/${res.repo}.`
            );
          } else if (res.status === "FAILED" || res.status === "CANCELLED") {
            setIsScanning(false);
            const err = res.error_detail || "Scan terminated unexpectedly.";
            setScanError(err);
            toast.error("Scan Failed", err);
          } else {
            timer = setTimeout(poll, 1200);
          }
        } catch (err: any) {
          setIsScanning(false);
          const msg = err.message || "Failed to retrieve scan status.";
          setScanError(msg);
          toast.error("Network Error", msg);
        }
      };
      poll();
    }
    return () => clearTimeout(timer);
  }, [activeScanId, isScanning, toast]);

  const validateAndFetchInfo = async (urlToValidate: string) => {
    if (!urlToValidate.trim()) return;
    setIsValidating(true);
    setValidationError(null);
    setRepoMetadata(null);
    setBranches([]);

    try {
      await api.validateRepoUrl(urlToValidate);

      const settings = storage.getSettings();
      const meta = await api.getRepoInfo(urlToValidate, settings.githubToken);
      setRepoMetadata(meta);
      setSelectedBranch(meta.default_branch || "main");

      try {
        const b = await api.getBranches(urlToValidate, settings.githubToken);
        setBranches(b);
      } catch {
        setBranches([
          { name: meta.default_branch, commit_sha: "", protected: false },
        ]);
      }
    } catch (err: any) {
      const msg = err.message || "Failed to validate repository URL. Ensure it follows https://github.com/owner/repo format.";
      setValidationError(msg);
    } finally {
      setIsValidating(false);
    }
  };

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!repoUrl.trim() || isScanning) return;

    setIsScanning(true);
    setScanError(null);
    setScanResult(null);
    setElapsedSeconds(0);

    try {
      const settings = storage.getSettings();
      const res = await api.startScan({
        repo_url: repoUrl.trim(),
        branch: selectedBranch,
        commit_sha: commitSha.trim() || undefined,
        github_token: settings.githubToken || undefined,
        enable_secrets: enableSecrets,
        enable_dependencies: enableDeps,
        enable_sast: enableSast,
        enable_infrastructure: enableInfrastructure,
      });

      setActiveScanId(res.scan_id);
      toast.info("Scan Started", `Analyzing ${repoUrl.trim()}...`);
    } catch (err: any) {
      setIsScanning(false);
      const msg = err.message || "Failed to initiate scan.";
      setScanError(msg);
      toast.error("Execution Error", msg);
    }
  };

  const handleCancelScan = async () => {
    if (!activeScanId) return;
    try {
      await api.cancelScan(activeScanId);
      setIsScanning(false);
      toast.warning("Scan Cancelled", "The analysis process was stopped.");
    } catch {
      // Ignored
    }
  };

  return (
    <div className="space-y-6 max-w-3xl mx-auto">
      {/* Page Header */}
      <PageHeader
        title="New Scan"
        description="Audit authorized public GitHub repositories using real-time static and secret analysis."
      />

      {/* Main Configuration Panel */}
      <div className="macos-panel p-5.5 space-y-5 border border-[var(--border)] rounded-[var(--radius-md)] bg-[var(--surface)]">
        <form onSubmit={handleStartScan} className="space-y-4">
          {/* Repository URL Input */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <label className="block text-[12.5px] font-medium text-[var(--foreground)]">
                GitHub Repository URL
              </label>
              <span className="text-[11px] text-[var(--foreground-tertiary)]">
                Example: https://github.com/pallets/flask
              </span>
            </div>

            <div className="flex flex-col sm:flex-row gap-2">
              <div className="relative flex-1">
                <GithubIcon className="w-4 h-4 text-[var(--foreground-tertiary)] absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  type="url"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  onBlur={() => repoUrl.trim() && validateAndFetchInfo(repoUrl.trim())}
                  placeholder="https://github.com/owner/repository"
                  className="macos-input w-full pl-9 font-mono text-[12.5px]"
                  disabled={isScanning}
                  required
                />
              </div>

              <button
                type="button"
                onClick={() => validateAndFetchInfo(repoUrl.trim())}
                disabled={isValidating || !repoUrl.trim() || isScanning}
                className="btn-secondary h-9 text-[12.5px] px-3.5 flex-shrink-0"
              >
                {isValidating ? "Validating..." : "Verify URL"}
              </button>
            </div>

            {validationError && (
              <div className="p-3 rounded-[var(--radius-sm)] bg-[var(--danger)]/10 border border-[var(--danger)]/20 text-[12px] text-[var(--danger)] flex items-start gap-2">
                <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                <span>{validationError}</span>
              </div>
            )}
          </div>

          {/* Repository Metadata Card if Verified */}
          {repoMetadata && (
            <div className="p-3.5 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border)] space-y-2 text-[12px]">
              <div className="flex items-center justify-between">
                <div className="font-semibold text-[var(--foreground)] text-[13px]">
                  {repoMetadata.full_name}
                </div>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded-[var(--radius-sm)] bg-[var(--surface)] border border-[var(--border)] text-[var(--foreground-secondary)]">
                  {repoMetadata.primary_language || "Unknown Language"}
                </span>
              </div>
              <p className="text-[var(--foreground-secondary)] text-[12px] line-clamp-1">
                {repoMetadata.description || "Public GitHub repository verified."}
              </p>
              <div className="flex items-center gap-4 text-[11px] text-[var(--foreground-tertiary)] pt-1 border-t border-[var(--border)]">
                <span>Stars: {repoMetadata.stars.toLocaleString()}</span>
                <span>Forks: {repoMetadata.forks.toLocaleString()}</span>
                <span>Default Branch: {repoMetadata.default_branch}</span>
              </div>
            </div>
          )}

          {/* Branch & Commit Selection */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 pt-1">
            <div className="space-y-1">
              <label className="block text-[12.5px] font-medium text-[var(--foreground)]">
                Target Branch
              </label>
              {branches.length > 0 ? (
                <select
                  value={selectedBranch}
                  onChange={(e) => setSelectedBranch(e.target.value)}
                  disabled={isScanning}
                  className="macos-select w-full text-[12.5px] cursor-pointer"
                >
                  {branches.map((b) => (
                    <option key={b.name} value={b.name}>
                      {b.name}
                    </option>
                  ))}
                </select>
              ) : (
                <input
                  type="text"
                  value={selectedBranch}
                  onChange={(e) => setSelectedBranch(e.target.value)}
                  placeholder="main"
                  className="macos-input w-full font-mono text-[12.5px]"
                  disabled={isScanning}
                />
              )}
            </div>

            <div className="space-y-1">
              <label className="block text-[12.5px] font-medium text-[var(--foreground)]">
                Commit SHA (Optional)
              </label>
              <input
                type="text"
                value={commitSha}
                onChange={(e) => setCommitSha(e.target.value)}
                placeholder="HEAD"
                className="macos-input w-full font-mono text-[12.5px]"
                disabled={isScanning}
              />
            </div>
          </div>

          {/* Scanning Engines Configuration Pills */}
          <div className="pt-2 space-y-2">
            <div className="text-[12.5px] font-medium text-[var(--foreground)]">
              Configured Security Scanners
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5 text-[12px]">
              <label className="flex items-center gap-2.5 p-2.5 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border)] cursor-pointer hover:bg-[var(--surface-hover)] transition-colors">
                <input
                  type="checkbox"
                  checked={enableSecrets}
                  onChange={(e) => setEnableSecrets(e.target.checked)}
                  disabled={isScanning}
                  className="rounded text-[var(--primary)] focus:ring-[var(--focus-ring)]"
                />
                <div>
                  <div className="font-medium text-[var(--foreground)]">Gitleaks</div>
                  <div className="text-[11px] text-[var(--foreground-tertiary)]">Secrets &amp; Leaks</div>
                </div>
              </label>

              <label className="flex items-center gap-2.5 p-2.5 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border)] cursor-pointer hover:bg-[var(--surface-hover)] transition-colors">
                <input
                  type="checkbox"
                  checked={enableDeps}
                  onChange={(e) => setEnableDeps(e.target.checked)}
                  disabled={isScanning}
                  className="rounded text-[var(--primary)] focus:ring-[var(--focus-ring)]"
                />
                <div>
                  <div className="font-medium text-[var(--foreground)]">Google OSV</div>
                  <div className="text-[11px] text-[var(--foreground-tertiary)]">Dependencies</div>
                </div>
              </label>

              <label className="flex items-center gap-2.5 p-2.5 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border)] cursor-pointer hover:bg-[var(--surface-hover)] transition-colors">
                <input
                  type="checkbox"
                  checked={enableSast}
                  onChange={(e) => setEnableSast(e.target.checked)}
                  disabled={isScanning}
                  className="rounded text-[var(--primary)] focus:ring-[var(--focus-ring)]"
                />
                <div>
                  <div className="font-medium text-[var(--foreground)]">Semgrep</div>
                  <div className="text-[11px] text-[var(--foreground-tertiary)]">SAST Code Rules</div>
                </div>
              </label>

              <label className="flex items-center gap-2.5 p-2.5 rounded-[var(--radius-sm)] bg-[var(--surface-secondary)] border border-[var(--border)] cursor-pointer hover:bg-[var(--surface-hover)] transition-colors">
                <input
                  type="checkbox"
                  checked={enableInfrastructure}
                  onChange={(e) => setEnableInfrastructure(e.target.checked)}
                  disabled={isScanning}
                  className="rounded text-[var(--primary)] focus:ring-[var(--focus-ring)]"
                />
                <div>
                  <div className="font-medium text-[var(--foreground)]">ConfigAudit</div>
                  <div className="text-[11px] text-[var(--foreground-tertiary)]">IaC &amp; CI/CD</div>
                </div>
              </label>
            </div>
          </div>

          {/* Action Row */}
          <div className="pt-3 border-t border-[var(--border)] flex items-center justify-between">
            <span className="text-[11px] font-mono text-[var(--foreground-tertiary)]">
              Stateless in-memory scanner runtime
            </span>

            <div className="flex items-center gap-2">
              {isScanning ? (
                <button
                  type="button"
                  onClick={handleCancelScan}
                  className="btn-destructive"
                >
                  <StopCircle className="w-3.5 h-3.5" />
                  <span>Cancel Scan</span>
                </button>
              ) : (
                <button
                  type="submit"
                  disabled={!repoUrl.trim() || isValidating}
                  className="btn-primary"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Start Security Scan</span>
                </button>
              )}
            </div>
          </div>
        </form>
      </div>

      {/* Live Scan Experience (Progress + Logs) */}
      {(isScanning || scanResult) && (
        <div className="space-y-4">
          <ScanProgressBar
            progress={scanResult?.progress || (isScanning ? 15 : 0)}
            currentStep={scanResult?.current_step || "Initializing..."}
            status={scanResult?.status || "QUEUED"}
            elapsedSeconds={elapsedSeconds}
          />

          <ScanTerminal
            logs={scanResult?.logs || []}
            activeStep={scanResult?.current_step}
            isScanning={isScanning}
          />

          {scanResult?.status === "COMPLETED" && (
            <div className="macos-panel p-4 flex items-center justify-between bg-[var(--surface-secondary)] border border-[var(--border)] rounded-[var(--radius-md)]">
              <div>
                <div className="font-semibold text-[14px] text-[var(--foreground)]">
                  Scan Completed Successfully
                </div>
                <div className="text-[12px] text-[var(--foreground-secondary)] mt-0.5">
                  Found {scanResult.findings.length} security issues in {scanResult.duration_seconds}s.
                </div>
              </div>
              <Link
                href="/results"
                className="btn-primary"
              >
                <span>View Findings</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            </div>
          )}

          {scanError && (
            <div className="p-3 rounded-[var(--radius-sm)] bg-[var(--danger)]/10 border border-[var(--danger)]/20 text-[12.5px] text-[var(--danger)]">
              <strong>Scan error:</strong> {scanError}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function ScanPage() {
  return (
    <Suspense
      fallback={
        <div className="text-[12px] text-[var(--foreground-tertiary)] font-mono">
          Loading scanner...
        </div>
      }
    >
      <ScanContent />
    </Suspense>
  );
}
