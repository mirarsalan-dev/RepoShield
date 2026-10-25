"use client";

import React, { useState, useEffect } from "react";
import {
  ShieldCheck,
  Check,
  Download,
  Upload,
  RotateCcw,
  Play,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Copy,
  Trash2,
  FileCode,
  Calendar,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { api } from "@/lib/api";
import { SecurityPolicy, PolicyEvaluationResult, ScanResult, PolicySuppression } from "@/lib/types";

function policyToYaml(policy: SecurityPolicy): string {
  let yaml = `# RepoShield Security Policy Configuration\n`;
  yaml += `version: "1.0"\n`;
  yaml += `policy:\n`;
  yaml += `  id: "${policy.id}"\n`;
  yaml += `  name: "${policy.name}"\n`;
  yaml += `  rules:\n`;
  yaml += `    fail_on_critical: ${policy.fail_on_critical}\n`;
  yaml += `    fail_on_high: ${policy.fail_on_high}\n`;
  yaml += `    fail_on_secrets: ${policy.fail_on_secrets}\n`;
  yaml += `    fail_on_new_critical: ${policy.fail_on_new_critical}\n`;
  yaml += `    fail_on_new_high: ${policy.fail_on_new_high}\n`;
  yaml += `    warn_on_dependencies: ${policy.warn_on_dependencies}\n`;
  yaml += `    max_permitted_severity: "${policy.max_permitted_severity}"\n`;
  yaml += `    require_suppression_reason: ${policy.require_suppression_reason}\n`;
  yaml += `  suppressions:\n`;
  if (policy.suppressions.length === 0) {
    yaml += `    []\n`;
  } else {
    for (const s of policy.suppressions) {
      yaml += `    - rule_id: "${s.rule_id}"\n`;
      yaml += `      fingerprint: "${s.fingerprint}"\n`;
      yaml += `      reason: "${s.reason.replace(/"/g, '\\"')}"\n`;
      if (s.expires_at) yaml += `      expires_at: "${s.expires_at}"\n`;
    }
  }
  return yaml;
}

export default function PoliciesPage() {
  const [policy, setPolicy] = useState<SecurityPolicy>(storage.getPolicy());
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [testScanId, setTestScanId] = useState<string>("");
  const [evalResult, setEvalResult] = useState<PolicyEvaluationResult | null>(null);
  const [isTesting, setIsTesting] = useState(false);
  const [copiedYaml, setCopiedYaml] = useState(false);
  const [saveMessage, setSaveMessage] = useState<string | null>(null);

  useEffect(() => {
    const p = storage.getPolicy();
    setPolicy(p);
    const scans = storage.getScanHistory();
    setHistory(scans);
    if (scans.length > 0) {
      setTestScanId(scans[0].scan_id);
    }
  }, []);

  const handleToggle = (key: keyof SecurityPolicy) => {
    const updated = { ...policy, [key]: !policy[key] };
    setPolicy(updated);
    storage.savePolicy(updated);
    showSavedNotification();
  };

  const handleSeverityChange = (sev: any) => {
    const updated = { ...policy, max_permitted_severity: sev };
    setPolicy(updated);
    storage.savePolicy(updated);
    showSavedNotification();
  };

  const showSavedNotification = () => {
    setSaveMessage("Policy updated locally");
    setTimeout(() => setSaveMessage(null), 2500);
  };

  const handleResetDefault = () => {
    if (confirm("Reset security policy to default strict recommendations?")) {
      const defaultPol: SecurityPolicy = {
        id: "default-strict",
        name: "Default Strict Developer Policy",
        description: "Zero exposed secrets, no new critical/high findings.",
        fail_on_critical: true,
        fail_on_high: true,
        fail_on_secrets: true,
        fail_on_new_critical: true,
        fail_on_new_high: true,
        warn_on_dependencies: true,
        max_permitted_severity: "HIGH",
        require_suppression_reason: true,
        suppressions: storage.getSuppressions(),
      };
      setPolicy(defaultPol);
      storage.savePolicy(defaultPol);
      showSavedNotification();
    }
  };

  const handleRemoveSuppression = (fingerprint: string) => {
    storage.removeSuppression(fingerprint);
    const updated = storage.getPolicy();
    setPolicy(updated);
    showSavedNotification();
  };

  const handleTestPolicy = async () => {
    const scan = history.find((s) => s.scan_id === testScanId);
    if (!scan) return;

    setIsTesting(true);
    setEvalResult(null);

    try {
      const res = await api.evaluatePolicy(policy, scan.findings);
      setEvalResult(res);
    } catch {
      // Local evaluation fallback
      const activeSuppressions = new Map(
        policy.suppressions.map((s) => [s.fingerprint, s])
      );
      const nowIso = new Date().toISOString();
      const violations: string[] = [];
      const warnings: string[] = [];
      let suppressedCount = 0;

      for (const f of scan.findings) {
        const fp = f.fingerprint || `${f.detector_name}:${f.rule_id}:${f.file_path}`;
        const supp = activeSuppressions.get(fp);
        if (supp) {
          if (!supp.expires_at || supp.expires_at > nowIso) {
            suppressedCount++;
            continue;
          }
        }

        if (policy.fail_on_secrets && f.category === "SECRETS") {
          violations.push(`[SECRETS] Exposed secret detected in ${f.file_path} (${f.title})`);
        }
        if (policy.fail_on_critical && f.severity === "CRITICAL") {
          violations.push(`[CRITICAL] Critical issue in ${f.file_path} (${f.title})`);
        }
        if (policy.fail_on_high && f.severity === "HIGH") {
          violations.push(`[HIGH] High severity issue in ${f.file_path} (${f.title})`);
        }
        if (policy.warn_on_dependencies && f.category === "DEPENDENCIES") {
          warnings.push(`Vulnerable dependency: ${f.package_name || f.title}`);
        }
      }

      setEvalResult({
        passed: violations.length === 0,
        policy_name: policy.name,
        violations,
        warnings,
        evaluated_at: new Date().toISOString(),
        suppressed_count: suppressedCount,
      });
    } finally {
      setIsTesting(false);
    }
  };

  const handleCopyYaml = () => {
    const yaml = policyToYaml(policy);
    navigator.clipboard.writeText(yaml);
    setCopiedYaml(true);
    setTimeout(() => setCopiedYaml(false), 2000);
  };

  const handleDownloadYaml = () => {
    const yaml = policyToYaml(policy);
    const blob = new Blob([yaml], { type: "text/yaml;charset=utf-8;" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = ".reposhield.yml";
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  };

  const suppressions = storage.getSuppressions();

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="macos-title flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-[var(--accent)]" />
            <span>Security Policies</span>
          </h1>
          <p className="macos-subtitle">
            Configure automated release gates, rule thresholds, and auditable suppressions.
          </p>
        </div>

        <div className="flex items-center gap-2 self-start sm:self-auto">
          {saveMessage && (
            <span className="text-[12px] text-[#34C759] font-medium animate-in fade-in">
              {saveMessage}
            </span>
          )}
          <button
            onClick={handleResetDefault}
            className="macos-button flex items-center gap-1.5 text-[12px]"
            title="Reset to default"
          >
            <RotateCcw className="w-3.5 h-3.5 text-[var(--text-secondary)]" />
            <span>Reset</span>
          </button>
          <button
            onClick={handleDownloadYaml}
            className="macos-button flex items-center gap-1.5 text-[12px]"
            title="Export as .reposhield.yml"
          >
            <Download className="w-3.5 h-3.5 text-[var(--text-secondary)]" />
            <span>Export .reposhield.yml</span>
          </button>
        </div>
      </div>

      {/* Rules Grid */}
      <div className="macos-card p-5 space-y-4">
        <div className="border-b border-[var(--border-subtle)] pb-2.5">
          <h2 className="text-[14px] font-semibold text-[var(--text-primary)] tracking-tight">
            Enforcement Rules
          </h2>
          <p className="text-[12px] text-[var(--text-secondary)]">
            Toggles dictate when automated checks fail and merge requests are blocked.
          </p>
        </div>

        <div className="space-y-3">
          {/* Rule 1: Fail on Secrets */}
          <div className="flex items-center justify-between p-3 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)]">
            <div>
              <div className="text-[13px] font-medium text-[var(--text-primary)]">
                Never Permit Exposed Credentials
              </div>
              <div className="text-[11px] text-[var(--text-secondary)]">
                Blocks builds immediately if Gitleaks or Semgrep detects API keys or private certificates.
              </div>
            </div>
            <input
              type="checkbox"
              checked={policy.fail_on_secrets}
              onChange={() => handleToggle("fail_on_secrets")}
              className="w-4 h-4 accent-[var(--accent)] cursor-pointer"
            />
          </div>

          {/* Rule 2: Fail on New Critical */}
          <div className="flex items-center justify-between p-3 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)]">
            <div>
              <div className="text-[13px] font-medium text-[var(--text-primary)]">
                Fail on New Critical Findings
              </div>
              <div className="text-[11px] text-[var(--text-secondary)]">
                Reject commits that introduce any newly discovered Critical severity issue.
              </div>
            </div>
            <input
              type="checkbox"
              checked={policy.fail_on_new_critical}
              onChange={() => handleToggle("fail_on_new_critical")}
              className="w-4 h-4 accent-[var(--accent)] cursor-pointer"
            />
          </div>

          {/* Rule 3: Fail on New High */}
          <div className="flex items-center justify-between p-3 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)]">
            <div>
              <div className="text-[13px] font-medium text-[var(--text-primary)]">
                Fail on New High Findings
              </div>
              <div className="text-[11px] text-[var(--text-secondary)]">
                Reject commits that introduce newly discovered High severity findings.
              </div>
            </div>
            <input
              type="checkbox"
              checked={policy.fail_on_new_high}
              onChange={() => handleToggle("fail_on_new_high")}
              className="w-4 h-4 accent-[var(--accent)] cursor-pointer"
            />
          </div>

          {/* Rule 4: Warn on Vulnerable Dependencies */}
          <div className="flex items-center justify-between p-3 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)]">
            <div>
              <div className="text-[13px] font-medium text-[var(--text-primary)]">
                Warn on Vulnerable Dependencies
              </div>
              <div className="text-[11px] text-[var(--text-secondary)]">
                Emit prominent warnings whenever OSV detects vulnerable packages in manifests.
              </div>
            </div>
            <input
              type="checkbox"
              checked={policy.warn_on_dependencies}
              onChange={() => handleToggle("warn_on_dependencies")}
              className="w-4 h-4 accent-[var(--accent)] cursor-pointer"
            />
          </div>

          {/* Rule 5: Require Documented Suppression Reason */}
          <div className="flex items-center justify-between p-3 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)]">
            <div>
              <div className="text-[13px] font-medium text-[var(--text-primary)]">
                Require Documented Suppression Reason
              </div>
              <div className="text-[11px] text-[var(--text-secondary)]">
                Enforce developer accountability: suppressions require an explicit justification.
              </div>
            </div>
            <input
              type="checkbox"
              checked={policy.require_suppression_reason}
              onChange={() => handleToggle("require_suppression_reason")}
              className="w-4 h-4 accent-[var(--accent)] cursor-pointer"
            />
          </div>

          {/* Rule 6: Max Permitted Severity Threshold */}
          <div className="flex items-center justify-between p-3 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)]">
            <div>
              <div className="text-[13px] font-medium text-[var(--text-primary)]">
                Maximum Permitted Severity Threshold
              </div>
              <div className="text-[11px] text-[var(--text-secondary)]">
                Any finding equal to or exceeding this threshold will fail the pipeline.
              </div>
            </div>
            <select
              value={policy.max_permitted_severity}
              onChange={(e) => handleSeverityChange(e.target.value)}
              className="macos-select font-mono text-[12px]"
            >
              <option value="CRITICAL">CRITICAL (Only critical fails)</option>
              <option value="HIGH">HIGH (High & Critical fail)</option>
              <option value="MEDIUM">MEDIUM (Medium, High, Critical fail)</option>
              <option value="LOW">LOW (Low and above fail)</option>
            </select>
          </div>
        </div>
      </div>

      {/* Test Policy Against a Real Scan */}
      <div className="macos-card p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[var(--border-subtle)] pb-2.5">
          <div>
            <h2 className="text-[14px] font-semibold text-[var(--text-primary)] tracking-tight">
              Test Policy Against Scan
            </h2>
            <p className="text-[12px] text-[var(--text-secondary)]">
              Validate your security policy rules against any completed scan in local history.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <select
              value={testScanId}
              onChange={(e) => setTestScanId(e.target.value)}
              className="macos-select font-mono text-[12px] max-w-xs"
              disabled={history.length === 0}
            >
              {history.length === 0 ? (
                <option value="">No local scans</option>
              ) : (
                history.map((s) => (
                  <option key={s.scan_id} value={s.scan_id}>
                    {s.owner}/{s.repo} ({s.findings.length} findings)
                  </option>
                ))
              )}
            </select>

            <button
              onClick={handleTestPolicy}
              disabled={isTesting || !testScanId}
              className="macos-button-primary flex items-center gap-1.5 text-[12px]"
            >
              <Play className="w-3.5 h-3.5" />
              <span>{isTesting ? "Testing..." : "Test Policy"}</span>
            </button>
          </div>
        </div>

        {evalResult && (
          <div
            className={`p-4 rounded-[8px] border space-y-3 ${
              evalResult.passed
                ? "bg-[#34C759]/10 border-[#34C759]/30"
                : "bg-[#FF3B30]/10 border-[#FF3B30]/30"
            }`}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                {evalResult.passed ? (
                  <CheckCircle2 className="w-5 h-5 text-[#34C759]" />
                ) : (
                  <XCircle className="w-5 h-5 text-[#FF3B30]" />
                )}
                <span className="text-[14px] font-semibold text-[var(--text-primary)]">
                  {evalResult.passed ? "Policy Evaluation: Passed" : "Policy Evaluation: Failed"}
                </span>
              </div>
              <span className="text-[11px] font-mono text-[var(--text-secondary)]">
                {evalResult.suppressed_count} findings suppressed by policy
              </span>
            </div>

            {evalResult.violations.length > 0 && (
              <div className="space-y-1.5 pt-2 border-t border-[var(--border-subtle)]">
                <div className="text-[12px] font-semibold text-[#FF3B30]">Violations:</div>
                <ul className="space-y-1 text-[11px] text-[var(--text-primary)] font-mono">
                  {evalResult.violations.map((v, i) => (
                    <li key={i} className="flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full bg-[#FF3B30]" />
                      <span>{v}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Active Suppressions */}
      <div className="macos-card p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-2.5">
          <div>
            <h2 className="text-[14px] font-semibold text-[var(--text-primary)] tracking-tight">
              Active Suppressions ({suppressions.length})
            </h2>
            <p className="text-[12px] text-[var(--text-secondary)]">
              Explicit, auditable rule exemptions documented with justification reasons.
            </p>
          </div>
        </div>

        {suppressions.length === 0 ? (
          <div className="text-[12px] text-[var(--text-muted)] py-4 text-center">
            No active suppressions. To suppress a finding, open it in the Findings explorer.
          </div>
        ) : (
          <div className="space-y-2">
            {suppressions.map((s) => (
              <div
                key={s.fingerprint}
                className="p-3 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[12px]"
              >
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[11px] px-1.5 py-0.5 rounded bg-[var(--bg-surface)] border border-[var(--border-color)] text-[var(--text-primary)]">
                      {s.rule_id}
                    </span>
                    {s.expires_at && (
                      <span className="text-[10px] text-amber-600 dark:text-amber-400 flex items-center gap-1 font-mono">
                        <Calendar className="w-3 h-3" />
                        <span>Expires: {new Date(s.expires_at).toLocaleDateString()}</span>
                      </span>
                    )}
                  </div>
                  <div className="text-[12px] text-[var(--text-primary)]">
                    <span className="text-[var(--text-muted)]">Reason: </span>
                    <span>{s.reason}</span>
                  </div>
                </div>

                <button
                  onClick={() => handleRemoveSuppression(s.fingerprint)}
                  className="macos-button self-start sm:self-auto text-[11px] text-[#FF3B30] hover:bg-[#FF3B30]/10 flex items-center gap-1"
                  title="Remove suppression"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Unsuppress</span>
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* YAML Preview */}
      <div className="macos-card p-5 space-y-3">
        <div className="flex items-center justify-between border-b border-[var(--border-subtle)] pb-2.5">
          <div className="flex items-center gap-2">
            <FileCode className="w-4 h-4 text-[var(--accent)]" />
            <h2 className="text-[13px] font-semibold text-[var(--text-primary)] tracking-tight">
              Configuration Preview (.reposhield.yml)
            </h2>
          </div>
          <button
            onClick={handleCopyYaml}
            className="macos-button flex items-center gap-1.5 text-[11px]"
          >
            {copiedYaml ? <Check className="w-3.5 h-3.5 text-[#34C759]" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedYaml ? "Copied" : "Copy YAML"}</span>
          </button>
        </div>

        <pre className="macos-code-block max-h-56">
          {policyToYaml(policy)}
        </pre>
      </div>
    </div>
  );
}
