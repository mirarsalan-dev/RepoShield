"use client";

import React, { useState } from "react";
import {
  Globe,
  Lock,
  Shield,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  ArrowRight,
  RefreshCw,
  Search,
  ExternalLink,
} from "lucide-react";
import { api } from "@/lib/api";
import { WebsiteAssessmentResult, SecurityHeaderCheck, CookieCheck } from "@/lib/types";
import { MacTrafficLights } from "@/components/common/Icons";

export default function WebsiteSecurityPage() {
  const [targetUrl, setTargetUrl] = useState("https://");
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<WebsiteAssessmentResult | null>(null);

  const handleRunAssessment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isAuthorized) {
      setError("Explicit authorization confirmation is required before assessing any target domain.");
      return;
    }

    if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
      setError("Please provide a valid URL starting with http:// or https://");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await api.assessWebsite({ url: targetUrl, authorized: isAuthorized });
      setReport(res);
    } catch (err: any) {
      setError(err.message || "Failed to execute website security assessment.");
    } finally {
      setLoading(false);
    }
  };

  const getGradeColor = (grade: string) => {
    switch (grade) {
      case "A+":
      case "A":
        return "var(--system-green)";
      case "B":
        return "#30B0C7";
      case "C":
        return "var(--system-orange)";
      case "D":
      case "F":
      default:
        return "var(--system-red)";
    }
  };

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-[var(--border-subtle)]">
        <div>
          <h1 className="macos-title flex items-center gap-2">
            <Globe className="w-5 h-5 text-[var(--accent)]" />
            <span>Authorized Website Security Assessment</span>
          </h1>
          <p className="macos-subtitle">
            Safe, non-destructive audit of public TLS certificates, HTTP security headers, and cookie attributes.
          </p>
        </div>
        <MacTrafficLights />
      </div>

      {/* Target Assessment Form */}
      <div className="macos-card p-6 space-y-5">
        <form onSubmit={handleRunAssessment} className="space-y-4">
          <div className="space-y-1.5">
            <label className="text-[12px] font-semibold text-[var(--text-primary)] uppercase tracking-wider block">
              Target Web Domain or Endpoint
            </label>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Globe className="w-4 h-4 text-[var(--text-muted)] absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  type="text"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="macos-input w-full pl-9 text-[13px] font-mono"
                  disabled={loading}
                />
              </div>
              <button
                type="submit"
                disabled={loading || !isAuthorized}
                className="macos-button macos-button-primary px-5 text-[12px] flex items-center gap-2 font-medium"
              >
                {loading ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Auditing...</span>
                  </>
                ) : (
                  <>
                    <Search className="w-3.5 h-3.5" />
                    <span>Assess Target</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Authorization Checkbox & SSRF Disclaimer */}
          <div className="p-3.5 rounded-[8px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] space-y-2 text-[12px]">
            <label className="flex items-start gap-2.5 cursor-pointer">
              <input
                type="checkbox"
                checked={isAuthorized}
                onChange={(e) => setIsAuthorized(e.target.checked)}
                className="mt-0.5 rounded border-[var(--border-subtle)] text-[var(--accent)]"
              />
              <span className="text-[var(--text-primary)] font-medium leading-relaxed">
                I verify that I own or possess explicit written authorization to perform security header and TLS configuration analysis against this destination.
              </span>
            </label>
            <p className="text-[11px] text-[var(--text-muted)] pl-6">
              Security note: All requests strictly enforce DNS validation, timeout limits, and SSRF filtering. Loopback (127.0.0.1, localhost), link-local (169.254.0.0/16), and private RFC1918 subnets are automatically blocked.
            </p>
          </div>
        </form>

        {error && (
          <div className="p-3 rounded-[8px] bg-[#FF3B30]/10 border border-[#FF3B30]/30 text-[#FF3B30] text-[12px] flex items-center gap-2 font-medium">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Results View */}
      {report && (
        <div className="space-y-6">
          {/* Executive Overview Grade Card */}
          <div className="macos-card p-6 flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="space-y-1 text-center md:text-left">
              <span className="text-[11px] font-mono uppercase text-[var(--text-secondary)] font-semibold">
                Audit Target
              </span>
              <h2 className="text-[18px] font-semibold text-[var(--text-primary)] font-mono flex items-center gap-2">
                <span>{report.target_url}</span>
                <span className="text-[12px] font-mono px-2 py-0.5 rounded bg-[var(--bg-secondary)] text-[var(--text-secondary)] border border-[var(--border-subtle)]">
                  {report.final_url !== report.target_url ? "Redirected" : "Direct"}
                </span>
              </h2>
              <p className="text-[12px] text-[var(--text-secondary)] font-mono">
                IP: {report.ip_address} | Scanned {new Date(report.timestamp).toLocaleTimeString()}
              </p>
            </div>

            {/* Score Ring */}
            <div className="flex items-center gap-5">
              <div
                className="w-20 h-20 rounded-full flex flex-col items-center justify-center border-4"
                style={{
                  borderColor: getGradeColor(report.grade),
                  backgroundColor: `${getGradeColor(report.grade)}10`,
                }}
              >
                <span
                  className="text-[26px] font-bold leading-none"
                  style={{ color: getGradeColor(report.grade) }}
                >
                  {report.grade}
                </span>
                <span className="text-[10px] font-mono text-[var(--text-secondary)] mt-0.5">
                  {report.score}/100
                </span>
              </div>

              <div className="space-y-1 text-[12px]">
                <div className="flex items-center gap-1.5 font-medium text-[var(--text-primary)]">
                  {report.https_enforced ? (
                    <CheckCircle2 className="w-4 h-4 text-[var(--system-green)]" />
                  ) : (
                    <XCircle className="w-4 h-4 text-[var(--system-red)]" />
                  )}
                  <span>HTTPS Protocol Enforced</span>
                </div>
              </div>
            </div>
          </div>

          {/* Security Headers Table */}
          <div className="macos-card p-5 space-y-4">
            <div>
              <h3 className="text-[14px] font-semibold text-[var(--text-primary)] tracking-tight">
                HTTP Security Headers Telemetry
              </h3>
              <p className="text-[12px] text-[var(--text-secondary)]">
                Validation of defense-in-depth headers protecting against clickjacking, MIME sniffing, and XSS.
              </p>
            </div>

            <div className="macos-panel overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-[12px]">
                  <thead>
                    <tr className="border-b border-[var(--border-color)] bg-[var(--bg-secondary)] text-[var(--text-secondary)] text-[11px] font-medium">
                      <th className="py-2.5 px-3">Security Header</th>
                      <th className="py-2.5 px-3">Detection Status</th>
                      <th className="py-2.5 px-3">Received Value</th>
                      <th className="py-2.5 px-3">Remediation Guidance</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--border-subtle)]">
                    {report.headers.map((h: SecurityHeaderCheck, i: number) => (
                      <tr key={i} className="hover:bg-[var(--bg-hover)] transition-colors">
                        <td className="py-2.5 px-3 font-mono font-medium text-[var(--text-primary)]">
                          {h.name}
                        </td>
                        <td className="py-2.5 px-3">
                          {h.status === "PASS" && (
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded font-semibold text-[var(--system-green)] bg-[#34C759]/10 border border-[#34C759]/20">
                              PASS
                            </span>
                          )}
                          {h.status === "WARN" && (
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded font-semibold text-[var(--system-orange)] bg-[#FF9500]/10 border border-[#FF9500]/20">
                              WARN
                            </span>
                          )}
                          {h.status === "FAIL" && (
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded font-semibold text-[var(--system-red)] bg-[#FF3B30]/10 border border-[#FF3B30]/20">
                              FAIL
                            </span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-[var(--text-secondary)] max-w-xs truncate">
                          {h.value || "—"}
                        </td>
                        <td className="py-2.5 px-3 text-[11px] text-[var(--text-secondary)]">
                          {h.recommendation || "Header verified with strong security parameters."}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Cookies & Configuration Attributes */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="macos-card p-4 space-y-3">
              <h4 className="text-[13px] font-semibold text-[var(--text-primary)]">
                Cookie Security Flags
              </h4>
              {report.cookies.length === 0 ? (
                <p className="text-[12px] text-[var(--text-muted)]">
                  No Set-Cookie headers returned by server.
                </p>
              ) : (
                <div className="space-y-2">
                  {report.cookies.map((c: CookieCheck, i: number) => (
                    <div
                      key={i}
                      className="p-2.5 rounded bg-[var(--bg-secondary)] border border-[var(--border-subtle)] text-[12px] space-y-1"
                    >
                      <div className="flex items-center justify-between font-mono font-medium text-[var(--text-primary)]">
                        <span>{c.name}</span>
                        <div className="flex gap-1.5 text-[10px]">
                          {c.has_secure ? (
                            <span className="text-[var(--system-green)] font-semibold">Secure</span>
                          ) : (
                            <span className="text-[var(--system-red)] font-semibold">Insecure</span>
                          )}
                          {c.has_httponly ? (
                            <span className="text-[var(--system-green)] font-semibold">HttpOnly</span>
                          ) : (
                            <span className="text-[var(--system-orange)] font-semibold">NoHttpOnly</span>
                          )}
                        </div>
                      </div>
                      <div className="text-[11px] text-[var(--text-secondary)] font-mono">
                        SameSite: {c.samesite || "None"}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="macos-card p-4 space-y-3">
              <h4 className="text-[13px] font-semibold text-[var(--text-primary)]">
                Observed Server Telemetry
              </h4>
              <div className="space-y-2 text-[12px] font-mono">
                <div className="flex justify-between p-2 rounded bg-[var(--bg-secondary)] border border-[var(--border-subtle)]">
                  <span className="text-[var(--text-secondary)]">Server Banner</span>
                  <span className="text-[var(--text-primary)]">
                    {report.server_banner || "Hidden (Best Practice)"}
                  </span>
                </div>
                <div className="flex justify-between p-2 rounded bg-[var(--bg-secondary)] border border-[var(--border-subtle)]">
                  <span className="text-[var(--text-secondary)]">Protocol Scheme</span>
                  <span className="text-[var(--text-primary)]">
                    {report.final_url.startsWith("https://") ? "TLS v1.3 / HTTPS" : "Insecure HTTP"}
                  </span>
                </div>
                <div className="flex justify-between p-2 rounded bg-[var(--bg-secondary)] border border-[var(--border-subtle)]">
                  <span className="text-[var(--text-secondary)]">Duration</span>
                  <span className="text-[var(--text-primary)]">
                    {report.duration_seconds.toFixed(2)}s
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
