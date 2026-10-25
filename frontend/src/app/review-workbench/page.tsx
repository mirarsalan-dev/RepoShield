"use client";

import React, { useState, useEffect, useMemo, useRef } from "react";
import Link from "next/link";
import {
  ClipboardCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Download,
  Upload,
  Search,
  Filter,
  ArrowRight,
  FileText,
  Calendar,
  User,
  Tag,
  Wrench,
  Milestone,
  RotateCcw,
  Check,
  Trash2,
  ExternalLink,
  Shield,
  HelpCircle,
  FileCode,
} from "lucide-react";
import { storage } from "@/lib/storage";
import {
  ScanResult,
  Finding,
  Severity,
  ReviewStatus,
  RemediationDecision,
  TriageVerificationStatus,
  ReviewAnnotation,
} from "@/lib/types";
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import { EmptyState } from "@/components/common/EmptyState";
import { formatDate, formatTimeAgo } from "@/lib/utils";

const STATUS_OPTIONS: { value: ReviewStatus; label: string; color: string }[] = [
  { value: "UNDER_INVESTIGATION", label: "Under Investigation", color: "text-amber-500 bg-amber-500/10 border-amber-500/30" },
  { value: "FIX_REQUIRED", label: "Fix Required", color: "text-rose-500 bg-rose-500/10 border-rose-500/30" },
  { value: "ACCEPTED_RISK", label: "Accepted Risk", color: "text-blue-500 bg-blue-500/10 border-blue-500/30" },
  { value: "FALSE_POSITIVE", label: "False Positive", color: "text-neutral-400 bg-neutral-500/10 border-neutral-500/30" },
  { value: "VERIFIED_FIXED", label: "Verified Fixed", color: "text-emerald-500 bg-emerald-500/10 border-emerald-500/30" },
];

const DECISION_OPTIONS: { value: RemediationDecision; label: string }[] = [
  { value: "IMMEDIATE_PATCH", label: "Immediate Patch (Hotfix)" },
  { value: "PLANNED_SPRINT", label: "Planned Sprint Remediation" },
  { value: "MITIGATING_CONTROL", label: "Mitigating Control Applied" },
  { value: "WONT_FIX_INTERNAL", label: "Won't Fix (Internal / Non-Exposed)" },
  { value: "FALSE_POSITIVE", label: "False Positive (Pattern Mismatch)" },
  { value: "NEEDS_INVESTIGATION", label: "Needs Further Investigation" },
];

export default function ReviewWorkbenchPage() {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>("");
  const [selectedFindingId, setSelectedFindingId] = useState<string>("");
  const [search, setSearch] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [reviewsMap, setReviewsMap] = useState<Record<string, ReviewAnnotation>>({});
  const [saveSuccessMsg, setSaveSuccessMsg] = useState<string>("");

  // Workbench Form State
  const [reviewStatus, setReviewStatus] = useState<ReviewStatus>("UNDER_INVESTIGATION");
  const [remediationDecision, setRemediationDecision] = useState<RemediationDecision>("NEEDS_INVESTIGATION");
  const [fpJustification, setFpJustification] = useState<string>("");
  const [notes, setNotes] = useState<string>("");
  const [reviewer, setReviewer] = useState<string>("SecOps Analyst");
  const [expiresAt, setExpiresAt] = useState<string>("");
  const [remediationPlanId, setRemediationPlanId] = useState<string>("");

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Load scan history & existing reviews on mount
  useEffect(() => {
    const history = storage.getScanHistory();
    setScans(history);
    if (history.length > 0) {
      setSelectedScanId(history[0].scan_id);
    }
    setReviewsMap(storage.getReviewAnnotations());
  }, []);

  const activeScan = useMemo(() => {
    return scans.find((s) => s.scan_id === selectedScanId) || scans[0] || null;
  }, [scans, selectedScanId]);

  const findings = useMemo(() => {
    return activeScan ? activeScan.findings : [];
  }, [activeScan]);

  // Sync selected finding with form fields
  const selectedFinding = useMemo(() => {
    if (!selectedFindingId && findings.length > 0) {
      return findings[0];
    }
    return findings.find((f) => f.id === selectedFindingId) || findings[0] || null;
  }, [findings, selectedFindingId]);

  useEffect(() => {
    if (selectedFinding) {
      const fp = selectedFinding.fingerprint || `${selectedFinding.detector_name}:${selectedFinding.rule_id}:${selectedFinding.file_path}`;
      const existing = reviewsMap[fp];
      if (existing) {
        setReviewStatus(existing.status);
        setRemediationDecision(existing.remediation_decision);
        setFpJustification(existing.false_positive_justification || "");
        setNotes(existing.investigation_notes || "");
        setReviewer(existing.reviewer || "SecOps Analyst");
        setExpiresAt(existing.expires_at || "");
        setRemediationPlanId(existing.remediation_plan_id || "");
      } else {
        setReviewStatus("UNDER_INVESTIGATION");
        setRemediationDecision("NEEDS_INVESTIGATION");
        setFpJustification("");
        setNotes("");
        setReviewer("SecOps Analyst");
        setExpiresAt("");
        setRemediationPlanId("");
      }
    }
  }, [selectedFinding, reviewsMap]);

  // Statistics calculation
  const stats = useMemo(() => {
    const total = findings.length;
    let triaged = 0;
    let fixRequired = 0;
    let acceptedRisk = 0;
    let falsePositive = 0;
    let verifiedFixed = 0;
    let expiringSoon = 0;

    const now = new Date().getTime();
    const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;

    findings.forEach((f) => {
      const fp = f.fingerprint || `${f.detector_name}:${f.rule_id}:${f.file_path}`;
      const rev = reviewsMap[fp];
      if (rev) {
        triaged++;
        if (rev.status === "FIX_REQUIRED") fixRequired++;
        else if (rev.status === "ACCEPTED_RISK") acceptedRisk++;
        else if (rev.status === "FALSE_POSITIVE") falsePositive++;
        else if (rev.status === "VERIFIED_FIXED") verifiedFixed++;

        if (rev.expires_at) {
          const expTime = new Date(rev.expires_at).getTime();
          if (expTime > now && expTime - now <= thirtyDaysMs) {
            expiringSoon++;
          }
        }
      }
    });

    return {
      total,
      triaged,
      pending: Math.max(0, total - triaged),
      fixRequired,
      acceptedRisk,
      falsePositive,
      verifiedFixed,
      expiringSoon,
    };
  }, [findings, reviewsMap]);

  // Filtered findings list
  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      const fp = f.fingerprint || `${f.detector_name}:${f.rule_id}:${f.file_path}`;
      const rev = reviewsMap[fp];

      // Search
      if (search.trim()) {
        const q = search.toLowerCase();
        const matchesTitle = f.title.toLowerCase().includes(q);
        const matchesFile = f.file_path.toLowerCase().includes(q);
        const matchesRule = f.rule_id.toLowerCase().includes(q);
        if (!matchesTitle && !matchesFile && !matchesRule) return false;
      }

      // Severity
      if (severityFilter !== "ALL" && f.severity !== severityFilter) return false;

      // Status
      if (statusFilter === "PENDING" && rev) return false;
      if (statusFilter !== "ALL" && statusFilter !== "PENDING") {
        if (!rev || rev.status !== statusFilter) return false;
      }

      return true;
    });
  }, [findings, reviewsMap, search, severityFilter, statusFilter]);

  const handleSaveReview = () => {
    if (!selectedFinding) return;

    if (reviewStatus === "FALSE_POSITIVE" && !fpJustification.trim()) {
      alert("False Positive justification is mandatory when marking a finding as False Positive.");
      return;
    }

    const fp = selectedFinding.fingerprint || `${selectedFinding.detector_name}:${selectedFinding.rule_id}:${selectedFinding.file_path}`;
    const annotation: ReviewAnnotation = {
      finding_id: selectedFinding.id,
      fingerprint: fp,
      title: selectedFinding.title,
      file_path: selectedFinding.file_path,
      severity: selectedFinding.severity,
      category: selectedFinding.category,
      detector_name: selectedFinding.detector_name,
      rule_id: selectedFinding.rule_id,
      status: reviewStatus,
      remediation_decision: remediationDecision,
      false_positive_justification: fpJustification.trim() || undefined,
      investigation_notes: notes.trim(),
      reviewer: reviewer.trim() || "SecOps Analyst",
      reviewed_at: reviewsMap[fp]?.reviewed_at || new Date().toISOString(),
      updated_at: new Date().toISOString(),
      expires_at: expiresAt || undefined,
      remediation_plan_id: remediationPlanId.trim() || undefined,
      verification_status: reviewStatus === "VERIFIED_FIXED" ? "CONFIRMED_FIXED" : "UNVERIFIED",
    };

    storage.saveReviewAnnotation(annotation);
    setReviewsMap(storage.getReviewAnnotations());
    setSaveSuccessMsg("Triage review saved to local audit record.");
    setTimeout(() => setSaveSuccessMsg(""), 3000);
  };

  const handleDeleteReview = () => {
    if (!selectedFinding) return;
    const fp = selectedFinding.fingerprint || `${selectedFinding.detector_name}:${selectedFinding.rule_id}:${selectedFinding.file_path}`;
    if (confirm("Remove local review annotation for this finding?")) {
      storage.deleteReviewAnnotation(fp);
      setReviewsMap(storage.getReviewAnnotations());
      setSaveSuccessMsg("Review annotation deleted.");
      setTimeout(() => setSaveSuccessMsg(""), 3000);
    }
  };

  const handleExportBundle = () => {
    const jsonStr = storage.exportReviewBundle();
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `reposhield-reviews-bundle-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const handleImportBundle = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (content) {
        if (confirm("Import review annotations? Existing matching reviews will be updated with imported notes.")) {
          const res = storage.importReviewBundle(content);
          if (res.success) {
            setReviewsMap(storage.getReviewAnnotations());
            alert(res.message);
          } else {
            alert(`Import failed: ${res.message}`);
          }
        }
      }
    };
    reader.readAsText(file);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const setExpiryDays = (days: number) => {
    const d = new Date();
    d.setDate(d.getDate() + days);
    setExpiresAt(d.toISOString().slice(0, 10));
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12 animate-in fade-in duration-300">
      {/* Hidden file input for review bundle import */}
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleImportBundle}
        accept=".json"
        className="hidden"
      />

      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[var(--border)] pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-[8px] bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-500">
              <ClipboardCheck className="w-4 h-4" />
            </div>
            <h1 className="text-xl font-semibold tracking-tight text-[var(--foreground)]">
              Security Review Workbench
            </h1>
          </div>
          <p className="text-[13px] text-[var(--muted-foreground)] mt-1">
            Evidence-driven triage workspace. Record remediation decisions, false-positive justifications, and sprint plan associations.
          </p>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          {/* Active Scan Selector */}
          {scans.length > 0 && (
            <select
              value={selectedScanId}
              onChange={(e) => {
                setSelectedScanId(e.target.value);
                setSelectedFindingId("");
              }}
              className="px-3 py-1.5 text-[12px] rounded-[6px] bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)] font-mono focus:outline-none focus:ring-1 focus:ring-[var(--focus-ring)]"
            >
              {scans.map((s) => (
                <option key={s.scan_id} value={s.scan_id}>
                  {s.repo} ({s.commit_sha ? s.commit_sha.slice(0, 7) : "HEAD"}) — {formatTimeAgo(s.created_at || "")}
                </option>
              ))}
            </select>
          )}

          <button
            onClick={() => fileInputRef.current?.click()}
            className="flex items-center gap-1.5 px-3 py-1.5 text-[12px] rounded-[6px] bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)] hover:bg-[var(--surface-hover)] transition-colors"
            title="Import review annotations JSON bundle"
          >
            <Upload className="w-3.5 h-3.5 text-[var(--muted-foreground)]" />
            <span>Import Bundle</span>
          </button>

          <button
            onClick={handleExportBundle}
            className="flex items-center gap-1.5 px-3 py-1.5 text-[12px] rounded-[6px] bg-[var(--accent)] text-white hover:opacity-90 transition-opacity font-medium shadow-sm"
            title="Export all triage review annotations as a portable JSON bundle"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Bundle ({Object.keys(reviewsMap).length})</span>
          </button>
        </div>
      </div>

      {/* Zero Database & Non-Verification Disclaimer */}
      <div className="p-3.5 rounded-[8px] bg-blue-500/10 border border-blue-500/20 text-blue-700 dark:text-blue-300 text-[12px] flex items-start gap-2.5">
        <HelpCircle className="w-4 h-4 flex-shrink-0 mt-0.5 text-blue-500" />
        <div className="leading-relaxed">
          <span className="font-semibold">Review Policy & Safe Architecture:</span> Review annotations are persisted locally in browser storage without backend database dependencies. A human triage decision (e.g. <em>Accepted Risk</em> or <em>Fix Required</em>) indicates operational intent and is strictly distinct from automated technical verification. Verify remediations using the{" "}
          <Link href="/fix-validation" className="underline font-medium hover:text-blue-400">
            Fix Validation Engine
          </Link>
          .
        </div>
      </div>

      {/* Triage Statistics Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="p-3 rounded-[8px] bg-[var(--surface)] border border-[var(--border)]">
          <div className="text-[11px] font-medium text-[var(--muted-foreground)] uppercase tracking-wider">Total Findings</div>
          <div className="text-xl font-bold text-[var(--foreground)] mt-0.5">{stats.total}</div>
        </div>
        <div className="p-3 rounded-[8px] bg-[var(--surface)] border border-[var(--border)]">
          <div className="text-[11px] font-medium text-amber-500 uppercase tracking-wider">Pending Triage</div>
          <div className="text-xl font-bold text-amber-500 mt-0.5">{stats.pending}</div>
        </div>
        <div className="p-3 rounded-[8px] bg-[var(--surface)] border border-[var(--border)]">
          <div className="text-[11px] font-medium text-rose-500 uppercase tracking-wider">Fix Required</div>
          <div className="text-xl font-bold text-rose-500 mt-0.5">{stats.fixRequired}</div>
        </div>
        <div className="p-3 rounded-[8px] bg-[var(--surface)] border border-[var(--border)]">
          <div className="text-[11px] font-medium text-blue-500 uppercase tracking-wider">Accepted Risk</div>
          <div className="text-xl font-bold text-blue-500 mt-0.5">{stats.acceptedRisk}</div>
        </div>
        <div className="p-3 rounded-[8px] bg-[var(--surface)] border border-[var(--border)]">
          <div className="text-[11px] font-medium text-neutral-400 uppercase tracking-wider">False Positive</div>
          <div className="text-xl font-bold text-neutral-400 mt-0.5">{stats.falsePositive}</div>
        </div>
        <div className="p-3 rounded-[8px] bg-[var(--surface)] border border-[var(--border)]">
          <div className="text-[11px] font-medium text-emerald-500 uppercase tracking-wider">Verified Fixed</div>
          <div className="text-xl font-bold text-emerald-500 mt-0.5">{stats.verifiedFixed}</div>
        </div>
      </div>

      {/* Main Split Layout */}
      {findings.length === 0 ? (
        <EmptyState
          title="No Findings in Selected Scan"
          description="Perform a scan or select a historical scan with detected findings to begin security triage."
          actionText="Run New Scan"
          actionHref="/scan"
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left Column: Finding Selector & Filters (5 cols) */}
          <div className="lg:col-span-5 space-y-3">
            {/* Filter controls */}
            <div className="p-3 rounded-[8px] bg-[var(--surface)] border border-[var(--border)] space-y-2.5">
              <div className="relative">
                <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-[var(--muted-foreground)]" />
                <input
                  type="text"
                  placeholder="Search finding, file path, rule ID..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-full pl-8 pr-3 py-1.5 text-[12px] rounded-[6px] bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)] placeholder-[var(--muted-foreground)] focus:outline-none focus:ring-1 focus:ring-[var(--focus-ring)]"
                />
              </div>

              <div className="flex items-center gap-2 text-[11px]">
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="flex-1 px-2 py-1 rounded-[4px] bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)]"
                >
                  <option value="ALL">All Triage States</option>
                  <option value="PENDING">Pending Triage</option>
                  <option value="FIX_REQUIRED">Fix Required</option>
                  <option value="ACCEPTED_RISK">Accepted Risk</option>
                  <option value="FALSE_POSITIVE">False Positive</option>
                  <option value="VERIFIED_FIXED">Verified Fixed</option>
                  <option value="UNDER_INVESTIGATION">Under Investigation</option>
                </select>

                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="px-2 py-1 rounded-[4px] bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)]"
                >
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>
            </div>

            {/* Findings List */}
            <div className="space-y-2 max-h-[700px] overflow-y-auto pr-1">
              {filteredFindings.map((f) => {
                const fp = f.fingerprint || `${f.detector_name}:${f.rule_id}:${f.file_path}`;
                const rev = reviewsMap[fp];
                const isSelected = selectedFinding?.id === f.id;

                return (
                  <div
                    key={f.id}
                    onClick={() => setSelectedFindingId(f.id)}
                    className={`p-3 rounded-[8px] border cursor-pointer transition-all ${
                      isSelected
                        ? "bg-[var(--surface)] border-[var(--accent)] shadow-sm ring-1 ring-[var(--accent)]/30"
                        : "bg-[var(--surface)] border-[var(--border)] hover:border-[var(--border-hover)]"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <SeverityBadge severity={f.severity} />
                        <span className="text-[11px] font-mono text-[var(--muted-foreground)]">
                          {f.detector_name}
                        </span>
                      </div>

                      {rev ? (
                        <span
                          className={`px-1.5 py-0.5 text-[10px] font-medium rounded border uppercase ${
                            rev.status === "FIX_REQUIRED"
                              ? "text-rose-500 bg-rose-500/10 border-rose-500/30"
                              : rev.status === "ACCEPTED_RISK"
                              ? "text-blue-500 bg-blue-500/10 border-blue-500/30"
                              : rev.status === "FALSE_POSITIVE"
                              ? "text-neutral-400 bg-neutral-500/10 border-neutral-500/30"
                              : rev.status === "VERIFIED_FIXED"
                              ? "text-emerald-500 bg-emerald-500/10 border-emerald-500/30"
                              : "text-amber-500 bg-amber-500/10 border-amber-500/30"
                          }`}
                        >
                          {rev.status.replace("_", " ")}
                        </span>
                      ) : (
                        <span className="px-1.5 py-0.5 text-[10px] font-medium rounded border border-amber-500/20 text-amber-500/80 bg-amber-500/5">
                          Needs Triage
                        </span>
                      )}
                    </div>

                    <h4 className="text-[13px] font-medium text-[var(--foreground)] mt-2 line-clamp-1">
                      {f.title}
                    </h4>

                    <div className="text-[11px] font-mono text-[var(--muted-foreground)] mt-1 truncate">
                      {f.file_path}:{f.line_start || 1}
                    </div>

                    {rev?.expires_at && (
                      <div className="flex items-center gap-1 text-[10px] text-amber-500 mt-2 font-mono">
                        <Calendar className="w-3 h-3" />
                        <span>Expires: {rev.expires_at}</span>
                      </div>
                    )}
                  </div>
                );
              })}

              {filteredFindings.length === 0 && (
                <div className="p-8 text-center text-[13px] text-[var(--muted-foreground)] bg-[var(--surface)] border border-[var(--border)] rounded-[8px]">
                  No findings match selected filters.
                </div>
              )}
            </div>
          </div>

          {/* Right Column: Active Workbench Form (7 cols) */}
          <div className="lg:col-span-7">
            {selectedFinding ? (
              <div className="p-5 rounded-[10px] bg-[var(--surface)] border border-[var(--border)] shadow-sm space-y-5">
                {/* Finding Header */}
                <div className="border-b border-[var(--border)] pb-4">
                  <div className="flex items-center justify-between gap-3 flex-wrap">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={selectedFinding.severity} />
                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--muted-foreground)]">
                        {selectedFinding.category}
                      </span>
                      <span className="text-[11px] font-mono text-[var(--muted-foreground)]">
                        {selectedFinding.detector_name}
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      <Link
                        href={`/timeline?fingerprint=${encodeURIComponent(
                          selectedFinding.fingerprint || `${selectedFinding.detector_name}:${selectedFinding.rule_id}:${selectedFinding.file_path}`
                        )}`}
                        className="flex items-center gap-1 px-2.5 py-1 text-[11px] rounded-[5px] bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)] hover:bg-[var(--surface-hover)] transition-colors"
                        title="Inspect vulnerability origin and commit timeline"
                      >
                        <Milestone className="w-3.5 h-3.5 text-blue-500" />
                        <span>View Timeline</span>
                      </Link>

                      <Link
                        href={`/fix-validation?finding_id=${encodeURIComponent(selectedFinding.id)}`}
                        className="flex items-center gap-1 px-2.5 py-1 text-[11px] rounded-[5px] bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)] hover:bg-[var(--surface-hover)] transition-colors"
                        title="Verify proposed fix in Safe Test Lab"
                      >
                        <Wrench className="w-3.5 h-3.5 text-emerald-500" />
                        <span>Validate Fix</span>
                      </Link>
                    </div>
                  </div>

                  <h2 className="text-base font-semibold text-[var(--foreground)] mt-2.5">
                    {selectedFinding.title}
                  </h2>

                  <div className="flex items-center gap-2 text-[12px] font-mono text-[var(--muted-foreground)] mt-1">
                    <FileCode className="w-3.5 h-3.5 text-[var(--muted-foreground)]" />
                    <span>{selectedFinding.file_path}:{selectedFinding.line_start || 1}</span>
                    <span className="text-[var(--border)]">•</span>
                    <span>Rule: {selectedFinding.rule_id}</span>
                  </div>

                  {selectedFinding.evidence && (
                    <div className="mt-3 p-2.5 rounded-[6px] bg-[var(--surface-subtle)] border border-[var(--border)] font-mono text-[11px] text-[var(--muted-foreground)] overflow-x-auto max-h-24">
                      {selectedFinding.evidence}
                    </div>
                  )}
                </div>

                {/* Triage Form Fields */}
                <div className="space-y-4">
                  {/* Status & Decision Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-[12px] font-medium text-[var(--foreground)] mb-1.5">
                        Triage Review Status <span className="text-rose-500">*</span>
                      </label>
                      <select
                        value={reviewStatus}
                        onChange={(e) => setReviewStatus(e.target.value as ReviewStatus)}
                        className="w-full px-3 py-2 text-[12px] rounded-[6px] bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)] focus:outline-none focus:ring-1 focus:ring-[var(--focus-ring)]"
                      >
                        {STATUS_OPTIONS.map((opt) => (
                          <option key={opt.value} value={opt.value}>
                            {opt.label}
                          </option>
                        ))}
                      </select>
                    </div>

                    <div>
                      <label className="block text-[12px] font-medium text-[var(--foreground)] mb-1.5">
                        Remediation Decision <span className="text-rose-500">*</span>
                      </label>
                      <select
                        value={remediationDecision}
                        onChange={(e) => setRemediationDecision(e.target.value as RemediationDecision)}
                        className="w-full px-3 py-2 text-[12px] rounded-[6px] bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)] focus:outline-none focus:ring-1 focus:ring-[var(--focus-ring)]"
                      >
                        {DECISION_OPTIONS.map((opt) => (
                          <option key={opt.value} value={opt.value}>
                            {opt.label}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>

                  {/* False Positive Justification (Required if False Positive) */}
                  {reviewStatus === "FALSE_POSITIVE" && (
                    <div className="p-3.5 rounded-[8px] bg-rose-500/10 border border-rose-500/20 space-y-2">
                      <div className="flex items-center gap-1.5 text-[12px] font-semibold text-rose-500">
                        <AlertTriangle className="w-4 h-4" />
                        <span>False Positive Justification (Mandatory)</span>
                      </div>
                      <p className="text-[11px] text-[var(--muted-foreground)]">
                        Explain why this detection is invalid, synthetic test data, non-reachable internal code, or a regex mismatch.
                      </p>
                      <textarea
                        rows={3}
                        value={fpJustification}
                        onChange={(e) => setFpJustification(e.target.value)}
                        placeholder="e.g. Synthetic mock secret in test fixture; no production connectivity or live credential exposed."
                        className="w-full px-3 py-2 text-[12px] rounded-[6px] bg-[var(--surface)] border border-rose-500/30 text-[var(--foreground)] placeholder-[var(--muted-foreground)] focus:outline-none focus:ring-1 focus:ring-rose-500"
                      />
                    </div>
                  )}

                  {/* Investigation Notes */}
                  <div>
                    <label className="block text-[12px] font-medium text-[var(--foreground)] mb-1.5">
                      Investigation & Remediation Notes
                    </label>
                    <textarea
                      rows={4}
                      value={notes}
                      onChange={(e) => setNotes(e.target.value)}
                      placeholder="Add investigation findings, attack surface analysis, links to internal security docs or mitigation plans..."
                      className="w-full px-3 py-2 text-[12px] rounded-[6px] bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)] placeholder-[var(--muted-foreground)] focus:outline-none focus:ring-1 focus:ring-[var(--focus-ring)] leading-relaxed"
                    />
                  </div>

                  {/* Reviewer, Expiry & Plan Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    <div>
                      <label className="block text-[11px] font-medium text-[var(--muted-foreground)] mb-1">
                        Reviewer Identity
                      </label>
                      <div className="relative">
                        <User className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-[var(--muted-foreground)]" />
                        <input
                          type="text"
                          value={reviewer}
                          onChange={(e) => setReviewer(e.target.value)}
                          placeholder="e.g. Lead SecOps"
                          className="w-full pl-8 pr-2 py-1.5 text-[12px] rounded-[6px] bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)]"
                        />
                      </div>
                    </div>

                    <div>
                      <label className="block text-[11px] font-medium text-[var(--muted-foreground)] mb-1">
                        Review Expiry Date
                      </label>
                      <div className="relative">
                        <Calendar className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-[var(--muted-foreground)]" />
                        <input
                          type="date"
                          value={expiresAt}
                          onChange={(e) => setExpiresAt(e.target.value)}
                          className="w-full pl-8 pr-2 py-1.5 text-[12px] rounded-[6px] bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)]"
                        />
                      </div>
                      <div className="flex items-center gap-1 mt-1 text-[10px]">
                        <button
                          type="button"
                          onClick={() => setExpiryDays(30)}
                          className="px-1.5 py-0.5 rounded bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
                        >
                          +30d
                        </button>
                        <button
                          type="button"
                          onClick={() => setExpiryDays(90)}
                          className="px-1.5 py-0.5 rounded bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
                        >
                          +90d
                        </button>
                        {expiresAt && (
                          <button
                            type="button"
                            onClick={() => setExpiresAt("")}
                            className="px-1.5 py-0.5 rounded text-rose-500 hover:underline"
                          >
                            Clear
                          </button>
                        )}
                      </div>
                    </div>

                    <div>
                      <label className="block text-[11px] font-medium text-[var(--muted-foreground)] mb-1">
                        Remediation Plan / Ticket
                      </label>
                      <div className="relative">
                        <Tag className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-[var(--muted-foreground)]" />
                        <input
                          type="text"
                          value={remediationPlanId}
                          onChange={(e) => setRemediationPlanId(e.target.value)}
                          placeholder="e.g. SEC-Sprint-42"
                          className="w-full pl-8 pr-2 py-1.5 text-[12px] rounded-[6px] bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)]"
                        />
                      </div>
                    </div>
                  </div>

                  {/* Notification banner */}
                  {saveSuccessMsg && (
                    <div className="p-2.5 rounded-[6px] bg-emerald-500/10 border border-emerald-500/30 text-emerald-500 text-[12px] flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
                      <span>{saveSuccessMsg}</span>
                    </div>
                  )}

                  {/* Action buttons */}
                  <div className="flex items-center justify-between pt-3 border-t border-[var(--border)]">
                    <button
                      type="button"
                      onClick={handleDeleteReview}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-[12px] rounded-[6px] border border-rose-500/30 text-rose-500 hover:bg-rose-500/10 transition-colors"
                      title="Clear local triage annotation"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      <span>Reset Triage</span>
                    </button>

                    <div className="flex items-center gap-2.5">
                      <button
                        type="button"
                        onClick={handleSaveReview}
                        className="flex items-center gap-1.5 px-4 py-2 text-[12px] rounded-[6px] bg-[var(--accent)] text-white hover:opacity-90 font-medium transition-opacity shadow-sm"
                      >
                        <Check className="w-4 h-4" />
                        <span>Save Triage Decision</span>
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="p-12 text-center text-[var(--muted-foreground)] bg-[var(--surface)] border border-[var(--border)] rounded-[10px]">
                Select a finding from the left list to inspect evidence and document review decisions.
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
