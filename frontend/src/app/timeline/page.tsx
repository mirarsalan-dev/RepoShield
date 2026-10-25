"use client";

import React, { useState, useEffect, useMemo, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import {
  Milestone,
  GitCommit,
  GitBranch,
  Clock,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Calendar,
  ExternalLink,
  Search,
  Filter,
  Download,
  HelpCircle,
  ArrowRight,
  ClipboardCheck,
  FileCode,
  User,
  Shield,
  Layers,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { api } from "@/lib/api";
import {
  ScanResult,
  Finding,
  Severity,
  TimelineEvent,
  TimelineEventType,
} from "@/lib/types";
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import { EmptyState } from "@/components/common/EmptyState";
import { formatDate, formatTimeAgo } from "@/lib/utils";

function TimelineContent() {
  const searchParams = useSearchParams();
  const urlFingerprint = searchParams?.get("fingerprint") || "";

  const [scans, setScans] = useState<ScanResult[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>("");
  const [selectedFingerprint, setSelectedFingerprint] = useState<string>(urlFingerprint);
  const [eventTypeFilter, setEventTypeFilter] = useState<string>("ALL");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [search, setSearch] = useState<string>("");
  const [timelineEvents, setTimelineEvents] = useState<TimelineEvent[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  // Load scans & review annotations from storage
  useEffect(() => {
    const history = storage.getScanHistory();
    setScans(history);
    if (history.length > 0) {
      setSelectedScanId(history[0].scan_id);
    }
  }, []);

  const activeScan = useMemo(() => {
    return scans.find((s) => s.scan_id === selectedScanId) || scans[0] || null;
  }, [scans, selectedScanId]);

  // Fetch or synthesize timeline events
  useEffect(() => {
    if (!activeScan) {
      setLoading(false);
      return;
    }

    setLoading(true);
    const reviews = storage.getReviewAnnotations();

    // Call backend timeline correlation API
    api
      .generateCustomTimeline(activeScan, scans, reviews)
      .then((res) => {
        setTimelineEvents(res.events || []);
      })
      .catch((err) => {
        console.warn("Backend timeline endpoint fallback, generating local timeline events:", err);
        // Fallback local synthesis if offline
        const localEvents: TimelineEvent[] = [];
        activeScan.findings.forEach((f) => {
          const fp = f.fingerprint || `${f.detector_name}:${f.rule_id}:${f.file_path}`;
          if (f.is_historical && f.commit_sha) {
            localEvents.push({
              id: `intro:${fp}:${f.commit_sha.slice(0, 8)}`,
              finding_id: f.id,
              finding_fingerprint: fp,
              finding_title: f.title,
              severity: f.severity,
              category: f.category,
              event_type: "CODE_INTRODUCTION",
              timestamp: f.commit_date || activeScan.created_at || "",
              title: `Code Introduction (${f.commit_sha.slice(0, 7)})`,
              description: `Commit ${f.commit_sha.slice(0, 7)} modified ${f.file_path} introducing matching pattern.`,
              commit_sha: f.commit_sha,
              commit_author: f.commit_author,
              source_reference: `Git commit history diff on ${f.file_path}`,
              confidence: "HIGH",
            });
          } else {
            localEvents.push({
              id: `obs:${fp}:${activeScan.commit_sha || "head"}`,
              finding_id: f.id,
              finding_fingerprint: fp,
              finding_title: f.title,
              severity: f.severity,
              category: f.category,
              event_type: "CODE_INTRODUCTION",
              timestamp: activeScan.created_at || "",
              title: `Earliest Observed Presence`,
              description: `Discovered in active branch HEAD commit ${activeScan.commit_sha?.slice(0, 7) || "HEAD"}.`,
              commit_sha: activeScan.commit_sha,
              source_reference: `Repository HEAD snapshot at ${f.file_path}`,
              confidence: "MEDIUM",
              is_gap_or_uncertain: true,
            });
          }

          // First detection
          localEvents.push({
            id: `det:${fp}:${activeScan.scan_id.slice(0, 8)}`,
            finding_id: f.id,
            finding_fingerprint: fp,
            finding_title: f.title,
            severity: f.severity,
            category: f.category,
            event_type: "FIRST_RECORDED_DETECTION",
            timestamp: activeScan.created_at || "",
            title: `First Recorded Detection by RepoShield`,
            description: `Scanner ${f.detector_name} flagged ${f.title} in ${f.file_path}.`,
            commit_sha: activeScan.commit_sha,
            source_reference: `Scanner ${f.detector_name}`,
            confidence: "HIGH",
          });

          // Review if present
          if (reviews[fp]) {
            const rev = reviews[fp];
            localEvents.push({
              id: `triage:${fp}:${rev.reviewed_at}`,
              finding_id: f.id,
              finding_fingerprint: fp,
              finding_title: f.title,
              severity: f.severity,
              category: f.category,
              event_type: "TRIAGE_REVIEWED",
              timestamp: rev.reviewed_at,
              title: `Triage Decision: ${rev.status.replace("_", " ")}`,
              description: `Reviewed by ${rev.reviewer}. Decision: ${rev.remediation_decision}. Notes: ${rev.investigation_notes || "None"}`,
              source_reference: `Review Workbench Record`,
              confidence: "HIGH",
            });
          }
        });

        localEvents.sort((a, b) => (b.timestamp || "").localeCompare(a.timestamp || ""));
        setTimelineEvents(localEvents);
      })
      .finally(() => {
        setLoading(false);
      });
  }, [activeScan, scans]);

  // Unique findings list for focus dropdown
  const uniqueFindings = useMemo(() => {
    if (!activeScan) return [];
    return activeScan.findings;
  }, [activeScan]);

  // Filtered timeline events
  const filteredEvents = useMemo(() => {
    return timelineEvents.filter((ev) => {
      // Focus finding
      if (selectedFingerprint && ev.finding_fingerprint !== selectedFingerprint) {
        return false;
      }

      // Event type
      if (eventTypeFilter !== "ALL" && ev.event_type !== eventTypeFilter) {
        return false;
      }

      // Severity
      if (severityFilter !== "ALL" && ev.severity !== severityFilter) {
        return false;
      }

      // Search
      if (search.trim()) {
        const q = search.toLowerCase();
        const matchesTitle = ev.title.toLowerCase().includes(q);
        const matchesDesc = ev.description.toLowerCase().includes(q);
        const matchesFinding = ev.finding_title.toLowerCase().includes(q);
        const matchesSha = ev.commit_sha?.toLowerCase().includes(q);
        if (!matchesTitle && !matchesDesc && !matchesFinding && !matchesSha) return false;
      }

      return true;
    });
  }, [timelineEvents, selectedFingerprint, eventTypeFilter, severityFilter, search]);

  const handleExportTimeline = () => {
    const data = {
      repository: activeScan?.repo || "Unknown",
      commit_sha: activeScan?.commit_sha || "HEAD",
      scan_id: activeScan?.scan_id || "",
      exported_at: new Date().toISOString(),
      total_events: filteredEvents.length,
      events: filteredEvents,
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `reposhield-incident-timeline-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const getEventBadge = (type: TimelineEventType) => {
    switch (type) {
      case "CODE_INTRODUCTION":
        return { label: "Code Introduction", color: "text-rose-500 bg-rose-500/10 border-rose-500/30" };
      case "FIRST_RECORDED_DETECTION":
        return { label: "First Detection", color: "text-amber-500 bg-amber-500/10 border-amber-500/30" };
      case "ADVISORY_PUBLISHED":
        return { label: "Public Advisory", color: "text-purple-500 bg-purple-500/10 border-purple-500/30" };
      case "TRIAGE_REVIEWED":
        return { label: "Triage Review", color: "text-blue-500 bg-blue-500/10 border-blue-500/30" };
      case "REMEDIATION_COMMITTED":
        return { label: "Remediation Commit", color: "text-emerald-500 bg-emerald-500/10 border-emerald-500/30" };
      case "VERIFICATION_RESULT":
        return { label: "Verification Result", color: "text-teal-500 bg-teal-500/10 border-teal-500/30" };
      case "RECURRENCE":
        return { label: "Recurrence", color: "text-orange-500 bg-orange-500/10 border-orange-500/30" };
      default:
        return { label: type, color: "text-neutral-400 bg-neutral-500/10 border-neutral-500/30" };
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12 animate-in fade-in duration-300">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-[var(--border)] pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-[8px] bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-500">
              <Milestone className="w-4 h-4" />
            </div>
            <h1 className="text-xl font-semibold tracking-tight text-[var(--foreground)]">
              Vulnerability Origin & Incident Timeline
            </h1>
          </div>
          <p className="text-[13px] text-[var(--muted-foreground)] mt-1">
            Chronological audit log tracking code introductions, commit diffs, first recorded detections, and review decisions.
          </p>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          {scans.length > 0 && (
            <select
              value={selectedScanId}
              onChange={(e) => setSelectedScanId(e.target.value)}
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
            onClick={handleExportTimeline}
            className="flex items-center gap-1.5 px-3 py-1.5 text-[12px] rounded-[6px] bg-[var(--accent)] text-white hover:opacity-90 font-medium transition-opacity shadow-sm"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Timeline ({filteredEvents.length})</span>
          </button>
        </div>
      </div>

      {/* Honest Audit Banner & Uncertainty Disclosure */}
      <div className="p-3.5 rounded-[8px] bg-amber-500/10 border border-amber-500/20 text-amber-700 dark:text-amber-300 text-[12px] flex items-start gap-2.5">
        <HelpCircle className="w-4 h-4 flex-shrink-0 mt-0.5 text-amber-500" />
        <div className="leading-relaxed">
          <span className="font-semibold">Timeline Confidence & Gaps:</span> RepoShield explicitly distinguishes between <em>earliest observed scan occurrence</em> and the <em>actual commit introducing code</em>. Historical commit depth is bounded by shallow clone depth (up to 40 commits). Findings without an isolated git blame commit are labeled with medium confidence and flagged as earliest observed presence.
        </div>
      </div>

      {/* Filter and Finding Focus Toolbar */}
      <div className="p-4 rounded-[10px] bg-[var(--surface)] border border-[var(--border)] shadow-sm space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-center">
          {/* Finding Focus Dropdown */}
          <div className="md:col-span-5">
            <label className="block text-[11px] font-medium text-[var(--muted-foreground)] mb-1">
              Focus on Specific Vulnerability
            </label>
            <select
              value={selectedFingerprint}
              onChange={(e) => setSelectedFingerprint(e.target.value)}
              className="w-full px-3 py-1.5 text-[12px] rounded-[6px] bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)] truncate"
            >
              <option value="">All Findings ({uniqueFindings.length} in scope)</option>
              {uniqueFindings.map((f) => {
                const fp = f.fingerprint || `${f.detector_name}:${f.rule_id}:${f.file_path}`;
                return (
                  <option key={f.id} value={fp}>
                    [{f.severity}] {f.title} ({f.file_path})
                  </option>
                );
              })}
            </select>
          </div>

          {/* Event Type Filter */}
          <div className="md:col-span-3">
            <label className="block text-[11px] font-medium text-[var(--muted-foreground)] mb-1">
              Event Category
            </label>
            <select
              value={eventTypeFilter}
              onChange={(e) => setEventTypeFilter(e.target.value)}
              className="w-full px-3 py-1.5 text-[12px] rounded-[6px] bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)]"
            >
              <option value="ALL">All Lifecycle Events</option>
              <option value="CODE_INTRODUCTION">Code Introductions</option>
              <option value="FIRST_RECORDED_DETECTION">First Recorded Detections</option>
              <option value="ADVISORY_PUBLISHED">Public Advisories</option>
              <option value="TRIAGE_REVIEWED">Triage Reviews</option>
              <option value="REMEDIATION_COMMITTED">Remediation Commits</option>
              <option value="VERIFICATION_RESULT">Verification Results</option>
            </select>
          </div>

          {/* Severity Filter */}
          <div className="md:col-span-2">
            <label className="block text-[11px] font-medium text-[var(--muted-foreground)] mb-1">
              Severity
            </label>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="w-full px-3 py-1.5 text-[12px] rounded-[6px] bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)]"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          {/* Search Box */}
          <div className="md:col-span-2">
            <label className="block text-[11px] font-medium text-[var(--muted-foreground)] mb-1">
              Search
            </label>
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-[var(--muted-foreground)]" />
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Commit, title..."
                className="w-full pl-8 pr-2.5 py-1.5 text-[12px] rounded-[6px] bg-[var(--surface-subtle)] border border-[var(--border)] text-[var(--foreground)] focus:outline-none focus:ring-1 focus:ring-[var(--focus-ring)]"
              />
            </div>
          </div>
        </div>

        {selectedFingerprint && (
          <div className="flex items-center justify-between text-[11px] pt-2 border-t border-[var(--border)]">
            <span className="text-[var(--muted-foreground)]">
              Filtering timeline exclusively for selected finding fingerprint: <code className="font-mono text-[var(--foreground)]">{selectedFingerprint}</code>
            </span>
            <button
              onClick={() => setSelectedFingerprint("")}
              className="text-blue-500 hover:underline font-medium"
            >
              Clear focus filter
            </button>
          </div>
        )}
      </div>

      {/* Main Timeline View */}
      {loading ? (
        <div className="p-12 text-center text-[var(--muted-foreground)] bg-[var(--surface)] border border-[var(--border)] rounded-[10px]">
          Correlating git history, scan records, and vulnerability advisory timelines...
        </div>
      ) : filteredEvents.length === 0 ? (
        <EmptyState
          title="No Incident Timeline Events Found"
          description="Adjust your filters or focus selection to view historical vulnerability events."
        />
      ) : (
        <div className="relative pl-6 md:pl-8 border-l-2 border-[var(--border)] ml-3 md:ml-4 space-y-6">
          {filteredEvents.map((ev, idx) => {
            const badge = getEventBadge(ev.event_type);
            return (
              <div key={ev.id || idx} className="relative group">
                {/* Timeline node marker */}
                <div className="absolute -left-[31px] md:-left-[39px] top-1.5 w-4 h-4 rounded-full bg-[var(--surface)] border-2 border-[var(--accent)] group-hover:scale-110 transition-transform shadow-sm" />

                {/* Event Card */}
                <div className="p-4 rounded-[10px] bg-[var(--surface)] border border-[var(--border)] shadow-sm hover:border-[var(--border-hover)] transition-colors space-y-3">
                  {/* Top line: event type badge, severity, timestamp, confidence */}
                  <div className="flex items-center justify-between gap-3 flex-wrap">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`px-2 py-0.5 text-[10px] font-semibold rounded border uppercase ${badge.color}`}>
                        {badge.label}
                      </span>
                      <SeverityBadge severity={ev.severity} />
                      <span className="text-[11px] font-mono text-[var(--muted-foreground)]">
                        {ev.category}
                      </span>
                    </div>

                    <div className="flex items-center gap-3 text-[11px] text-[var(--muted-foreground)]">
                      {ev.confidence && (
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-medium border ${
                            ev.confidence === "HIGH"
                              ? "text-emerald-500 bg-emerald-500/10 border-emerald-500/30"
                              : "text-amber-500 bg-amber-500/10 border-amber-500/30"
                          }`}
                          title={ev.is_gap_or_uncertain ? "Gaps in historical records; inferred observation" : "Direct git diff confirmation"}
                        >
                          Confidence: {ev.confidence}
                        </span>
                      )}
                      <div className="flex items-center gap-1 font-mono">
                        <Clock className="w-3.5 h-3.5" />
                        <span>{formatDate(ev.timestamp)}</span>
                        <span>({formatTimeAgo(ev.timestamp)})</span>
                      </div>
                    </div>
                  </div>

                  {/* Title & Description */}
                  <div>
                    <h3 className="text-sm font-semibold text-[var(--foreground)]">
                      {ev.title}
                    </h3>
                    <p className="text-[12px] text-[var(--muted-foreground)] mt-1 leading-relaxed">
                      {ev.description}
                    </p>
                  </div>

                  {/* Association Details */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] pt-2 border-t border-[var(--border)] font-mono text-[var(--muted-foreground)]">
                    <div className="truncate">
                      <span className="text-[var(--foreground)] font-medium">Finding: </span>
                      {ev.finding_title}
                    </div>

                    <div className="truncate">
                      <span className="text-[var(--foreground)] font-medium">Source Ref: </span>
                      {ev.source_reference}
                    </div>

                    {ev.commit_sha && (
                      <div className="flex items-center gap-1.5">
                        <GitCommit className="w-3.5 h-3.5 text-blue-500" />
                        <span>Commit: </span>
                        <code className="text-blue-500 font-bold">{ev.commit_sha.slice(0, 8)}</code>
                        {ev.commit_author && (
                          <span className="text-[var(--muted-foreground)]">by {ev.commit_author}</span>
                        )}
                      </div>
                    )}

                    {ev.notes && (
                      <div className="md:col-span-2 text-[11px] text-[var(--muted-foreground)] italic font-sans">
                        Note: {ev.notes}
                      </div>
                    )}
                  </div>

                  {/* Quick action bar */}
                  <div className="flex items-center justify-end gap-3 pt-1 text-[11px]">
                    <Link
                      href={`/review-workbench?finding_id=${encodeURIComponent(ev.finding_id)}`}
                      className="flex items-center gap-1 text-[var(--muted-foreground)] hover:text-[var(--foreground)] transition-colors"
                    >
                      <ClipboardCheck className="w-3 h-3 text-indigo-500" />
                      <span>Review Workbench</span>
                    </Link>

                    <Link
                      href={`/fix-validation?finding_id=${encodeURIComponent(ev.finding_id)}`}
                      className="flex items-center gap-1 text-[var(--muted-foreground)] hover:text-[var(--foreground)] transition-colors"
                    >
                      <CheckCircle2 className="w-3 h-3 text-emerald-500" />
                      <span>Validate Fix</span>
                    </Link>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default function TimelinePage() {
  return (
    <Suspense fallback={<div className="p-12 text-center text-[var(--muted-foreground)]">Loading Incident Timeline...</div>}>
      <TimelineContent />
    </Suspense>
  );
}
