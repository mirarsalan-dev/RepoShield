"use client";

import React, { useState, useEffect, Suspense } from "react";
import Link from "next/link";
import {
  Network,
  Shield,
  AlertTriangle,
  ArrowRight,
  Filter,
  CheckCircle2,
  ExternalLink,
  ChevronRight,
  Sparkles,
  Info,
  Lock,
  Terminal,
  Activity,
  Layers,
} from "lucide-react";
import { storage } from "@/lib/storage";
import { ScanResult, AttackPathChain, AttackPathNode, Severity } from "@/lib/types";
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import { MacTrafficLights } from "@/components/common/Icons";

function AttackPathContent() {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [selectedChain, setSelectedChain] = useState<AttackPathChain | null>(null);
  const [selectedNode, setSelectedNode] = useState<AttackPathNode | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");

  useEffect(() => {
    const history = storage.getScanHistory();
    setScans(history);
    if (history.length > 0) {
      const active = history[0];
      setSelectedScan(active);
      const chains = active.attack_path_graph?.chains || [];
      if (chains.length > 0) {
        setSelectedChain(chains[0]);
        if (chains[0].nodes.length > 0) {
          setSelectedNode(chains[0].nodes[0]);
        }
      }
    }
  }, []);

  const handleScanChange = (scanId: string) => {
    const scan = scans.find((s) => s.scan_id === scanId);
    if (scan) {
      setSelectedScan(scan);
      const chains = scan.attack_path_graph?.chains || [];
      if (chains.length > 0) {
        setSelectedChain(chains[0]);
        setSelectedNode(chains[0].nodes[0] || null);
      } else {
        setSelectedChain(null);
        setSelectedNode(null);
      }
    }
  };

  const chains = selectedScan?.attack_path_graph?.chains || [];
  const filteredChains = chains.filter((c) => {
    if (severityFilter === "ALL") return true;
    return c.severity === severityFilter;
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Top Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-[var(--border-subtle)]">
        <div className="space-y-1 min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="p-1.5 rounded-[6px] bg-[var(--accent)]/10 text-[var(--accent)] shrink-0 flex-shrink-0">
              <Network className="w-5 h-5" />
            </span>
            <h1 className="text-[20px] font-semibold text-[var(--text-primary)] tracking-tight">
              Attack Path Visualizer
            </h1>
            <span className="text-[11px] font-mono px-2.5 py-0.5 rounded-full bg-[var(--accent)]/15 text-[var(--accent)] border border-[var(--accent)]/30 whitespace-nowrap shrink-0 flex-shrink-0 inline-flex items-center">
              Evidence-Backed Graph
            </span>
          </div>
          <p className="text-[13px] text-[var(--text-secondary)] mt-1">
            Correlates individual vulnerabilities, credentials, and infrastructure weaknesses into realistic exploit chains to prioritize high-leverage choke points.
          </p>
        </div>

        {/* Scan Selector */}
        {scans.length > 0 && (
          <div className="flex items-center gap-3">
            <span className="text-[12px] text-[var(--text-secondary)]">Target:</span>
            <select
              value={selectedScan?.scan_id || ""}
              onChange={(e) => handleScanChange(e.target.value)}
              className="macos-input text-[12px] py-1 px-2.5 max-w-[220px]"
            >
              {scans.map((s) => (
                <option key={s.scan_id} value={s.scan_id}>
                  {s.owner}/{s.repo} ({s.attack_path_graph?.total_paths || 0} paths)
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {chains.length === 0 ? (
        <div className="macos-panel p-12 text-center max-w-lg mx-auto space-y-3">
          <Shield className="w-10 h-10 text-[var(--system-green)] mx-auto" />
          <h3 className="text-[15px] font-semibold text-[var(--text-primary)]">
            No Exploitable Attack Paths Identified
          </h3>
          <p className="text-[13px] text-[var(--text-secondary)] leading-relaxed">
            RepoShield did not detect multi-stage attack chains in this repository. All current findings remain isolated without evidence supporting lateral privilege movement.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Attack Chains List */}
          <div className="lg:col-span-4 space-y-3">
            <div className="flex items-center justify-between px-1">
              <span className="text-[12px] font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
                Identified Chains ({filteredChains.length})
              </span>
              <div className="flex items-center gap-1.5">
                <Filter className="w-3 h-3 text-[var(--text-muted)]" />
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="macos-input text-[11px] py-0.5 px-1.5"
                >
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                </select>
              </div>
            </div>

            <div className="macos-panel divide-y divide-[var(--border-subtle)] max-h-[640px] overflow-y-auto">
              {filteredChains.map((c) => {
                const isSelected = selectedChain?.id === c.id;
                return (
                  <button
                    key={c.id}
                    onClick={() => {
                      setSelectedChain(c);
                      setSelectedNode(c.nodes[0] || null);
                    }}
                    className={`w-full text-left p-3.5 transition-colors ${
                      isSelected
                        ? "bg-[var(--accent)]/10 border-l-2 border-[var(--accent)]"
                        : "hover:bg-[var(--bg-hover)]"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <SeverityBadge severity={c.severity} />
                      <span className="text-[11px] font-mono text-[var(--text-muted)]">
                        {c.nodes.length} Steps
                      </span>
                    </div>
                    <div className="text-[13px] font-medium text-[var(--text-primary)] mt-1.5">
                      {c.title}
                    </div>
                    <div className="text-[11px] text-[var(--text-secondary)] mt-1 line-clamp-2">
                      {c.risk_summary}
                    </div>
                  </button>
                );
              })}
            </div>

            {/* Critical Choke Points Card */}
            {selectedScan?.attack_path_graph?.choke_points && selectedScan.attack_path_graph.choke_points.length > 0 && (
              <div className="macos-panel p-4 space-y-2.5 border-[var(--system-green)]/30 bg-[var(--system-green)]/5">
                <div className="flex items-center gap-2 text-[var(--system-green)] font-semibold text-[12px] uppercase">
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Strategic Choke Points</span>
                </div>
                <p className="text-[12px] text-[var(--text-secondary)]">
                  Remediating these key findings severs the largest number of attack trajectories:
                </p>
                <ul className="text-[12px] text-[var(--text-primary)] space-y-1.5 pl-4 list-disc">
                  {selectedScan.attack_path_graph.choke_points.map((cp, idx) => (
                    <li key={idx} className="leading-snug">{cp}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Right Column: Visual Graph & Step Details */}
          <div className="lg:col-span-8 space-y-5">
            {selectedChain && (
              <>
                {/* Chain Overview Banner */}
                <div className="macos-panel p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={selectedChain.severity} />
                      <h2 className="text-[16px] font-semibold text-[var(--text-primary)]">
                        {selectedChain.title}
                      </h2>
                    </div>
                    <MacTrafficLights />
                  </div>
                  <p className="text-[13px] text-[var(--text-secondary)] leading-relaxed">
                    {selectedChain.risk_summary}
                  </p>

                  <div className="p-2.5 rounded-[6px] bg-[var(--accent)]/10 border border-[var(--accent)]/20 text-[12px] text-[var(--accent)] flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
                    <span><strong>Interrupt Action:</strong> {selectedChain.interrupt_action}</span>
                  </div>
                </div>

                {/* Graph Progression Pipeline */}
                <div className="macos-panel p-5 space-y-4">
                  <span className="text-[11px] font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
                    Exploit Flow Progression
                  </span>

                  <div className="flex flex-col md:flex-row items-stretch justify-between gap-3 relative">
                    {selectedChain.nodes.map((node, idx) => {
                      const isSelected = selectedNode?.id === node.id;
                      const isLast = idx === selectedChain.nodes.length - 1;

                      return (
                        <React.Fragment key={node.id}>
                          <button
                            onClick={() => setSelectedNode(node)}
                            className={`flex-1 p-3.5 rounded-[8px] border text-left transition-all ${
                              isSelected
                                ? "bg-[var(--accent)]/15 border-[var(--accent)] ring-1 ring-[var(--accent)]"
                                : "bg-[var(--bg-secondary)] border-[var(--border-subtle)] hover:border-[var(--text-secondary)]"
                            }`}
                          >
                            <div className="flex items-center justify-between gap-1">
                              <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-[var(--bg-primary)] border border-[var(--border-subtle)] text-[var(--text-secondary)]">
                                {node.node_type}
                              </span>
                              <SeverityBadge severity={node.severity} />
                            </div>

                            <div className="text-[13px] font-semibold text-[var(--text-primary)] mt-2 line-clamp-2">
                              {node.label}
                            </div>

                            {node.file_path && (
                              <div className="text-[11px] font-mono text-[var(--text-muted)] mt-1 truncate">
                                {node.file_path}
                              </div>
                            )}
                          </button>

                          {!isLast && (
                            <div className="hidden md:flex items-center justify-center text-[var(--text-muted)]">
                              <ArrowRight className="w-4 h-4" />
                            </div>
                          )}
                        </React.Fragment>
                      );
                    })}
                  </div>
                </div>

                {/* Selected Node Evidence Inspector */}
                {selectedNode && (
                  <div className="macos-panel p-5 space-y-4 border-[var(--border-subtle)]">
                    <div className="flex items-center justify-between pb-2 border-b border-[var(--border-subtle)]">
                      <div>
                        <span className="text-[11px] font-mono uppercase text-[var(--accent)]">
                          Node Inspector • {selectedNode.node_type}
                        </span>
                        <h3 className="text-[15px] font-semibold text-[var(--text-primary)] mt-0.5">
                          {selectedNode.label}
                        </h3>
                      </div>

                      <div className="flex items-center gap-2">
                        <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[var(--bg-secondary)] border border-[var(--border-subtle)] text-[var(--system-green)]">
                          {selectedNode.evidence_status}
                        </span>
                        {selectedNode.finding_id && (
                          <Link
                            href={`/findings/${selectedNode.finding_id}`}
                            className="macos-button text-[12px] flex items-center gap-1 text-[var(--accent)]"
                          >
                            <span>Inspect Finding</span>
                            <ExternalLink className="w-3 h-3" />
                          </Link>
                        )}
                      </div>
                    </div>

                    {selectedNode.evidence && (
                      <div className="space-y-1.5">
                        <div className="text-[11px] font-semibold text-[var(--text-secondary)] uppercase">
                          Observed Evidence Snippet
                        </div>
                        <pre className="p-3 rounded-[6px] bg-[var(--bg-secondary)] border border-[var(--border-subtle)] font-mono text-[11px] text-[var(--text-primary)] overflow-x-auto whitespace-pre">
                          {selectedNode.evidence}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function AttackPathVisualizerPage() {
  return (
    <Suspense fallback={<div className="p-8 text-center text-[var(--text-muted)]">Loading Attack Path Visualizer...</div>}>
      <AttackPathContent />
    </Suspense>
  );
}
