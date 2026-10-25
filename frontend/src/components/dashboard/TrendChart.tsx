"use client";

import React from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { ScanResult } from "@/lib/types";
import { formatTimeAgo } from "@/lib/utils";
import { TrendingUp, History } from "lucide-react";

interface TrendChartProps {
  history: ScanResult[];
}

export function TrendChart({ history }: TrendChartProps) {
  const chartData = [...history]
    .reverse()
    .slice(-8)
    .map((scan) => ({
      name: `${scan.repo.substring(0, 8)} (${formatTimeAgo(scan.started_at)})`,
      critical: scan.risk_score?.critical_count || 0,
      high: scan.risk_score?.high_count || 0,
      total: scan.risk_score?.total_findings || 0,
      score: scan.risk_score?.score || 0,
    }));

  if (chartData.length < 2) {
    return (
      <div className="macos-panel p-6 flex flex-col items-center justify-center h-[260px] text-center text-[var(--text-secondary)] space-y-2">
        <History className="w-6 h-6 text-[var(--text-secondary)]" />
        <div className="text-[13px] font-semibold text-[var(--text-primary)]">
          Vulnerability Trend
        </div>
        <p className="text-[12px] max-w-sm text-[var(--text-secondary)]">
          Historical trends populate automatically as you scan repositories and save results in your browser localStorage.
        </p>
      </div>
    );
  }

  return (
    <div className="macos-panel p-4 flex flex-col h-[260px]">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-[13px] font-semibold text-[var(--text-primary)] flex items-center gap-1.5">
          <TrendingUp className="w-4 h-4 text-[var(--accent)]" />
          <span>Vulnerability Trend Across Scans</span>
        </h3>
        <span className="text-[11px] text-[var(--text-secondary)]">
          Last {chartData.length} Scans
        </span>
      </div>

      <div className="flex-1 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#007AFF" stopOpacity={0.2} />
                <stop offset="95%" stopColor="#007AFF" stopOpacity={0.0} />
              </linearGradient>
              <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#FF3B30" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#FF3B30" stopOpacity={0.0} />
              </linearGradient>
            </defs>
            <XAxis
              dataKey="name"
              stroke="var(--text-secondary)"
              fontSize={10}
              tickLine={false}
              axisLine={{ stroke: "var(--border-subtle)" }}
            />
            <YAxis
              stroke="var(--text-secondary)"
              fontSize={10}
              tickLine={false}
              axisLine={{ stroke: "var(--border-subtle)" }}
              allowDecimals={false}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "var(--bg-secondary)",
                borderColor: "var(--border-subtle)",
                borderRadius: "6px",
                fontSize: "12px",
                color: "var(--text-primary)",
              }}
            />
            <Area
              type="monotone"
              dataKey="total"
              name="Total Findings"
              stroke="#007AFF"
              strokeWidth={1.5}
              fillOpacity={1}
              fill="url(#colorTotal)"
            />
            <Area
              type="monotone"
              dataKey="critical"
              name="Critical Issues"
              stroke="#FF3B30"
              strokeWidth={1.5}
              fillOpacity={1}
              fill="url(#colorCritical)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
