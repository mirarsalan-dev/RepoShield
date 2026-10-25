"use client";

import React from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import { RiskScore } from "@/lib/types";

interface SeverityChartProps {
  riskScore?: RiskScore;
}

const SEVERITY_COLORS = {
  Critical: "#FF3B30",
  High: "#FF9500",
  Medium: "#F5A623",
  Low: "#34C759",
  Info: "#007AFF",
};

export function SeverityChart({ riskScore }: SeverityChartProps) {
  if (!riskScore) return null;

  const data = [
    { name: "Critical", count: riskScore.critical_count || 0, color: SEVERITY_COLORS.Critical },
    { name: "High", count: riskScore.high_count || 0, color: SEVERITY_COLORS.High },
    { name: "Medium", count: riskScore.medium_count || 0, color: SEVERITY_COLORS.Medium },
    { name: "Low", count: riskScore.low_count || 0, color: SEVERITY_COLORS.Low },
  ];

  return (
    <div className="macos-panel p-4 flex flex-col h-[280px]">
      <div className="flex items-center justify-between pb-2 border-b border-[var(--border-subtle)] mb-2">
        <h3 className="text-[13px] font-semibold text-[var(--text-primary)]">
          Findings by Severity
        </h3>
        <span className="text-[11px] text-[var(--text-muted)] font-mono">
          {riskScore.total_findings} findings
        </span>
      </div>

      <div className="flex-1 w-full pt-2">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 8, right: 8, left: -24, bottom: 0 }}>
            <XAxis
              dataKey="name"
              stroke="var(--text-muted)"
              fontSize={11}
              tickLine={false}
              axisLine={{ stroke: "var(--border-subtle)" }}
            />
            <YAxis
              stroke="var(--text-muted)"
              fontSize={11}
              tickLine={false}
              axisLine={{ stroke: "var(--border-subtle)" }}
              allowDecimals={false}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "var(--bg-surface)",
                borderColor: "var(--border-color)",
                borderRadius: "6px",
                fontSize: "12px",
                color: "var(--text-primary)",
                boxShadow: "0 4px 12px rgba(0,0,0,0.1)",
              }}
              cursor={{ fill: "rgba(120, 120, 128, 0.08)" }}
            />
            <Bar dataKey="count" radius={[4, 4, 0, 0]}>
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
