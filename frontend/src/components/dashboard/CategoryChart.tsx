"use client";

import React from "react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import { RiskScore } from "@/lib/types";

interface CategoryChartProps {
  riskScore?: RiskScore;
}

// macOS system colors: Red (Secrets), Orange (Dependencies), Blue (SAST)
const CATEGORY_COLORS = ["#FF3B30", "#FF9500", "#007AFF"];

export function CategoryChart({ riskScore }: CategoryChartProps) {
  if (!riskScore) return null;

  const data = [
    { name: "Secrets", value: riskScore.secrets_count },
    { name: "Dependencies", value: riskScore.dependencies_count },
    { name: "Static Code (SAST)", value: riskScore.sast_count },
  ].filter((d) => d.value > 0);

  if (data.length === 0) {
    return (
      <div className="macos-panel p-5 flex flex-col items-center justify-center h-[280px] text-center text-[var(--text-secondary)]">
        <div className="text-[13px] font-semibold text-[var(--text-primary)] mb-1">
          Category Distribution
        </div>
        <p className="text-[12px]">No vulnerabilities detected in this scan.</p>
      </div>
    );
  }

  return (
    <div className="macos-panel p-4 flex flex-col h-[280px]">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-[13px] font-semibold text-[var(--text-primary)]">
          Category Distribution
        </h3>
        <span className="text-[11px] text-[var(--text-secondary)]">
          {data.length} Categories
        </span>
      </div>

      <div className="flex-1 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              innerRadius={50}
              outerRadius={75}
              paddingAngle={3}
              dataKey="value"
            >
              {data.map((_, index) => (
                <Cell
                  key={`cell-${index}`}
                  fill={CATEGORY_COLORS[index % CATEGORY_COLORS.length]}
                />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: "var(--bg-secondary)",
                borderColor: "var(--border-subtle)",
                borderRadius: "6px",
                fontSize: "12px",
                color: "var(--text-primary)",
              }}
            />
            <Legend
              verticalAlign="bottom"
              height={32}
              formatter={(value) => (
                <span className="text-[11px] text-[var(--text-secondary)]">{value}</span>
              )}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
