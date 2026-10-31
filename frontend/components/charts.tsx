"use client";

import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { FindingCategory, RiskLevel } from "@/lib/api";
import { CATEGORY_META, RISK_STYLES } from "@/lib/risk";

const tooltipStyle = { background: "#0c1526", border: "1px solid #1c2b47", borderRadius: 8, color: "#e2e8f0", fontSize: 12 };
const axis = { fill: "#8a9bb8", fontSize: 12 };

export function RiskDistributionChart({ data }: { data: { level: RiskLevel; count: number }[] }) {
  const rows = data.map((d) => ({ name: RISK_STYLES[d.level].label, count: d.count, level: d.level }));
  return (
    <div className="h-64 w-full">
      <ResponsiveContainer>
        <BarChart data={rows} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
          <CartesianGrid stroke="#1c2b47" vertical={false} />
          <XAxis dataKey="name" tick={axis} axisLine={false} tickLine={false} />
          <YAxis allowDecimals={false} tick={axis} axisLine={false} tickLine={false} />
          <Tooltip cursor={{ fill: "rgba(76,201,240,0.06)" }} contentStyle={tooltipStyle} formatter={(v: number) => [v, "Scans"]} />
          <Bar dataKey="count" radius={[4, 4, 0, 0]} maxBarSize={48}>
            {rows.map((r) => <Cell key={r.level} fill={RISK_STYLES[r.level].hex} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

export function ThreatCategoryChart({ data }: { data: { category: FindingCategory; count: number }[] }) {
  const rows = data.map((d) => ({ name: CATEGORY_META[d.category].label, count: d.count }));
  return (
    <div className="h-64 w-full">
      <ResponsiveContainer>
        <BarChart data={rows} layout="vertical" margin={{ top: 4, right: 16, left: 8, bottom: 0 }}>
          <CartesianGrid stroke="#1c2b47" horizontal={false} />
          <XAxis type="number" allowDecimals={false} tick={axis} axisLine={false} tickLine={false} />
          <YAxis type="category" dataKey="name" width={110} tick={axis} axisLine={false} tickLine={false} />
          <Tooltip cursor={{ fill: "rgba(76,201,240,0.06)" }} contentStyle={tooltipStyle} formatter={(v: number) => [v, "Findings"]} />
          <Bar dataKey="count" fill="#4cc9f0" radius={[0, 4, 4, 0]} maxBarSize={22} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
