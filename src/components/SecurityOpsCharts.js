"use client";

import { useEffect, useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const COLORS = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#0284c7",
  blocked: "#0f766e",
  delivered: "#059669",
  retrying: "#d97706",
  failed: "#dc2626",
  neutral: "#64748b",
};

export function AttackTrendChart({ data = [] }) {
  return (
    <ChartFrame>
      <AreaChart data={data}>
        <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
        <XAxis dataKey="label" tick={{ fontSize: 12 }} />
        <YAxis tick={{ fontSize: 12 }} allowDecimals={false} />
        <Tooltip />
        <Legend />
        <Area type="monotone" dataKey="critical" stackId="1" stroke={COLORS.critical} fill={COLORS.critical} />
        <Area type="monotone" dataKey="high" stackId="1" stroke={COLORS.high} fill={COLORS.high} />
        <Area type="monotone" dataKey="medium" stackId="1" stroke={COLORS.medium} fill={COLORS.medium} />
        <Area type="monotone" dataKey="low" stackId="1" stroke={COLORS.low} fill={COLORS.low} />
      </AreaChart>
    </ChartFrame>
  );
}

export function LineTrendChart({ data = [], lines = [] }) {
  return (
    <ChartFrame>
      <LineChart data={data}>
        <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
        <XAxis dataKey="label" tick={{ fontSize: 12 }} />
        <YAxis tick={{ fontSize: 12 }} allowDecimals={false} />
        <Tooltip />
        <Legend />
        {lines.map((line, index) => (
          <Line
            key={line.key}
            type="monotone"
            dataKey={line.key}
            stroke={line.color || palette(index)}
            strokeWidth={2}
            dot={false}
          />
        ))}
      </LineChart>
    </ChartFrame>
  );
}

export function HorizontalBarChart({ data = [], dataKey = "count", nameKey = "label" }) {
  return (
    <ChartFrame height={Math.max(220, data.length * 42)}>
      <BarChart data={data} layout="vertical" margin={{ left: 24, right: 20 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
        <XAxis type="number" allowDecimals={false} tick={{ fontSize: 12 }} />
        <YAxis type="category" dataKey={nameKey} width={120} tick={{ fontSize: 12 }} />
        <Tooltip />
        <Bar dataKey={dataKey} fill="#0f766e" radius={[0, 8, 8, 0]} />
      </BarChart>
    </ChartFrame>
  );
}

export function SeverityBarChart({ data = [] }) {
  return (
    <ChartFrame>
      <BarChart data={data}>
        <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
        <XAxis dataKey="label" tick={{ fontSize: 12 }} />
        <YAxis allowDecimals={false} tick={{ fontSize: 12 }} />
        <Tooltip />
        <Bar dataKey="count" radius={[8, 8, 0, 0]}>
          {data.map((item, index) => (
            <Cell key={`${item.label}-${index}`} fill={COLORS[item.label] || COLORS.neutral} />
          ))}
        </Bar>
      </BarChart>
    </ChartFrame>
  );
}

export function NotificationHealthChart({ data = [] }) {
  return (
    <ChartFrame>
      <BarChart data={data}>
        <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
        <XAxis dataKey="label" tick={{ fontSize: 12 }} />
        <YAxis allowDecimals={false} tick={{ fontSize: 12 }} />
        <Tooltip />
        <Legend />
        <Bar dataKey="delivered" stackId="a" fill={COLORS.delivered} />
        <Bar dataKey="retrying" stackId="a" fill={COLORS.retrying} />
        <Bar dataKey="failed" stackId="a" fill={COLORS.failed} />
      </BarChart>
    </ChartFrame>
  );
}

export function ProgressBar({ label, value, hint }) {
  const score = Math.max(0, Math.min(100, Number(value || 0)));
  return (
    <div>
      <div className="mb-2 flex items-center justify-between gap-3">
        <span className="text-sm font-medium text-slate-700">{label}</span>
        <span className="text-sm font-semibold text-slate-950">{score}%</span>
      </div>
      <div className="h-3 overflow-hidden rounded-full bg-slate-100">
        <div
          className="h-full rounded-full bg-emerald-500"
          style={{ width: `${score}%` }}
        />
      </div>
      {hint ? <p className="mt-1 text-xs text-slate-500">{hint}</p> : null}
    </div>
  );
}

export function chartLabel(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString(undefined, { month: "short", day: "2-digit", hour: "2-digit" });
}

function ChartFrame({ children, height = 280 }) {
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return (
      <div
        className="flex items-center justify-center rounded-md border border-slate-100 bg-slate-50 text-sm text-slate-500"
        style={{ width: "100%", height }}
      >
        Loading chart
      </div>
    );
  }

  return (
    <div style={{ width: "100%", height, minWidth: 0, minHeight: height }}>
      <ResponsiveContainer>{children}</ResponsiveContainer>
    </div>
  );
}

function palette(index) {
  return ["#0f766e", "#2563eb", "#d97706", "#dc2626", "#7c3aed"][index % 5];
}
