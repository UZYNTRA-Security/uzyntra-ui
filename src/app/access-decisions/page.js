"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";
import MetricCard from "@/components/MetricCard";
import { HorizontalBarChart } from "@/components/SecurityOpsCharts";

export default function AccessDecisionsPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const res = await api.getPolicyDecisions({ limit: 100 });
      setData(res.data);
    } catch (err) {
      setError(err.message || "Failed to load policy decisions");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const items = data?.items || [];
  const chartData = useMemo(() => {
    const counts = items.reduce((acc, item) => {
      acc[item.decision] = (acc[item.decision] || 0) + 1;
      return acc;
    }, {});
    return Object.entries(counts).map(([label, count]) => ({ label, count }));
  }, [items]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Access Decisions"
        subtitle="Decision history for allow, challenge, rate limit, block, and quarantine outcomes"
        actions={<button className="btn-primary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
        <MetricCard title="Decisions" value={items.length} hint="Within the current query window" />
        <MetricCard title="Challenge" value={items.filter((item) => item.decision === "challenge").length} hint="Step-up verification outcomes" />
        <MetricCard title="Rate Limited" value={items.filter((item) => item.decision === "rate_limit").length} hint="Adaptive throttling outcomes" />
        <MetricCard title="Blocked" value={items.filter((item) => item.decision === "block").length} hint="Denied request outcomes" />
      </div>
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard title="Decision Distribution">
          <HorizontalBarChart data={chartData} />
        </SectionCard>
        <SectionCard title="Decision Timeline">
          <SimpleTable
            columns={[
              { key: "evaluatedAt", label: "Time", render: (row) => formatDate(row.evaluatedAt) },
              { key: "decision", label: "Decision" },
              { key: "mode", label: "Mode" },
              { key: "riskScore", label: "Risk" },
              { key: "confidence", label: "Confidence", render: (row) => `${Math.round(Number(row.confidence || 0) * 100)}%` },
              { key: "decisionReason", label: "Reason" },
            ]}
            rows={items}
            emptyText="No access decisions recorded"
          />
        </SectionCard>
      </div>
    </div>
  );
}

function ErrorBanner({ message }) {
  return <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">{message}</div>;
}

function formatDate(value) {
  return value ? new Date(value).toLocaleString() : "";
}
