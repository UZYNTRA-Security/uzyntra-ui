"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import MetricCard from "@/components/MetricCard";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

export default function PolicyDecisionsPage() {
  const [data, setData] = useState(null);
  const [selected, setSelected] = useState(null);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const res = await api.getPolicyDecisions({ limit: 100 });
      setData(res.data);
      const first = res.data.items?.[0];
      if (first?.id) {
        const explanation = await api.explainPolicyDecision(first.id);
        setSelected(explanation.data);
      }
    } catch (err) {
      setError(err.message || "Failed to load policy decisions");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const items = data?.items || [];
  return (
    <div className="space-y-6">
      <PageHeader title="Policy Decisions" subtitle="Immutable decision history with explanation and risk context" actions={<button className="btn-primary" onClick={load}>Refresh</button>} />
      {error ? <ErrorBanner message={error} /> : null}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
        <MetricCard title="Decisions" value={items.length} hint="Current query window" />
        <MetricCard title="Block" value={items.filter((item) => item.decision === "block").length} hint="High-confidence denials" />
        <MetricCard title="Challenge" value={items.filter((item) => item.decision === "challenge").length} hint="Step-up candidates" />
        <MetricCard title="Avg Risk" value={average(items.map((item) => item.riskScore))} hint="Normalized decision score" />
      </div>
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1fr)_420px]">
        <SectionCard title="Decision Timeline">
          <SimpleTable
            columns={[
              { key: "evaluatedAt", label: "Time", render: (row) => formatDate(row.evaluatedAt) },
              { key: "decision", label: "Decision" },
              { key: "mode", label: "Mode" },
              { key: "riskScore", label: "Risk" },
              { key: "confidence", label: "Confidence" },
              { key: "decisionReason", label: "Reason" },
            ]}
            rows={items}
            emptyText="No policy decisions"
          />
        </SectionCard>
        <SectionCard title="Explanation">
          <pre className="max-h-[420px] overflow-auto rounded-xl bg-slate-950 p-4 text-xs text-slate-50">
            {selected ? JSON.stringify(selected.explanation, null, 2) : "No decision selected"}
          </pre>
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

function average(values) {
  const numbers = values.map(Number).filter(Number.isFinite);
  if (!numbers.length) return "-";
  return Math.round(numbers.reduce((sum, value) => sum + value, 0) / numbers.length);
}
