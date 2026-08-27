"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";
import MetricCard from "@/components/MetricCard";

export default function CorrelationEventsPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const res = await api.getCorrelationEvents({ limit: 50 });
      setData(res.data);
    } catch (err) {
      setError(err.message || "Failed to load correlation events");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const items = data?.items || [];
  const maxRisk = items.reduce((value, item) => Math.max(value, Number(item.riskScore || 0)), 0);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Correlation Events"
        subtitle="Multi-request attack chains across detectors, endpoints, identities, and time windows"
        actions={<button className="btn-primary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
        <MetricCard title="Attack Chains" value={items.length} hint="Correlated findings in the current window" />
        <MetricCard title="Highest Risk" value={Math.round(maxRisk)} hint="Maximum correlated risk score" />
        <MetricCard title="Critical Chains" value={items.filter((item) => item.severity === "critical").length} hint="Needs immediate review" />
      </div>
      <SectionCard title="Correlated Attack Patterns">
        <SimpleTable
          columns={[
            { key: "windowEnd", label: "Window End", render: (row) => formatDate(row.windowEnd) },
            { key: "correlationType", label: "Pattern" },
            { key: "severity", label: "Severity" },
            { key: "riskScore", label: "Risk" },
            { key: "confidence", label: "Confidence", render: (row) => `${Math.round(Number(row.confidence || 0) * 100)}%` },
            { key: "relatedEventIds", label: "Events", render: (row) => row.relatedEventIds?.length || 0 },
            { key: "relatedDetectorIds", label: "Detectors", render: (row) => row.relatedDetectorIds?.length || 0 },
          ]}
          rows={items}
          emptyText="No correlated attack chains in this window"
        />
      </SectionCard>
    </div>
  );
}

function ErrorBanner({ message }) {
  return <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">{message}</div>;
}

function formatDate(value) {
  return value ? new Date(value).toLocaleString() : "";
}
