"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";
import MetricCard from "@/components/MetricCard";

export default function DetectionsPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const res = await api.getDetections({ limit: 50 });
      setData(res.data);
    } catch (err) {
      setError(err.message || "Failed to load detections");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const items = data?.items || [];
  const critical = items.filter((item) => item.severity === "critical").length;
  const high = items.filter((item) => item.severity === "high").length;
  const avgRisk = items.length
    ? Math.round(items.reduce((sum, item) => sum + Number(item.riskScore || 0), 0) / items.length)
    : 0;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Detections"
        subtitle="Behavioral findings, abuse signals, explainable risk factors, and analyst feedback"
        actions={<button className="btn-primary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
        <MetricCard title="Open Findings" value={items.length} hint="Advanced behavioral findings in scope" />
        <MetricCard title="Critical / High" value={`${critical} / ${high}`} hint="Requires analyst attention" />
        <MetricCard title="Average Risk" value={avgRisk} hint="Composite score across current findings" />
      </div>
      <SectionCard title="Advanced Detection Findings">
        <SimpleTable
          columns={[
            { key: "lastSeenAt", label: "Last Seen", render: (row) => formatDate(row.lastSeenAt) },
            { key: "findingType", label: "Finding" },
            { key: "detectorId", label: "Detector" },
            { key: "severity", label: "Severity" },
            { key: "riskScore", label: "Risk" },
            { key: "confidence", label: "Confidence", render: (row) => `${Math.round(Number(row.confidence || 0) * 100)}%` },
            { key: "eventCount", label: "Events" },
          ]}
          rows={items}
          emptyText="No advanced detection findings in this window"
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
