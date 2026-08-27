"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";
import MetricCard from "@/components/MetricCard";
import { HorizontalBarChart } from "@/components/SecurityOpsCharts";

export default function RiskAnalysisPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const res = await api.getRiskAnalysis();
      setData(res.data);
    } catch (err) {
      setError(err.message || "Failed to load risk analysis");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const topDetectors = useMemo(
    () => (data?.topDetectors || []).map((item) => ({ label: item.detectorId, count: item.avgRisk || item.count })),
    [data],
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Risk Analysis"
        subtitle="Composite event, client, API, and tenant risk built from deterministic detection signals"
        actions={<button className="btn-primary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
        <MetricCard title="Composite Risk" value={data?.summary?.compositeRisk || 0} hint="Highest current advanced risk" />
        <MetricCard title="Findings" value={data?.summary?.findings?.total || 0} hint="Behavioral findings in the window" />
        <MetricCard title="Correlations" value={data?.summary?.correlations?.total || 0} hint="Multi-signal attack chains" />
        <MetricCard title="Avg Confidence" value={`${Math.round(Number(data?.summary?.findings?.avgConfidence || 0) * 100)}%`} hint="Detection confidence average" />
      </div>
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard title="Top Detector Risk">
          <HorizontalBarChart data={topDetectors} />
        </SectionCard>
        <SectionCard title="Behavioral Baselines">
          <SimpleTable
            columns={[
              { key: "baselineKeyLabel", label: "Client" },
              { key: "baselineType", label: "Type" },
              { key: "sampleCount", label: "Samples" },
              { key: "requestRatePerMinute", label: "Req/min" },
              { key: "learnedAt", label: "Learned", render: (row) => formatDate(row.learnedAt) },
            ]}
            rows={data?.baselines || []}
            emptyText="No behavioral baselines learned yet"
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
