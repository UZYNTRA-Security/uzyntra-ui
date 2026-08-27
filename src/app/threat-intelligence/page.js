"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";
import MetricCard from "@/components/MetricCard";
import { HorizontalBarChart } from "@/components/SecurityOpsCharts";

export default function ThreatIntelligencePage() {
  const [data, setData] = useState(null);
  const [matches, setMatches] = useState(null);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const [overviewRes, matchesRes] = await Promise.all([
        api.getThreatIntelligence(),
        api.getThreatMatches({ limit: 10 }),
      ]);
      setData(overviewRes.data);
      setMatches(matchesRes.data);
    } catch (err) {
      setError(err.message || "Failed to load threat intelligence");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const categories = useMemo(
    () => (data?.categories || []).map((item) => ({ label: item.category, count: item.count })),
    [data],
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Threat Intelligence"
        subtitle="Local and future provider intelligence feeding risk scoring, detection enrichment, and SOC triage"
        actions={<button className="btn-primary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}

      <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
        <MetricCard title="Indicators" value={data?.summary?.indicators?.total || 0} hint="Active global and tenant indicators" />
        <MetricCard title="Malicious" value={data?.summary?.indicators?.malicious || 0} hint="Reputation score 70+" />
        <MetricCard title="Matches" value={data?.summary?.matches?.total || 0} hint="Indicator matches in scope" />
        <MetricCard title="Max Risk Delta" value={data?.summary?.matches?.maxRiskDelta || 0} hint="Largest enrichment impact" />
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard title="Indicator Categories">
          <HorizontalBarChart data={categories} />
        </SectionCard>
        <SectionCard title="Source Health">
          <div className="grid grid-cols-2 gap-4 text-sm">
            {["healthy", "degraded", "failed", "unknown"].map((key) => (
              <div key={key} className="rounded-lg border border-slate-200 bg-slate-50 p-4">
                <p className="font-semibold capitalize text-slate-700">{key}</p>
                <p className="mt-2 text-3xl font-bold text-slate-950">{data?.summary?.sourceHealth?.[key] || 0}</p>
              </div>
            ))}
          </div>
        </SectionCard>
        <SectionCard title="Recent Indicator Matches">
          <SimpleTable
            columns={[
              { key: "matchedAt", label: "Matched", render: (row) => formatDate(row.matchedAt) },
              { key: "indicatorType", label: "Type" },
              { key: "matchLabel", label: "Indicator" },
              { key: "matchContext", label: "Context" },
              { key: "riskDelta", label: "Risk +" },
              { key: "confidenceDelta", label: "Confidence +", render: (row) => `${Math.round(Number(row.confidenceDelta || 0) * 100)}%` },
            ]}
            rows={matches?.items || []}
            emptyText="No threat intelligence matches in this window"
          />
        </SectionCard>
        <SectionCard title="Configured Sources">
          <SimpleTable
            columns={[
              { key: "name", label: "Source" },
              { key: "providerType", label: "Provider" },
              { key: "status", label: "Status" },
              { key: "healthStatus", label: "Health" },
              { key: "lastSyncAt", label: "Last Sync", render: (row) => formatDate(row.lastSyncAt) },
            ]}
            rows={data?.sources || []}
            emptyText="No intelligence sources configured yet"
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
