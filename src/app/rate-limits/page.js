"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import MetricCard from "@/components/MetricCard";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

export default function RateLimitsPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const res = await api.getRateLimits({ limit: 100 });
      setData(res.data);
    } catch (err) {
      setError(err.message || "Failed to load rate limits");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const items = data?.items || [];
  return (
    <div className="space-y-6">
      <PageHeader title="Rate Limits" subtitle="Bounded adaptive throttling policies by organization, firewall, route, credential, or source" actions={<button className="btn-primary" onClick={load}>Refresh</button>} />
      {error ? <ErrorBanner message={error} /> : null}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
        <MetricCard title="Policies" value={items.length} hint="Configured rate-limit policies" />
        <MetricCard title="Active" value={items.filter((item) => item.status === "active").length} hint="Ready for protection evaluation" />
        <MetricCard title="Smallest Window" value={smallestWindow(items)} hint="Seconds" />
      </div>
      <SectionCard title="Rate-Limit Policies">
        <SimpleTable
          columns={[
            { key: "name", label: "Name" },
            { key: "dimension", label: "Dimension" },
            { key: "limitCount", label: "Limit" },
            { key: "windowSeconds", label: "Window" },
            { key: "status", label: "Status" },
          ]}
          rows={items}
          emptyText="No rate-limit policies configured"
        />
      </SectionCard>
    </div>
  );
}

function ErrorBanner({ message }) {
  return <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">{message}</div>;
}

function smallestWindow(items) {
  if (!items.length) return 0;
  return Math.min(...items.map((item) => Number(item.windowSeconds || 0)).filter(Boolean));
}
