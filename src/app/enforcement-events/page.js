"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import MetricCard from "@/components/MetricCard";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";
import { HorizontalBarChart } from "@/components/SecurityOpsCharts";

export default function EnforcementEventsPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const res = await api.getEnforcementEvents({ limit: 100 });
      setData(res.data);
    } catch (err) {
      setError(err.message || "Failed to load enforcement events");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const items = data?.items || [];
  const actionData = useMemo(() => {
    const counts = items.reduce((acc, item) => {
      acc[item.action] = (acc[item.action] || 0) + 1;
      return acc;
    }, {});
    return Object.entries(counts).map(([label, count]) => ({ label, count }));
  }, [items]);

  return (
    <div className="space-y-6">
      <PageHeader title="Enforcement Events" subtitle="Canonical adaptive protection outcomes for SOC review and future SOAR workflows" actions={<button className="btn-primary" onClick={load}>Refresh</button>} />
      {error ? <ErrorBanner message={error} /> : null}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
        <MetricCard title="Events" value={items.length} hint="Current query window" />
        <MetricCard title="Applied" value={items.filter((item) => item.outcome === "applied").length} hint="Enforcement-mode actions" />
        <MetricCard title="Observed" value={items.filter((item) => item.outcome === "observed").length} hint="Observe-mode recommendations" />
        <MetricCard title="Failed" value={items.filter((item) => item.outcome === "failed").length} hint="Fail-safe path visibility" />
      </div>
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard title="Action Distribution">
          <HorizontalBarChart data={actionData} />
        </SectionCard>
        <SectionCard title="Timeline">
          <SimpleTable
            columns={[
              { key: "createdAt", label: "Time", render: (row) => formatDate(row.createdAt) },
              { key: "action", label: "Action" },
              { key: "mode", label: "Mode" },
              { key: "outcome", label: "Outcome" },
              { key: "reason", label: "Reason" },
              { key: "riskScore", label: "Risk" },
            ]}
            rows={items}
            emptyText="No enforcement events"
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
