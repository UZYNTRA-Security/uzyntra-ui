"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";
import MetricCard from "@/components/MetricCard";

export default function PoliciesPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const res = await api.getZeroTrustPolicies({ limit: 100 });
      setData(res.data);
    } catch (err) {
      setError(err.message || "Failed to load policies");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const items = data?.items || [];
  return (
    <div className="space-y-6">
      <PageHeader
        title="Policies"
        subtitle="Immutable Zero Trust policy versions, deployment modes, rollback targets, and fail behavior"
        actions={<button className="btn-primary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
        <MetricCard title="Policies" value={items.length} hint="Configured policy records" />
        <MetricCard title="Observe" value={items.filter((item) => item.mode === "observe").length} hint="Decision-only evaluation" />
        <MetricCard title="Enforce" value={items.filter((item) => item.mode === "enforce").length} hint="Active enforcement candidates" />
      </div>
      <SectionCard title="Zero Trust Policies">
        <SimpleTable
          columns={[
            { key: "name", label: "Name" },
            { key: "status", label: "Status" },
            { key: "mode", label: "Mode" },
            { key: "failBehavior", label: "Fail Behavior" },
            { key: "activeVersionId", label: "Active Version", render: (row) => row.activeVersionId ? row.activeVersionId.slice(0, 8) : "" },
            { key: "updatedAt", label: "Updated", render: (row) => formatDate(row.updatedAt) },
          ]}
          rows={items}
          emptyText="No Zero Trust policies configured"
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
