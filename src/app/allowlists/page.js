"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import MetricCard from "@/components/MetricCard";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

export default function AllowlistsPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const res = await api.getAllowlists({ limit: 100 });
      setData(res.data);
    } catch (err) {
      setError(err.message || "Failed to load allowlists");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const items = data?.items || [];
  return (
    <div className="space-y-6">
      <PageHeader title="Allowlists" subtitle="Bounded exception controls that never expose unrestricted bypasses" actions={<button className="btn-primary" onClick={load}>Refresh</button>} />
      {error ? <ErrorBanner message={error} /> : null}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
        <MetricCard title="Entries" value={items.length} hint="Scoped exception entries" />
        <MetricCard title="Active" value={items.filter((item) => item.status === "active").length} hint="Current allowlist controls" />
        <MetricCard title="Expiring" value={items.filter((item) => item.expiresAt).length} hint="TTL-backed exceptions" />
      </div>
      <SectionCard title="Allowlist Entries">
        <SimpleTable
          columns={[
            { key: "entryType", label: "Type" },
            { key: "entryLabel", label: "Entry" },
            { key: "status", label: "Status" },
            { key: "expiresAt", label: "Expires", render: (row) => formatDate(row.expiresAt) },
            { key: "reason", label: "Reason" },
          ]}
          rows={items}
          emptyText="No allowlist entries"
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
