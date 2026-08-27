"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

export default function IntelligenceSourcesPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const res = await api.getThreatSources();
      setData(res.data);
    } catch (err) {
      setError(err.message || "Failed to load intelligence sources");
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Intelligence Sources"
        subtitle="Provider abstraction, source health, sync status, rate limits, and future feed readiness"
        actions={<button className="btn-primary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      <SectionCard title="Source Health and Capabilities">
        <SimpleTable
          columns={[
            { key: "name", label: "Source" },
            { key: "providerType", label: "Provider" },
            { key: "status", label: "Status" },
            { key: "healthStatus", label: "Health" },
            { key: "capabilities", label: "Capabilities", render: (row) => (row.capabilities || []).join(", ") },
            { key: "rateLimitPerMinute", label: "Rate/min" },
            { key: "timeoutMs", label: "Timeout" },
            { key: "lastFailureCode", label: "Last Failure" },
          ]}
          rows={data?.items || []}
          emptyText="No intelligence sources configured yet"
        />
      </SectionCard>
    </div>
  );
}

function ErrorBanner({ message }) {
  return <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">{message}</div>;
}
