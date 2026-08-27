"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import MetricCard from "@/components/MetricCard";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

export default function PolicyHistoryPage() {
  const [policies, setPolicies] = useState([]);
  const [simulations, setSimulations] = useState([]);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const [policyRes, simulationRes] = await Promise.all([
        api.getZeroTrustPolicies({ limit: 100 }),
        api.getPolicySimulations({ limit: 100 }),
      ]);
      setPolicies(policyRes.data.items || []);
      setSimulations(simulationRes.data.items || []);
    } catch (err) {
      setError(err.message || "Failed to load policy history");
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader title="Policy History" subtitle="Policy version, simulation, rollback, and approval evidence" actions={<button className="btn-primary" onClick={load}>Refresh</button>} />
      {error ? <ErrorBanner message={error} /> : null}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
        <MetricCard title="Policies" value={policies.length} hint="Versioned Zero Trust policies" />
        <MetricCard title="Simulations" value={simulations.length} hint="Saved dry-run and replay runs" />
        <MetricCard title="Completed" value={simulations.filter((item) => item.status === "completed").length} hint="Finished simulation records" />
        <MetricCard title="High Impact" value={simulations.reduce((sum, item) => sum + Number(item.impactSummary?.highImpact || 0), 0)} hint="Predicted block/quarantine actions" />
      </div>
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard title="Policy Versions">
          <SimpleTable
            columns={[
              { key: "name", label: "Policy" },
              { key: "mode", label: "Mode" },
              { key: "activeVersionId", label: "Active Version", render: (row) => row.activeVersionId ? row.activeVersionId.slice(0, 8) : "" },
              { key: "updatedAt", label: "Updated", render: (row) => formatDate(row.updatedAt) },
            ]}
            rows={policies}
            emptyText="No policies"
          />
        </SectionCard>
        <SectionCard title="Simulation Evidence">
          <SimpleTable
            columns={[
              { key: "mode", label: "Mode" },
              { key: "status", label: "Status" },
              { key: "summary", label: "Summary" },
              { key: "createdAt", label: "Created", render: (row) => formatDate(row.createdAt) },
            ]}
            rows={simulations}
            emptyText="No simulation evidence"
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
