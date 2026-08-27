"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import MetricCard from "@/components/MetricCard";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

export default function PlatformPage() {
  const [overview, setOverview] = useState(null);
  const [health, setHealth] = useState([]);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const [overviewRes, healthRes] = await Promise.all([
        api.getPlatformOverview(),
        api.getPlatformHealth({ limit: 8 }),
      ]);
      setOverview(overviewRes.data);
      setHealth(healthRes.data?.items || []);
    } catch (err) {
      setError(err.message || "Failed to load platform state");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const summary = overview?.summary || {};
  const rollup = overview?.health || {};

  return (
    <div className="space-y-6">
      <PageHeader
        title="Platform"
        subtitle="Global enterprise scale, region posture, developer ecosystem, and marketplace readiness"
        actions={<button className="btn-primary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3 xl:grid-cols-6">
        <MetricCard title="Active Regions" value={summary.activeRegions} hint="Available operating regions" />
        <MetricCard title="Health Issues" value={summary.degradedHealth} hint="Degraded or down checks" />
        <MetricCard title="Assignments" value={summary.tenantAssignments} hint="Tenant region placements" />
        <MetricCard title="Developer Apps" value={summary.developerApps} hint="Active ecosystem apps" />
        <MetricCard title="Marketplace" value={summary.marketplaceListings} hint="Published listings" />
        <MetricCard title="Backup Failures" value={summary.backupFailures} hint="DR signals requiring review" />
      </div>

      <SectionCard title="Reliability Rollup">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
          <Signal label="Records" value={rollup.total ?? 0} />
          <Signal label="Healthy" value={rollup.healthy ?? 0} />
          <Signal label="Avg Latency P95" value={`${rollup.averageLatencyP95Ms ?? 0} ms`} />
          <Signal label="Availability" value={`${rollup.averageAvailabilityPercent ?? 100}%`} />
        </div>
      </SectionCard>

      <SectionCard title="Recent Platform Health">
        <SimpleTable
          columns={[
            { key: "serviceType", label: "Service" },
            { key: "status", label: "Status" },
            { key: "availabilityPercent", label: "Availability", render: (row) => `${row.availabilityPercent}%` },
            { key: "latencyP95Ms", label: "P95", render: (row) => `${row.latencyP95Ms} ms` },
            { key: "checkedAt", label: "Checked" },
          ]}
          rows={health}
          emptyText="No platform health records have been captured"
        />
      </SectionCard>

      <SectionCard title="Governance Guardrails">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <Signal label="Production DNS" value={overview?.governance?.productionDnsManagedHere ? "Managed" : "Blocked"} />
          <Signal label="Failover Approval" value={overview?.governance?.crossRegionFailoverRequiresApproval ? "Required" : "Optional"} />
          <Signal label="Provider Secrets" value={overview?.governance?.hiddenProviderCredentialsExposed ? "Exposed" : "Hidden"} />
        </div>
      </SectionCard>
    </div>
  );
}

function Signal({ label, value }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-4">
      <p className="text-xs font-medium uppercase tracking-[0.14em] text-slate-500">{label}</p>
      <p className="mt-2 text-lg font-semibold text-slate-950">{value}</p>
    </div>
  );
}

function ErrorBanner({ message }) {
  return <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">{message}</div>;
}
