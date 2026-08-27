"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import MetricCard from "@/components/MetricCard";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

export default function EnterprisePage() {
  const [overview, setOverview] = useState(null);
  const [hierarchy, setHierarchy] = useState([]);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const [overviewRes, hierarchyRes] = await Promise.all([
        api.getEnterpriseOverview(),
        api.getOrganizationHierarchy({ limit: 100 }),
      ]);
      setOverview(overviewRes.data);
      setHierarchy(hierarchyRes.data?.items || []);
    } catch (err) {
      setError(err.message || "Failed to load enterprise operations");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const summary = overview?.summary || {};

  return (
    <div className="space-y-6">
      <PageHeader
        title="Enterprise Operations"
        subtitle="MSSP customer hierarchy, governance boundaries, tenant health, and operating scope"
        actions={<button className="btn-primary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3 xl:grid-cols-6">
        <MetricCard title="Customers" value={summary.managedCustomers} hint="Active child tenants" />
        <MetricCard title="Delegations" value={summary.activeDelegations} hint="Current access grants" />
        <MetricCard title="Incidents" value={summary.activeIncidents} hint="Open or investigating" />
        <MetricCard title="Critical Alerts" value={summary.criticalAlerts} hint="Current critical backlog" />
        <MetricCard title="Firewalls" value={summary.activeFirewalls} hint="Active gateway instances" />
        <MetricCard title="Reports" value={summary.complianceReports} hint="Compliance foundations" />
      </div>

      <SectionCard title="Governance State">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <Signal label="Delegated Approval" value={overview?.governance?.delegatedAccessRequiresApproval ? "Required" : "Optional"} />
          <Signal label="Hidden Global Access" value={overview?.governance?.hiddenGlobalAccessAllowed ? "Allowed" : "Blocked"} />
          <Signal label="AI Execution" value={overview?.governance?.aiExecutionAllowed ? "Allowed" : "Advisory Only"} />
        </div>
      </SectionCard>

      <SectionCard title="Organization Hierarchy">
        <SimpleTable
          columns={[
            { key: "currentScopeRole", label: "Scope" },
            { key: "relationshipType", label: "Relationship" },
            { key: "status", label: "Status" },
            { key: "parentOrganization", label: "Parent", render: (row) => row.parentOrganization?.name || row.parentOrganizationId },
            { key: "childOrganization", label: "Child", render: (row) => row.childOrganization?.name || row.childOrganizationId },
          ]}
          rows={hierarchy}
          emptyText="No organization hierarchy has been configured"
        />
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
