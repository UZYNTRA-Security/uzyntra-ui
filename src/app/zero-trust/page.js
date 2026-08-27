"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import MetricCard from "@/components/MetricCard";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";
import { HorizontalBarChart } from "@/components/SecurityOpsCharts";

export default function ZeroTrustPage() {
  const [policies, setPolicies] = useState(null);
  const [decisions, setDecisions] = useState(null);
  const [bypasses, setBypasses] = useState(null);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const [policyRes, decisionRes, bypassRes] = await Promise.all([
        api.getZeroTrustPolicies({ limit: 50 }),
        api.getPolicyDecisions({ limit: 50 }),
        api.getEmergencyBypasses({ limit: 20 }),
      ]);
      setPolicies(policyRes.data);
      setDecisions(decisionRes.data);
      setBypasses(bypassRes.data);
    } catch (err) {
      setError(err.message || "Failed to load Zero Trust data");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const policyItems = policies?.items || [];
  const decisionItems = decisions?.items || [];
  const activePolicies = policyItems.filter((item) => item.status === "active").length;
  const enforceCount = policyItems.filter((item) => item.mode === "enforce").length;
  const activeBypasses = (bypasses?.items || []).filter((item) => item.status === "active").length;
  const blocked = decisionItems.filter((item) => ["block", "quarantine"].includes(item.decision)).length;
  const chartData = useMemo(() => {
    const counts = decisionItems.reduce((acc, item) => {
      acc[item.decision] = (acc[item.decision] || 0) + 1;
      return acc;
    }, {});
    return Object.entries(counts).map(([label, count]) => ({ label, count }));
  }, [decisionItems]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Zero Trust"
        subtitle="Adaptive decisions across identity, API context, threat intelligence, risk, and policy state"
        actions={<button className="btn-primary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
        <MetricCard title="Active Policies" value={activePolicies} hint="Tenant-scoped policies ready for evaluation" />
        <MetricCard title="Enforce Mode" value={enforceCount} hint="Policies capable of active enforcement" />
        <MetricCard title="Blocked / Quarantined" value={blocked} hint="Recent high-friction decisions" />
        <MetricCard title="Emergency Bypasses" value={activeBypasses} hint="Active break-glass controls" />
      </div>
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard title="Decision Mix">
          <HorizontalBarChart data={chartData} />
        </SectionCard>
        <SectionCard title="Recent Access Decisions">
          <SimpleTable
            columns={[
              { key: "evaluatedAt", label: "Time", render: (row) => formatDate(row.evaluatedAt) },
              { key: "decision", label: "Decision" },
              { key: "mode", label: "Mode" },
              { key: "riskScore", label: "Risk" },
              { key: "decisionReason", label: "Reason" },
            ]}
            rows={decisionItems.slice(0, 10)}
            emptyText="No policy decisions recorded"
          />
        </SectionCard>
        <SectionCard title="Policy State">
          <SimpleTable
            columns={[
              { key: "name", label: "Policy" },
              { key: "status", label: "Status" },
              { key: "mode", label: "Mode" },
              { key: "failBehavior", label: "Fail" },
              { key: "updatedAt", label: "Updated", render: (row) => formatDate(row.updatedAt) },
            ]}
            rows={policyItems.slice(0, 10)}
            emptyText="No Zero Trust policies configured"
          />
        </SectionCard>
        <SectionCard title="Emergency Bypass State">
          <SimpleTable
            columns={[
              { key: "createdAt", label: "Created", render: (row) => formatDate(row.createdAt) },
              { key: "status", label: "Status" },
              { key: "expiresAt", label: "Expires", render: (row) => formatDate(row.expiresAt) },
              { key: "reason", label: "Reason" },
            ]}
            rows={(bypasses?.items || []).slice(0, 10)}
            emptyText="No emergency bypasses"
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
