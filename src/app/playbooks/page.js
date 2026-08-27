"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";
import MetricCard from "@/components/MetricCard";

export default function PlaybooksPage() {
  const [playbooks, setPlaybooks] = useState([]);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const res = await api.getPlaybooks({ limit: 50 });
      setPlaybooks(res.data.items || []);
    } catch (err) {
      setError(err.message || "Failed to load playbooks");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const summary = useMemo(() => ({
    active: playbooks.filter((item) => item.status === "active").length,
    approval: playbooks.filter((item) => item.requiresApproval).length,
    automatic: playbooks.filter((item) => Number(item.automationLevel) >= 2).length,
  }), [playbooks]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Playbooks"
        subtitle="SOAR response workflows, automation level, approval posture, and trigger scope"
        actions={<button className="btn-primary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
        <MetricCard title="Playbooks" value={playbooks.length} hint="Configured response workflows" />
        <MetricCard title="Active" value={summary.active} hint="Available for trigger evaluation" />
        <MetricCard title="Approval Gated" value={summary.approval} hint="Human review required" />
        <MetricCard title="Automation Level 2+" value={summary.automatic} hint="Eligible for guarded execution" />
      </div>
      <SectionCard title="Response Playbooks">
        <SimpleTable
          columns={[
            { key: "name", label: "Name" },
            { key: "triggerType", label: "Trigger" },
            { key: "automationLevel", label: "Level" },
            { key: "riskLevel", label: "Risk" },
            { key: "requiresApproval", label: "Approval", render: (row) => (row.requiresApproval ? "Required" : "Not required") },
            { key: "status", label: "Status" },
            { key: "updatedAt", label: "Updated", render: (row) => formatDate(row.updatedAt) },
          ]}
          rows={playbooks}
          emptyText="No SOAR playbooks configured"
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
