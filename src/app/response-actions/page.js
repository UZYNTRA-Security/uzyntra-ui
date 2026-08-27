"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";
import MetricCard from "@/components/MetricCard";

export default function ResponseActionsPage() {
  const [actions, setActions] = useState([]);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const res = await api.getResponseActions({ limit: 50 });
      setActions(res.data.items || []);
    } catch (err) {
      setError(err.message || "Failed to load response actions");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const summary = useMemo(() => ({
    recommended: actions.filter((item) => item.status === "recommended").length,
    approval: actions.filter((item) => item.status === "approval_required").length,
    completed: actions.filter((item) => item.status === "completed").length,
  }), [actions]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Response Actions"
        subtitle="Recommended, approval-gated, and internally completed SOAR actions"
        actions={<button className="btn-primary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
        <MetricCard title="Actions" value={actions.length} hint="Recent response decisions" />
        <MetricCard title="Recommended" value={summary.recommended} hint="No side effects" />
        <MetricCard title="Approval Required" value={summary.approval} hint="High-impact or gated" />
        <MetricCard title="Completed" value={summary.completed} hint="Internal safe actions" />
      </div>
      <SectionCard title="Action Queue">
        <SimpleTable
          columns={[
            { key: "actionType", label: "Action" },
            { key: "targetType", label: "Target" },
            { key: "status", label: "Status" },
            { key: "approvalState", label: "Approval" },
            { key: "riskLevel", label: "Risk" },
            { key: "reason", label: "Reason" },
            { key: "createdAt", label: "Created", render: (row) => formatDate(row.createdAt) },
          ]}
          rows={actions}
          emptyText="No response actions yet"
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
