"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";
import MetricCard from "@/components/MetricCard";

export default function AutomationRunsPage() {
  const [runs, setRuns] = useState([]);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const res = await api.getAutomationRuns({ limit: 50 });
      setRuns(res.data.items || []);
    } catch (err) {
      setError(err.message || "Failed to load automation runs");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const summary = useMemo(() => ({
    approval: runs.filter((item) => item.status === "approval_required").length,
    completed: runs.filter((item) => item.status === "completed").length,
    failed: runs.filter((item) => item.status === "failed").length,
  }), [runs]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Automation Runs"
        subtitle="Execution history, approval state, idempotency outcomes, and playbook results"
        actions={<button className="btn-primary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
        <MetricCard title="Runs" value={runs.length} hint="Recent automation executions" />
        <MetricCard title="Approval Required" value={summary.approval} hint="Waiting for human review" />
        <MetricCard title="Completed" value={summary.completed} hint="Finished internal actions" />
        <MetricCard title="Failed" value={summary.failed} hint="Needs operator review" />
      </div>
      <SectionCard title="Run History">
        <SimpleTable
          columns={[
            { key: "triggerType", label: "Trigger" },
            { key: "status", label: "Status" },
            { key: "automationLevel", label: "Level" },
            { key: "approvalState", label: "Approval" },
            { key: "resultSummary", label: "Result" },
            { key: "startedAt", label: "Started", render: (row) => formatDate(row.startedAt) },
          ]}
          rows={runs}
          emptyText="No automation runs yet"
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
