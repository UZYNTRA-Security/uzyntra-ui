"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import MetricCard from "@/components/MetricCard";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

export default function ApprovalWorkflowsPage() {
  const [requests, setRequests] = useState([]);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const res = await api.getPolicyChangeRequests({ limit: 100 });
      setRequests(res.data.items || []);
    } catch (err) {
      setError(err.message || "Failed to load approval workflows");
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader title="Approval Workflows" subtitle="Policy change requests before enforcement promotion or rollback" actions={<button className="btn-primary" onClick={load}>Refresh</button>} />
      {error ? <ErrorBanner message={error} /> : null}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
        <MetricCard title="Requests" value={requests.length} hint="Current approval queue" />
        <MetricCard title="Pending" value={requests.filter((item) => item.status === "requested").length} hint="Awaiting reviewer action" />
        <MetricCard title="Approved" value={requests.filter((item) => item.status === "approved").length} hint="Ready for controlled activation" />
        <MetricCard title="Rejected" value={requests.filter((item) => item.status === "rejected").length} hint="Blocked changes" />
      </div>
      <SectionCard title="Approval Queue">
        <SimpleTable
          columns={[
            { key: "requestedAction", label: "Action" },
            { key: "status", label: "Status" },
            { key: "reason", label: "Reason" },
            { key: "policyVersionId", label: "Version", render: (row) => row.policyVersionId ? row.policyVersionId.slice(0, 8) : "" },
            { key: "expiresAt", label: "Expires", render: (row) => formatDate(row.expiresAt) },
          ]}
          rows={requests}
          emptyText="No policy approval requests"
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
