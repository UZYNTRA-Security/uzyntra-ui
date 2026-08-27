"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";
import MetricCard from "@/components/MetricCard";

export default function InvestigationsPage() {
  const [cases, setCases] = useState([]);
  const [evidence, setEvidence] = useState([]);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const [caseRes, evidenceRes] = await Promise.all([
        api.getInvestigations({ limit: 50 }),
        api.getEvidence({ limit: 20 }),
      ]);
      setCases(caseRes.data.items || []);
      setEvidence(evidenceRes.data.items || []);
    } catch (err) {
      setError(err.message || "Failed to load investigations");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const summary = useMemo(() => ({
    open: cases.filter((item) => item.status === "open").length,
    investigating: cases.filter((item) => item.status === "investigating").length,
    critical: cases.filter((item) => item.severity === "critical").length,
  }), [cases]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Investigations"
        subtitle="Case workflow, incident linkage, SLA state, and sanitized evidence timeline"
        actions={<button className="btn-primary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
        <MetricCard title="Cases" value={cases.length} hint="Investigation records" />
        <MetricCard title="Open" value={summary.open} hint="Awaiting triage" />
        <MetricCard title="Investigating" value={summary.investigating} hint="Active response work" />
        <MetricCard title="Critical" value={summary.critical} hint="Highest severity cases" />
      </div>
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard title="Case Queue">
          <SimpleTable
            columns={[
              { key: "title", label: "Title" },
              { key: "severity", label: "Severity" },
              { key: "status", label: "Status" },
              { key: "lastSeenAt", label: "Last Seen", render: (row) => formatDate(row.lastSeenAt) },
              { key: "slaDueAt", label: "SLA", render: (row) => formatDate(row.slaDueAt) },
            ]}
            rows={cases}
            emptyText="No investigation cases"
          />
        </SectionCard>
        <SectionCard title="Evidence Timeline">
          <SimpleTable
            columns={[
              { key: "sourceType", label: "Source" },
              { key: "evidenceType", label: "Type" },
              { key: "evidenceHash", label: "Hash" },
              { key: "retentionClass", label: "Retention" },
              { key: "occurredAt", label: "Observed", render: (row) => formatDate(row.occurredAt) },
            ]}
            rows={evidence}
            emptyText="No evidence collected"
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
