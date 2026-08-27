"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";
import MetricCard from "@/components/MetricCard";

export default function AiHistoryPage() {
  const [sessions, setSessions] = useState([]);
  const [reports, setReports] = useState([]);
  const [context, setContext] = useState(null);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const [sessionRes, reportRes, contextRes] = await Promise.all([
        api.getAiSessions({ limit: 50 }),
        api.getAiReports({ limit: 20 }),
        api.getAiContext({ limit: 10 }),
      ]);
      setSessions(sessionRes.data.items || []);
      setReports(reportRes.data.items || []);
      setContext(contextRes.data);
    } catch (err) {
      setError(err.message || "Failed to load AI history");
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="AI History"
        subtitle="Tenant-scoped copilot sessions, generated reports, and retrieval context inventory"
        actions={<button className="btn-primary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
        <MetricCard title="Sessions" value={sessions.length} hint="AI conversation records" />
        <MetricCard title="Reports" value={reports.length} hint="Generated summaries" />
        <MetricCard title="Evidence Scope" value={context?.evidenceRefs?.length || 0} hint="Retrieved references" />
        <MetricCard title="Guardrail" value="Enabled" hint="Advisory-only boundary" />
      </div>
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard title="Sessions">
          <SimpleTable
            columns={[
              { key: "title", label: "Title" },
              { key: "status", label: "Status" },
              { key: "purpose", label: "Purpose" },
              { key: "updatedAt", label: "Updated", render: (row) => formatDate(row.updatedAt) },
            ]}
            rows={sessions}
            emptyText="No AI sessions"
          />
        </SectionCard>
        <SectionCard title="Reports">
          <SimpleTable
            columns={[
              { key: "title", label: "Title" },
              { key: "reportType", label: "Type" },
              { key: "provider", label: "Provider" },
              { key: "generatedAt", label: "Generated", render: (row) => formatDate(row.generatedAt) },
            ]}
            rows={reports}
            emptyText="No AI reports"
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
