"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";
import MetricCard from "@/components/MetricCard";

export default function AiReportsPage() {
  const [reports, setReports] = useState([]);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const res = await api.getAiReports({ limit: 50 });
      setReports(res.data.items || []);
    } catch (err) {
      setError(err.message || "Failed to load AI reports");
    }
  }

  async function generate() {
    setError("");
    try {
      await api.generateAiReport({ reportType: "analyst", title: "Analyst Security Summary" });
      load();
    } catch (err) {
      setError(err.message || "Failed to generate report");
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="AI Reports"
        subtitle="Generated analyst, executive, compliance, incident, and customer-ready security summaries"
        actions={<button className="btn-primary" onClick={generate}>Generate Analyst Report</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
        <MetricCard title="Reports" value={reports.length} hint="Generated in current scope" />
        <MetricCard title="Evidence Linked" value={reports.filter((report) => report.evidenceRefs?.length).length} hint="Contains internal references" />
        <MetricCard title="Provider" value="Local" hint="No external AI key required" />
      </div>
      <SectionCard title="Report History">
        <SimpleTable
          columns={[
            { key: "title", label: "Title" },
            { key: "reportType", label: "Type" },
            { key: "confidence", label: "Confidence", render: (row) => `${Math.round(Number(row.confidence || 0) * 100)}%` },
            { key: "evidenceRefs", label: "Evidence", render: (row) => row.evidenceRefs?.length || 0 },
            { key: "generatedAt", label: "Generated", render: (row) => formatDate(row.generatedAt) },
          ]}
          rows={reports}
          emptyText="No AI reports generated"
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
