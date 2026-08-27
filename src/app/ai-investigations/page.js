"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";
import MetricCard from "@/components/MetricCard";

export default function AiInvestigationsPage() {
  const [analysis, setAnalysis] = useState(null);
  const [evidence, setEvidence] = useState([]);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const [explainRes, evidenceRes] = await Promise.all([
        api.explainSecurityContext({ prompt: "Explain active investigations and response history." }),
        api.getEvidence({ limit: 20 }),
      ]);
      setAnalysis(explainRes.data);
      setEvidence(evidenceRes.data.items || []);
    } catch (err) {
      setError(err.message || "Failed to load AI investigation analysis");
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="AI Investigations"
        subtitle="Evidence-backed investigation summaries, timelines, and recommended analyst steps"
        actions={<button className="btn-primary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
        <MetricCard title="Confidence" value={analysis ? `${Math.round(Number(analysis.confidence || 0) * 100)}%` : "0%"} hint="Context-backed explanation" />
        <MetricCard title="Evidence Refs" value={analysis?.evidenceRefs?.length || 0} hint="Internal records cited" />
        <MetricCard title="Mode" value="Advisory" hint="No direct SOAR execution" />
      </div>
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard title="Investigation Summary">
          <pre className="max-h-[460px] overflow-auto whitespace-pre-wrap rounded-xl bg-slate-950 p-4 text-sm text-slate-50">
            {analysis?.content || "No AI investigation summary yet"}
          </pre>
        </SectionCard>
        <SectionCard title="Evidence Timeline">
          <SimpleTable
            columns={[
              { key: "sourceType", label: "Source" },
              { key: "evidenceType", label: "Type" },
              { key: "evidenceHash", label: "Hash" },
              { key: "occurredAt", label: "Observed", render: (row) => formatDate(row.occurredAt) },
            ]}
            rows={evidence}
            emptyText="No SOAR evidence available"
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
