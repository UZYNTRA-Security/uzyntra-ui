"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

const DEFAULT_FORM = {
  detectorId: "behavior.endpoint_discovery",
  status: "active",
  confidenceThreshold: "0.65",
  severityOverride: "",
};

export default function DetectionRulesPage() {
  const [data, setData] = useState(null);
  const [form, setForm] = useState(DEFAULT_FORM);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function load() {
    setError("");
    try {
      const res = await api.getDetectionRules();
      setData(res.data);
    } catch (err) {
      setError(err.message || "Failed to load detector rules");
    }
  }

  async function save(event) {
    event.preventDefault();
    setError("");
    setMessage("");
    try {
      await api.saveDetectionRule({
        detectorId: form.detectorId,
        status: form.status,
        confidenceThreshold: Number(form.confidenceThreshold),
        severityOverride: form.severityOverride || null,
        tuning: { source: "phase_8_2_ui" },
      });
      setMessage("Detector configuration saved");
      await load();
    } catch (err) {
      setError(err.message || "Failed to save detector rule");
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Detection Rules"
        subtitle="Detector lifecycle, confidence thresholds, tuning, and suppression guardrails"
        actions={<button className="btn-secondary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      {message ? <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-700">{message}</div> : null}

      <SectionCard title="Detector Configuration">
        <form className="grid grid-cols-1 gap-4 md:grid-cols-4" onSubmit={save}>
          <label className="space-y-2">
            <span className="text-sm font-medium text-slate-600">Detector ID</span>
            <input className="input-ui" value={form.detectorId} onChange={(e) => setForm({ ...form, detectorId: e.target.value })} />
          </label>
          <label className="space-y-2">
            <span className="text-sm font-medium text-slate-600">Status</span>
            <select className="select-ui" value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value })}>
              <option value="active">Active</option>
              <option value="observe">Observe</option>
              <option value="disabled">Disabled</option>
            </select>
          </label>
          <label className="space-y-2">
            <span className="text-sm font-medium text-slate-600">Confidence</span>
            <input className="input-ui" value={form.confidenceThreshold} onChange={(e) => setForm({ ...form, confidenceThreshold: e.target.value })} />
          </label>
          <label className="space-y-2">
            <span className="text-sm font-medium text-slate-600">Severity Override</span>
            <select className="select-ui" value={form.severityOverride} onChange={(e) => setForm({ ...form, severityOverride: e.target.value })}>
              <option value="">None</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </label>
          <button className="btn-primary md:col-span-4" type="submit">Save Detector Rule</button>
        </form>
      </SectionCard>

      <SectionCard title="Configured Detectors">
        <SimpleTable
          columns={[
            { key: "detectorId", label: "Detector" },
            { key: "status", label: "Status" },
            { key: "confidenceThreshold", label: "Threshold" },
            { key: "severityOverride", label: "Override" },
            { key: "updatedAt", label: "Updated", render: (row) => formatDate(row.updatedAt) },
          ]}
          rows={data?.items || []}
          emptyText="No detector-specific tuning has been configured"
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
