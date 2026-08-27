"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

const DEFAULT_INDICATOR = {
  indicatorType: "ip",
  value: "",
  category: "scanner",
  reputationScore: "80",
  confidence: "0.8",
  severity: "high",
  tags: "local,curated",
};

export default function ThreatIndicatorsPage() {
  const [data, setData] = useState(null);
  const [form, setForm] = useState(DEFAULT_INDICATOR);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function load() {
    setError("");
    try {
      const res = await api.getThreatIndicators({ limit: 100 });
      setData(res.data);
    } catch (err) {
      setError(err.message || "Failed to load threat indicators");
    }
  }

  async function create(event) {
    event.preventDefault();
    setError("");
    setMessage("");
    try {
      await api.createThreatIndicator({
        ...form,
        reputationScore: Number(form.reputationScore),
        confidence: Number(form.confidence),
        tags: form.tags.split(",").map((tag) => tag.trim()).filter(Boolean),
      });
      setMessage("Indicator saved");
      setForm(DEFAULT_INDICATOR);
      await load();
    } catch (err) {
      setError(err.message || "Failed to save indicator");
    }
  }

  async function review(indicatorId, reviewStatus) {
    setError("");
    setMessage("");
    try {
      await api.reviewThreatIndicator({ indicatorId, reviewStatus });
      setMessage(`Indicator marked ${reviewStatus}`);
      await load();
    } catch (err) {
      setError(err.message || "Failed to review indicator");
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Threat Indicators"
        subtitle="Curated indicators, analyst review, false-positive controls, and reputation inputs"
        actions={<button className="btn-secondary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      {message ? <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-700">{message}</div> : null}

      <SectionCard title="Add Local Indicator">
        <form className="grid grid-cols-1 gap-4 md:grid-cols-4" onSubmit={create}>
          <label className="space-y-2">
            <span className="text-sm font-medium text-slate-600">Type</span>
            <select className="select-ui" value={form.indicatorType} onChange={(e) => setForm({ ...form, indicatorType: e.target.value })}>
              <option value="ip">IP</option>
              <option value="cidr">CIDR</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
              <option value="hash">Hash</option>
              <option value="asn">ASN</option>
              <option value="user_agent">User Agent</option>
            </select>
          </label>
          <label className="space-y-2 md:col-span-2">
            <span className="text-sm font-medium text-slate-600">Value</span>
            <input className="input-ui" value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} />
          </label>
          <label className="space-y-2">
            <span className="text-sm font-medium text-slate-600">Category</span>
            <input className="input-ui" value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })} />
          </label>
          <label className="space-y-2">
            <span className="text-sm font-medium text-slate-600">Score</span>
            <input className="input-ui" value={form.reputationScore} onChange={(e) => setForm({ ...form, reputationScore: e.target.value })} />
          </label>
          <label className="space-y-2">
            <span className="text-sm font-medium text-slate-600">Confidence</span>
            <input className="input-ui" value={form.confidence} onChange={(e) => setForm({ ...form, confidence: e.target.value })} />
          </label>
          <label className="space-y-2">
            <span className="text-sm font-medium text-slate-600">Severity</span>
            <select className="select-ui" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </label>
          <label className="space-y-2">
            <span className="text-sm font-medium text-slate-600">Tags</span>
            <input className="input-ui" value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} />
          </label>
          <button className="btn-primary md:col-span-4" type="submit">Save Indicator</button>
        </form>
      </SectionCard>

      <SectionCard title="Indicator Review">
        <SimpleTable
          columns={[
            { key: "indicatorType", label: "Type" },
            { key: "indicatorValueDisplay", label: "Indicator" },
            { key: "category", label: "Category" },
            { key: "reputationScore", label: "Score" },
            { key: "confidence", label: "Confidence", render: (row) => `${Math.round(Number(row.confidence || 0) * 100)}%` },
            { key: "reviewStatus", label: "Review" },
            {
              key: "actions",
              label: "Actions",
              render: (row) => (
                <div className="flex gap-2">
                  <button className="btn-secondary py-1 text-xs" onClick={() => review(row.id, "confirmed")}>Confirm</button>
                  <button className="btn-secondary py-1 text-xs" onClick={() => review(row.id, "trusted")}>Trust</button>
                  <button className="btn-danger py-1 text-xs" onClick={() => review(row.id, "false_positive")}>False Positive</button>
                </div>
              ),
            },
          ]}
          rows={data?.items || []}
          emptyText="No indicators have been added yet"
        />
      </SectionCard>
    </div>
  );
}

function ErrorBanner({ message }) {
  return <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">{message}</div>;
}
