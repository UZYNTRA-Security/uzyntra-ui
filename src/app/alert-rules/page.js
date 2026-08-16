"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

const initialForm = {
  name: "",
  severityThreshold: "high",
  scoreThreshold: 65,
  confidenceThreshold: "",
  detectorIds: "",
  attackTypes: "",
  actions: "",
  aggregationWindowSeconds: 300,
  thresholdCount: 1,
  cooldownSeconds: 300,
};

export default function AlertRulesPage() {
  const [rows, setRows] = useState([]);
  const [form, setForm] = useState(initialForm);
  const [error, setError] = useState("");

  async function load() {
    try {
      const res = await api.getAlertRules();
      setRows(res.data?.items || []);
    } catch (err) {
      setError(err.message || "Failed to load rules");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const columns = useMemo(
    () => [
      { key: "name", label: "Name" },
      { key: "status", label: "Status" },
      { key: "severityThreshold", label: "Severity" },
      { key: "thresholdCount", label: "Count" },
      { key: "aggregationWindowSeconds", label: "Window" },
      { key: "cooldownSeconds", label: "Cooldown" },
      {
        key: "actions",
        label: "Actions",
        render: (row) => (
          <div className="flex gap-2">
            <button className="btn-secondary" onClick={() => setStatus(row, row.status === "active" ? "disabled" : "active")}>
              {row.status === "active" ? "Disable" : "Enable"}
            </button>
            <button className="btn-secondary" onClick={() => remove(row.id)}>Delete</button>
          </div>
        ),
      },
    ],
    [],
  );

  async function submit(event) {
    event.preventDefault();
    setError("");
    try {
      await api.createAlertRule({
        ...form,
        detectorIds: csv(form.detectorIds),
        attackTypes: csv(form.attackTypes),
        actions: csv(form.actions),
        confidenceThreshold: form.confidenceThreshold === "" ? null : Number(form.confidenceThreshold),
        scoreThreshold: form.scoreThreshold === "" ? null : Number(form.scoreThreshold),
        matchAll: false,
      });
      setForm(initialForm);
      await load();
    } catch (err) {
      setError(err.message || "Failed to save rule");
    }
  }

  async function setStatus(row, status) {
    await api.updateAlertRule(row.id, { ...row, status, matchAll: true });
    await load();
  }

  async function remove(ruleId) {
    await api.deleteAlertRule(ruleId);
    await load();
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Alert Rules" subtitle="Safe threshold, detector, and cooldown controls" actions={<button className="btn-primary" onClick={load}>Refresh</button>} />
      {error ? <div className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">{error}</div> : null}
      <SectionCard title="Create Rule">
        <form onSubmit={submit} className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <Field label="Name" value={form.name} onChange={(e) => set("name", e.target.value)} required />
          <Select label="Severity" value={form.severityThreshold} onChange={(e) => set("severityThreshold", e.target.value)} options={["critical", "high", "medium", "low"]} />
          <Field label="Score" type="number" value={form.scoreThreshold} onChange={(e) => set("scoreThreshold", e.target.value)} />
          <Field label="Confidence" type="number" step="0.01" value={form.confidenceThreshold} onChange={(e) => set("confidenceThreshold", e.target.value)} />
          <Field label="Detector IDs" value={form.detectorIds} onChange={(e) => set("detectorIds", e.target.value)} />
          <Field label="Attack Types" value={form.attackTypes} onChange={(e) => set("attackTypes", e.target.value)} />
          <Field label="Actions" value={form.actions} onChange={(e) => set("actions", e.target.value)} />
          <Field label="Window Seconds" type="number" value={form.aggregationWindowSeconds} onChange={(e) => set("aggregationWindowSeconds", Number(e.target.value))} />
          <Field label="Threshold Count" type="number" value={form.thresholdCount} onChange={(e) => set("thresholdCount", Number(e.target.value))} />
          <Field label="Cooldown Seconds" type="number" value={form.cooldownSeconds} onChange={(e) => set("cooldownSeconds", Number(e.target.value))} />
          <div className="md:col-span-3"><button className="btn-primary" type="submit">Create</button></div>
        </form>
      </SectionCard>
      <SectionCard title="Rules">
        <SimpleTable columns={columns} rows={rows} emptyText="No alert rules found" />
      </SectionCard>
    </div>
  );

  function set(key, value) {
    setForm((current) => ({ ...current, [key]: value }));
  }
}

function csv(value) {
  return String(value || "").split(",").map((item) => item.trim()).filter(Boolean);
}

function Field({ label, ...props }) {
  return <label className="block"><span className="mb-2 block text-sm font-medium text-slate-700">{label}</span><input {...props} className="w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm" /></label>;
}

function Select({ label, options, ...props }) {
  return <label className="block"><span className="mb-2 block text-sm font-medium text-slate-700">{label}</span><select {...props} className="w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm">{options.map((option) => <option key={option} value={option}>{option}</option>)}</select></label>;
}
