"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import MetricCard from "@/components/MetricCard";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

const DEFAULT_FORM = {
  serviceType: "control_plane",
  status: "healthy",
  availabilityPercent: 100,
  latencyP95Ms: 0,
  errorRatePercent: 0,
};

export default function PlatformHealthPage() {
  const [rows, setRows] = useState([]);
  const [rollup, setRollup] = useState({});
  const [form, setForm] = useState(DEFAULT_FORM);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function load() {
    setError("");
    try {
      const response = await api.getPlatformHealth({ limit: 100 });
      setRows(response.data?.items || []);
      setRollup(response.data?.rollup || {});
    } catch (err) {
      setError(err.message || "Failed to load platform health");
    }
  }

  async function record(event) {
    event.preventDefault();
    setError("");
    setMessage("");
    try {
      await api.recordPlatformHealth(form);
      setMessage("Health record saved");
      setForm(DEFAULT_FORM);
      await load();
    } catch (err) {
      setError(err.message || "Failed to save platform health");
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader title="Platform Health" subtitle="Regional service availability, latency, failure state, and recovery signals" actions={<button className="btn-secondary" onClick={load}>Refresh</button>} />
      {error ? <ErrorBanner message={error} /> : null}
      {message ? <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-700">{message}</div> : null}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
        <MetricCard title="Records" value={rollup.total} hint="Recent health samples" />
        <MetricCard title="Healthy" value={rollup.healthy} hint="Non-degraded checks" />
        <MetricCard title="Degraded" value={rollup.degraded} hint="Down or degraded checks" />
        <MetricCard title="Availability" value={`${rollup.averageAvailabilityPercent ?? 100}%`} hint="Average across samples" />
      </div>

      <SectionCard title="Record Health Check">
        <form className="grid grid-cols-1 gap-4 md:grid-cols-6" onSubmit={record}>
          <select className="select-ui" value={form.serviceType} onChange={(e) => set("serviceType", e.target.value)}>
            <option value="control_plane">Control Plane</option>
            <option value="gateway">Gateway</option>
            <option value="database">Database</option>
            <option value="ingestion">Ingestion</option>
            <option value="notification">Notification</option>
            <option value="marketplace">Marketplace</option>
          </select>
          <select className="select-ui" value={form.status} onChange={(e) => set("status", e.target.value)}>
            <option value="healthy">Healthy</option>
            <option value="degraded">Degraded</option>
            <option value="down">Down</option>
            <option value="maintenance">Maintenance</option>
          </select>
          <input className="input-ui" type="number" min="0" max="100" value={form.availabilityPercent} onChange={(e) => set("availabilityPercent", e.target.value)} />
          <input className="input-ui" type="number" min="0" value={form.latencyP95Ms} onChange={(e) => set("latencyP95Ms", e.target.value)} />
          <input className="input-ui" type="number" min="0" max="100" value={form.errorRatePercent} onChange={(e) => set("errorRatePercent", e.target.value)} />
          <button className="btn-primary" type="submit">Record</button>
        </form>
      </SectionCard>

      <SectionCard title="Health Records">
        <SimpleTable
          columns={[
            { key: "serviceType", label: "Service" },
            { key: "status", label: "Status" },
            { key: "availabilityPercent", label: "Availability", render: (row) => `${row.availabilityPercent}%` },
            { key: "latencyP95Ms", label: "P95", render: (row) => `${row.latencyP95Ms} ms` },
            { key: "errorRatePercent", label: "Errors", render: (row) => `${row.errorRatePercent}%` },
            { key: "checkedAt", label: "Checked" },
          ]}
          rows={rows}
          emptyText="No health records found"
        />
      </SectionCard>
    </div>
  );

  function set(key, value) {
    setForm((current) => ({ ...current, [key]: value }));
  }
}

function ErrorBanner({ message }) {
  return <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">{message}</div>;
}
