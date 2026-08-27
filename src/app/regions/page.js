"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

const DEFAULT_FORM = {
  regionKey: "",
  name: "",
  geography: "",
  provider: "multi_provider",
  status: "planned",
  dataResidencyClass: "standard",
  primaryControlPlane: false,
  failoverAllowed: false,
};

export default function RegionsPage() {
  const [rows, setRows] = useState([]);
  const [form, setForm] = useState(DEFAULT_FORM);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function load() {
    setError("");
    try {
      const response = await api.getPlatformRegions({ limit: 100 });
      setRows(response.data?.items || []);
    } catch (err) {
      setError(err.message || "Failed to load regions");
    }
  }

  async function create(event) {
    event.preventDefault();
    setError("");
    setMessage("");
    try {
      await api.createPlatformRegion(form);
      setMessage("Region saved");
      setForm(DEFAULT_FORM);
      await load();
    } catch (err) {
      setError(err.message || "Failed to save region");
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Regions"
        subtitle="Data residency, failover eligibility, regional services, and tenant placement controls"
        actions={<button className="btn-secondary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      {message ? <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-700">{message}</div> : null}

      <SectionCard title="Create Region">
        <form className="grid grid-cols-1 gap-4 md:grid-cols-6" onSubmit={create}>
          <input className="input-ui" placeholder="region-key" value={form.regionKey} onChange={(e) => set("regionKey", e.target.value)} />
          <input className="input-ui md:col-span-2" placeholder="Region name" value={form.name} onChange={(e) => set("name", e.target.value)} />
          <input className="input-ui" placeholder="Geography" value={form.geography} onChange={(e) => set("geography", e.target.value)} />
          <select className="select-ui" value={form.status} onChange={(e) => set("status", e.target.value)}>
            <option value="planned">Planned</option>
            <option value="active">Active</option>
            <option value="degraded">Degraded</option>
            <option value="maintenance">Maintenance</option>
          </select>
          <input className="input-ui" placeholder="Residency class" value={form.dataResidencyClass} onChange={(e) => set("dataResidencyClass", e.target.value)} />
          <label className="flex items-center gap-2 text-sm text-slate-700">
            <input type="checkbox" checked={form.primaryControlPlane} onChange={(e) => set("primaryControlPlane", e.target.checked)} />
            Primary
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-700">
            <input type="checkbox" checked={form.failoverAllowed} onChange={(e) => set("failoverAllowed", e.target.checked)} />
            Failover
          </label>
          <button className="btn-primary md:col-span-4" type="submit">Save Region</button>
        </form>
      </SectionCard>

      <SectionCard title="Region Map">
        <SimpleTable
          columns={[
            { key: "regionKey", label: "Key" },
            { key: "name", label: "Name" },
            { key: "geography", label: "Geography" },
            { key: "status", label: "Status" },
            { key: "dataResidencyClass", label: "Residency" },
            { key: "tenantAssignment", label: "Tenant Scope", render: (row) => row.tenantAssignment?.assignmentType || "unassigned" },
          ]}
          rows={rows}
          emptyText="No platform regions configured"
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
