"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

const DEFAULT_FORM = {
  name: "",
  slug: "",
  planKey: "professional",
  lifecycleStatus: "provisioning",
  dataResidency: "global",
};

export default function CustomerTenantsPage() {
  const [rows, setRows] = useState([]);
  const [form, setForm] = useState(DEFAULT_FORM);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function load() {
    setError("");
    try {
      const response = await api.getCustomerTenants({ limit: 100 });
      setRows(response.data?.items || []);
    } catch (err) {
      setError(err.message || "Failed to load customer tenants");
    }
  }

  async function create(event) {
    event.preventDefault();
    setError("");
    setMessage("");
    try {
      await api.createCustomerTenant(form);
      setMessage("Customer tenant created");
      setForm(DEFAULT_FORM);
      await load();
    } catch (err) {
      setError(err.message || "Failed to create customer tenant");
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Customer Tenants"
        subtitle="MSSP and enterprise child-customer management with isolated customer boundaries"
        actions={<button className="btn-secondary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      {message ? <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-700">{message}</div> : null}

      <SectionCard title="Create Customer Tenant">
        <form className="grid grid-cols-1 gap-4 md:grid-cols-5" onSubmit={create}>
          <input className="input-ui md:col-span-2" placeholder="Customer name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <input className="input-ui" placeholder="slug" value={form.slug} onChange={(e) => setForm({ ...form, slug: e.target.value })} />
          <select className="select-ui" value={form.planKey} onChange={(e) => setForm({ ...form, planKey: e.target.value })}>
            <option value="starter">Starter</option>
            <option value="professional">Professional</option>
            <option value="enterprise">Enterprise</option>
            <option value="mssp">MSSP</option>
          </select>
          <select className="select-ui" value={form.lifecycleStatus} onChange={(e) => setForm({ ...form, lifecycleStatus: e.target.value })}>
            <option value="provisioning">Provisioning</option>
            <option value="active">Active</option>
            <option value="suspended">Suspended</option>
          </select>
          <button className="btn-primary md:col-span-5" type="submit">Create Tenant</button>
        </form>
      </SectionCard>

      <SectionCard title="Managed Customers">
        <SimpleTable
          columns={[
            { key: "name", label: "Customer" },
            { key: "slug", label: "Slug" },
            { key: "relationshipType", label: "Relationship" },
            { key: "relationshipStatus", label: "Status" },
            { key: "tenantSettings", label: "Plan", render: (row) => row.tenantSettings?.planKey || "unset" },
            { key: "metrics", label: "Signals", render: (row) => `${row.metrics?.alerts || 0} alerts / ${row.metrics?.incidents || 0} incidents` },
          ]}
          rows={rows}
          emptyText="No customer tenants are assigned"
        />
      </SectionCard>
    </div>
  );
}

function ErrorBanner({ message }) {
  return <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">{message}</div>;
}
