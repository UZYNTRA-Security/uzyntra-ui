"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

const empty = { name: "", url: "", signingSecret: "" };

export default function IntegrationsPage() {
  const [rows, setRows] = useState([]);
  const [catalog, setCatalog] = useState([]);
  const [form, setForm] = useState(empty);
  const [error, setError] = useState("");

  async function load() {
    try {
      setError("");
      const [res, catalogRes] = await Promise.all([
        api.getNotificationChannels(),
        api.getIntegrationCatalog({ limit: 100 }),
      ]);
      setRows(res.data?.items || []);
      setCatalog(catalogRes.data?.items || []);
    } catch (err) {
      setError(err.message || "Failed to load integrations");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const columns = useMemo(
    () => [
      { key: "name", label: "Name" },
      { key: "type", label: "Type" },
      { key: "status", label: "Status" },
      { key: "lastSuccessAt", label: "Last Success" },
      { key: "lastFailureAt", label: "Last Failure" },
    ],
    [],
  );

  async function submit(event) {
    event.preventDefault();
    setError("");
    try {
      await api.createNotificationChannel({
        type: "webhook",
        name: form.name,
        url: form.url,
        signingSecret: form.signingSecret || undefined,
        selectedEvents: ["alert.created"],
      });
      setForm(empty);
      await load();
    } catch (err) {
      setError(err.message || "Failed to create channel");
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Integrations" subtitle="Webhook notification channels and prepared email/SIEM foundations" actions={<button className="btn-primary" onClick={load}>Refresh</button>} />
      {error ? <div className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">{error}</div> : null}
      <SectionCard title="Webhook Channel">
        <form onSubmit={submit} className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <Field label="Name" value={form.name} onChange={(e) => set("name", e.target.value)} required />
          <Field label="HTTPS URL" value={form.url} onChange={(e) => set("url", e.target.value)} required />
          <Field label="Signing Secret" type="password" value={form.signingSecret} onChange={(e) => set("signingSecret", e.target.value)} />
          <div className="md:col-span-3"><button className="btn-primary" type="submit">Create</button></div>
        </form>
      </SectionCard>
      <SectionCard title="Channels">
        <SimpleTable columns={columns} rows={rows} emptyText="No notification channels found" />
      </SectionCard>
      <SectionCard title="Integration Catalog">
        <SimpleTable
          columns={[
            { key: "name", label: "Name" },
            { key: "category", label: "Category" },
            { key: "status", label: "Status" },
            { key: "securityReviewStatus", label: "Review" },
            { key: "version", label: "Version" },
          ]}
          rows={catalog}
          emptyText="No integration catalog entries found"
        />
      </SectionCard>
      <SectionCard title="Email and SIEM">
        <div className="text-sm text-slate-600">Prepared. Provider delivery workers are intentionally deferred.</div>
      </SectionCard>
    </div>
  );

  function set(key, value) {
    setForm((current) => ({ ...current, [key]: value }));
  }
}

function Field({ label, ...props }) {
  return <label className="block"><span className="mb-2 block text-sm font-medium text-slate-700">{label}</span><input {...props} className="w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm" /></label>;
}
