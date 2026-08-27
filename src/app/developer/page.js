"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

const DEFAULT_FORM = {
  name: "",
  slug: "",
  appType: "api_consumer",
  status: "active",
  rateLimitPerMinute: 60,
};

export default function DeveloperPage() {
  const [rows, setRows] = useState([]);
  const [form, setForm] = useState(DEFAULT_FORM);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function load() {
    setError("");
    try {
      const response = await api.getDeveloperApps({ limit: 100 });
      setRows(response.data?.items || []);
    } catch (err) {
      setError(err.message || "Failed to load developer apps");
    }
  }

  async function create(event) {
    event.preventDefault();
    setError("");
    setMessage("");
    try {
      await api.createDeveloperApp(form);
      setMessage("Developer app saved");
      setForm(DEFAULT_FORM);
      await load();
    } catch (err) {
      setError(err.message || "Failed to save developer app");
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader title="Developer Ecosystem" subtitle="Partner apps, API consumers, webhook apps, and scoped developer access" actions={<button className="btn-secondary" onClick={load}>Refresh</button>} />
      {error ? <ErrorBanner message={error} /> : null}
      {message ? <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-700">{message}</div> : null}

      <SectionCard title="Register Developer App">
        <form className="grid grid-cols-1 gap-4 md:grid-cols-5" onSubmit={create}>
          <input className="input-ui md:col-span-2" placeholder="App name" value={form.name} onChange={(e) => set("name", e.target.value)} />
          <input className="input-ui" placeholder="slug" value={form.slug} onChange={(e) => set("slug", e.target.value)} />
          <select className="select-ui" value={form.appType} onChange={(e) => set("appType", e.target.value)}>
            <option value="api_consumer">API Consumer</option>
            <option value="webhook_app">Webhook App</option>
            <option value="partner_integration">Partner Integration</option>
            <option value="internal_tool">Internal Tool</option>
          </select>
          <input className="input-ui" type="number" min="1" value={form.rateLimitPerMinute} onChange={(e) => set("rateLimitPerMinute", e.target.value)} />
          <button className="btn-primary md:col-span-5" type="submit">Save App</button>
        </form>
      </SectionCard>

      <SectionCard title="Developer Apps">
        <SimpleTable
          columns={[
            { key: "name", label: "Name" },
            { key: "slug", label: "Slug" },
            { key: "appType", label: "Type" },
            { key: "status", label: "Status" },
            { key: "rateLimitPerMinute", label: "Rate Limit" },
          ]}
          rows={rows}
          emptyText="No developer apps registered"
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
