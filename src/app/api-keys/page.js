"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

export default function ApiKeysPage() {
  const [apiKeys, setApiKeys] = useState([]);
  const [serviceAccounts, setServiceAccounts] = useState([]);
  const [form, setForm] = useState({ name: "", serviceAccountId: "" });
  const [plaintextKey, setPlaintextKey] = useState("");
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const [keys, accounts] = await Promise.all([api.getApiKeys(), api.getServiceAccounts()]);
      setApiKeys(keys.data?.apiKeys || []);
      setServiceAccounts(accounts.data?.serviceAccounts || []);
    } catch (err) {
      setError(err.message || "Failed to load API keys");
    }
  }

  async function create(event) {
    event.preventDefault();
    setPlaintextKey("");
    try {
      const created = await api.createApiKey(form);
      setPlaintextKey(created.data?.plaintextKey || "");
      setForm({ name: "", serviceAccountId: "" });
      await load();
    } catch (err) {
      setError(err.message || "API key creation failed");
    }
  }

  async function rotate(row) {
    setPlaintextKey("");
    const rotated = await api.rotateApiKey(row.id, `${row.name} replacement`);
    setPlaintextKey(rotated.data?.plaintextKey || "");
    await load();
  }

  useEffect(() => {
    load();
  }, []);

  const columns = useMemo(
    () => [
      { key: "name", label: "Name" },
      { key: "keyPrefix", label: "Prefix" },
      { key: "status", label: "Status" },
      { key: "createdAt", label: "Created" },
      { key: "lastUsedAt", label: "Last Used" },
      {
        key: "actions",
        label: "",
        render: (row) => (
          <div className="flex gap-2">
            <button className="btn-secondary" onClick={() => rotate(row)}>Rotate</button>
            <button className="btn-danger" onClick={() => api.revokeApiKey(row.id).then(load)}>Revoke</button>
          </div>
        ),
      },
    ],
    [],
  );

  return (
    <div className="space-y-6">
      <PageHeader title="API Keys" subtitle="One-time machine credentials for service accounts" />
      {error ? <div className="panel-soft rounded-xl p-4 text-sm text-red-700">{error}</div> : null}
      {plaintextKey ? (
        <div className="panel-soft rounded-xl p-4">
          <p className="text-sm font-semibold text-slate-900">Plaintext API key</p>
          <code className="mt-2 block break-all rounded bg-slate-950 p-3 text-xs text-white">
            {plaintextKey}
          </code>
        </div>
      ) : null}
      <SectionCard title="Create API Key">
        <form onSubmit={create} className="grid gap-3 md:grid-cols-[1fr_260px_auto]">
          <input className="input-ui" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Firewall ingestion" />
          <select className="select-ui" value={form.serviceAccountId} onChange={(e) => setForm({ ...form, serviceAccountId: e.target.value })}>
            <option value="">No service account</option>
            {serviceAccounts.map((account) => (
              <option key={account.id} value={account.id}>{account.name}</option>
            ))}
          </select>
          <button className="btn-primary" type="submit">Create</button>
        </form>
      </SectionCard>
      <SectionCard title="Keys">
        <SimpleTable columns={columns} rows={apiKeys} emptyText="No API keys found" />
      </SectionCard>
    </div>
  );
}
