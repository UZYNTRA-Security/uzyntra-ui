"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

export default function FirewallsPage() {
  const [firewalls, setFirewalls] = useState([]);
  const [activeFirewallId, setActiveFirewallId] = useState("");
  const [form, setForm] = useState({ name: "", environment: "production", region: "", hostname: "" });
  const [enrollmentToken, setEnrollmentToken] = useState("");
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const response = await api.getFirewalls();
      setFirewalls(response.data?.firewalls || []);
      setActiveFirewallId(response.data?.activeFirewallInstanceId || "");
    } catch (err) {
      setError(err.message || "Failed to load firewalls");
    }
  }

  async function register(event) {
    event.preventDefault();
    try {
      await api.registerFirewall(form);
      setForm({ name: "", environment: "production", region: "", hostname: "" });
      await load();
    } catch (err) {
      setError(err.message || "Registration failed");
    }
  }

  async function createToken(firewallId) {
    setEnrollmentToken("");
    const response = await api.createEnrollmentToken(firewallId);
    setEnrollmentToken(response.data?.plaintextToken || "");
    await load();
  }

  useEffect(() => {
    load();
  }, []);

  const columns = useMemo(
    () => [
      { key: "name", label: "Name" },
      { key: "environment", label: "Environment" },
      { key: "status", label: "Status" },
      { key: "version", label: "Version" },
      { key: "lastSeenAt", label: "Last Seen" },
      {
        key: "actions",
        label: "",
        render: (row) => (
          <div className="flex flex-wrap gap-2">
            <button className="btn-secondary" onClick={() => api.selectFirewall(row.id).then(load)}>
              Select
            </button>
            <button className="btn-secondary" onClick={() => createToken(row.id)}>
              Enroll
            </button>
            <button className="btn-danger" onClick={() => api.disableFirewall(row.id).then(load)}>
              Disable
            </button>
          </div>
        ),
      },
    ],
    [],
  );

  return (
    <div className="space-y-6">
      <PageHeader title="Firewalls" subtitle="Registered firewall instances and enrollment state" />
      {error ? <div className="panel-soft rounded-xl p-4 text-sm text-red-700">{error}</div> : null}
      {enrollmentToken ? (
        <div className="panel-soft rounded-xl p-4">
          <p className="text-sm font-semibold text-slate-900">Enrollment token</p>
          <code className="mt-2 block break-all rounded bg-slate-950 p-3 text-xs text-white">
            {enrollmentToken}
          </code>
        </div>
      ) : null}
      <SectionCard title="Register Firewall">
        <form onSubmit={register} className="grid gap-3 md:grid-cols-4">
          <input className="input-ui" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Production edge" />
          <input className="input-ui" value={form.environment} onChange={(e) => setForm({ ...form, environment: e.target.value })} placeholder="production" />
          <input className="input-ui" value={form.region} onChange={(e) => setForm({ ...form, region: e.target.value })} placeholder="us-east" />
          <button className="btn-primary" type="submit">Register</button>
        </form>
      </SectionCard>
      <SectionCard title={`Instances${activeFirewallId ? ` | Active: ${activeFirewallId}` : ""}`}>
        <SimpleTable columns={columns} rows={firewalls} emptyText="No firewalls registered" />
      </SectionCard>
    </div>
  );
}
