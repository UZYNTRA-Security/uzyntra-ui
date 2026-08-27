"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

const DEFAULT_FORM = {
  customerOrganizationId: "",
  userId: "",
  accessLevel: "analyst",
  status: "pending",
  justification: "",
};

export default function DelegatedAccessPage() {
  const [rows, setRows] = useState([]);
  const [form, setForm] = useState(DEFAULT_FORM);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function load() {
    setError("");
    try {
      const response = await api.getDelegatedAccess({ limit: 100 });
      setRows(response.data?.items || []);
    } catch (err) {
      setError(err.message || "Failed to load delegated access");
    }
  }

  async function create(event) {
    event.preventDefault();
    setError("");
    setMessage("");
    try {
      await api.createDelegatedAccess({
        ...form,
        userId: form.userId || undefined,
      });
      setMessage("Delegated access request recorded");
      setForm(DEFAULT_FORM);
      await load();
    } catch (err) {
      setError(err.message || "Failed to create delegated access");
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Delegated Access"
        subtitle="Scoped MSSP/customer access grants with approval state, expiration, and audit visibility"
        actions={<button className="btn-secondary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      {message ? <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-700">{message}</div> : null}

      <SectionCard title="Request Delegation">
        <form className="grid grid-cols-1 gap-4 md:grid-cols-5" onSubmit={create}>
          <input className="input-ui md:col-span-2" placeholder="Customer organization ID" value={form.customerOrganizationId} onChange={(e) => setForm({ ...form, customerOrganizationId: e.target.value })} />
          <input className="input-ui" placeholder="Optional user ID" value={form.userId} onChange={(e) => setForm({ ...form, userId: e.target.value })} />
          <select className="select-ui" value={form.accessLevel} onChange={(e) => setForm({ ...form, accessLevel: e.target.value })}>
            <option value="viewer">Viewer</option>
            <option value="analyst">Analyst</option>
            <option value="responder">Responder</option>
            <option value="admin">Admin</option>
            <option value="auditor">Auditor</option>
          </select>
          <select className="select-ui" value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value })}>
            <option value="pending">Pending</option>
            <option value="active">Active</option>
            <option value="suspended">Suspended</option>
          </select>
          <input className="input-ui md:col-span-5" placeholder="Justification" value={form.justification} onChange={(e) => setForm({ ...form, justification: e.target.value })} />
          <button className="btn-primary md:col-span-5" type="submit">Save Delegation</button>
        </form>
      </SectionCard>

      <SectionCard title="Access Grants">
        <SimpleTable
          columns={[
            { key: "customerOrganizationId", label: "Customer" },
            { key: "accessLevel", label: "Level" },
            { key: "status", label: "Status" },
            { key: "approvalState", label: "Approval" },
            { key: "expiresAt", label: "Expires", render: (row) => row.expiresAt ? new Date(row.expiresAt).toLocaleString() : "none" },
            { key: "effective", label: "Effective", render: (row) => row.effective ? "yes" : "no" },
          ]}
          rows={rows}
          emptyText="No delegated access grants are configured"
        />
      </SectionCard>
    </div>
  );
}

function ErrorBanner({ message }) {
  return <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">{message}</div>;
}
