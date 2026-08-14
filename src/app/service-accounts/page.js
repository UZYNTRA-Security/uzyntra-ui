"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

export default function ServiceAccountsPage() {
  const [serviceAccounts, setServiceAccounts] = useState([]);
  const [roles, setRoles] = useState([]);
  const [name, setName] = useState("");
  const [roleId, setRoleId] = useState("");
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const [accounts, rolesRes] = await Promise.all([api.getServiceAccounts(), api.getRoles()]);
      setServiceAccounts(accounts.data?.serviceAccounts || []);
      setRoles(rolesRes.data?.roles || []);
    } catch (err) {
      setError(err.message || "Failed to load service accounts");
    }
  }

  async function create(event) {
    event.preventDefault();
    try {
      await api.createServiceAccount({ name, roleId: roleId || null });
      setName("");
      setRoleId("");
      await load();
    } catch (err) {
      setError(err.message || "Service account creation failed");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const columns = useMemo(
    () => [
      { key: "name", label: "Name" },
      { key: "status", label: "Status" },
      { key: "roleName", label: "Role" },
      { key: "createdAt", label: "Created" },
      {
        key: "actions",
        label: "",
        render: (row) => (
          <div className="flex gap-2">
            <button className="btn-secondary" onClick={() => api.updateServiceAccountStatus(row.id, "active").then(load)}>
              Reactivate
            </button>
            <button className="btn-danger" onClick={() => api.updateServiceAccountStatus(row.id, "disabled").then(load)}>
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
      <PageHeader title="Service Accounts" subtitle="Organization-scoped machine identities" />
      {error ? <div className="panel-soft rounded-xl p-4 text-sm text-red-700">{error}</div> : null}
      <SectionCard title="Create Service Account">
        <form onSubmit={create} className="grid gap-3 md:grid-cols-[1fr_220px_auto]">
          <input className="input-ui" value={name} onChange={(e) => setName(e.target.value)} placeholder="telemetry-ingestor" />
          <select className="select-ui" value={roleId} onChange={(e) => setRoleId(e.target.value)}>
            <option value="">No role</option>
            {roles.map((role) => (
              <option key={role.id} value={role.id}>{role.name}</option>
            ))}
          </select>
          <button className="btn-primary" type="submit">Create</button>
        </form>
      </SectionCard>
      <SectionCard title="Service Accounts">
        <SimpleTable columns={columns} rows={serviceAccounts} emptyText="No service accounts found" />
      </SectionCard>
    </div>
  );
}
