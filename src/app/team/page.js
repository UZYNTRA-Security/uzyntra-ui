"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

export default function TeamPage() {
  const [members, setMembers] = useState([]);
  const [invitations, setInvitations] = useState([]);
  const [roles, setRoles] = useState([]);
  const [email, setEmail] = useState("");
  const [roleId, setRoleId] = useState("");
  const [oneTimeToken, setOneTimeToken] = useState("");
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const [memberRes, invitationRes, roleRes] = await Promise.all([
        api.getMembers(),
        api.getInvitations(),
        api.getRoles(),
      ]);
      setMembers(memberRes.data?.members || []);
      setInvitations(invitationRes.data?.invitations || []);
      setRoles(roleRes.data?.roles || []);
    } catch (err) {
      setError(err.message || "Failed to load team");
    }
  }

  async function invite(event) {
    event.preventDefault();
    setError("");
    setOneTimeToken("");
    try {
      const created = await api.createInvitation({ email, roleId: roleId || null });
      setOneTimeToken(created.data?.plaintextToken || "");
      setEmail("");
      await load();
    } catch (err) {
      setError(err.message || "Invitation failed");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const memberColumns = useMemo(
    () => [
      { key: "email", label: "Email" },
      { key: "status", label: "Status" },
      { key: "roleName", label: "Role" },
      {
        key: "actions",
        label: "",
        render: (row) => (
          <div className="flex gap-2">
            <button
              className="btn-secondary"
              onClick={() => api.updateMemberStatus(row.membershipId, "active").then(load)}
            >
              Reactivate
            </button>
            <button
              className="btn-danger"
              onClick={() => api.updateMemberStatus(row.membershipId, "disabled").then(load)}
            >
              Disable
            </button>
          </div>
        ),
      },
    ],
    [],
  );

  const invitationColumns = useMemo(
    () => [
      { key: "email", label: "Email" },
      { key: "status", label: "Status" },
      { key: "expiresAt", label: "Expires" },
      {
        key: "actions",
        label: "",
        render: (row) =>
          row.status === "pending" ? (
            <button className="btn-danger" onClick={() => api.revokeInvitation(row.id).then(load)}>
              Revoke
            </button>
          ) : null,
      },
    ],
    [],
  );

  return (
    <div className="space-y-6">
      <PageHeader title="Team" subtitle="Organization members, invitations, and scoped role assignments" />
      {error ? <div className="panel-soft rounded-xl p-4 text-sm text-red-700">{error}</div> : null}
      {oneTimeToken ? (
        <div className="panel-soft rounded-xl p-4">
          <p className="text-sm font-semibold text-slate-900">Invitation token</p>
          <code className="mt-2 block break-all rounded bg-slate-950 p-3 text-xs text-white">
            {oneTimeToken}
          </code>
        </div>
      ) : null}
      <SectionCard title="Invite Member">
        <form onSubmit={invite} className="grid gap-3 md:grid-cols-[1fr_220px_auto]">
          <input className="input-ui" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="operator@example.com" />
          <select className="select-ui" value={roleId} onChange={(e) => setRoleId(e.target.value)}>
            <option value="">No role</option>
            {roles.map((role) => (
              <option key={role.id} value={role.id}>{role.name}</option>
            ))}
          </select>
          <button className="btn-primary" type="submit">Invite</button>
        </form>
      </SectionCard>
      <SectionCard title="Members">
        <SimpleTable columns={memberColumns} rows={members} emptyText="No members found" />
      </SectionCard>
      <SectionCard title="Invitations">
        <SimpleTable columns={invitationColumns} rows={invitations} emptyText="No invitations found" />
      </SectionCard>
    </div>
  );
}
