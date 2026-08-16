"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import { formatTimestamp, severityClasses } from "@/lib/format";
import Badge from "@/components/Badge";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

export default function IncidentsPage() {
  const [rows, setRows] = useState([]);
  const [error, setError] = useState("");

  async function load() {
    try {
      const res = await api.getIncidents({ limit: 50 });
      setRows(res.data?.items || []);
    } catch (err) {
      setError(err.message || "Failed to load incidents");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const columns = useMemo(
    () => [
      { key: "title", label: "Incident" },
      { key: "severity", label: "Severity", render: (row) => <Badge className={severityClasses(row.severity)}>{row.severity}</Badge> },
      { key: "status", label: "Status" },
      { key: "assignedToUserId", label: "Assigned" },
      { key: "firstSeenAt", label: "First Seen", render: (row) => formatTimestamp(row.firstSeenAt) },
      { key: "lastSeenAt", label: "Updated", render: (row) => formatTimestamp(row.lastSeenAt) },
      {
        key: "actions",
        label: "Actions",
        render: (row) => (
          <div className="flex gap-2">
            <button className="btn-secondary" onClick={() => update(row.id, { status: "investigating" })}>Investigate</button>
            <button className="btn-secondary" onClick={() => update(row.id, { status: "resolved", resolution: "Resolved from console" })}>Resolve</button>
          </div>
        ),
      },
    ],
    [],
  );

  async function update(id, patch) {
    try {
      await api.updateIncident(id, patch);
      await load();
    } catch (err) {
      setError(err.message || "Incident update failed");
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Incidents" subtitle="Grouped alert investigations and resolution state" actions={<button className="btn-primary" onClick={load}>Refresh</button>} />
      {error ? <div className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">{error}</div> : null}
      <SectionCard title="Incident Queue">
        <SimpleTable columns={columns} rows={rows} emptyText="No incidents found" />
      </SectionCard>
    </div>
  );
}
