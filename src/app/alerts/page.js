"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import { formatTimestamp, severityClasses } from "@/lib/format";
import Badge from "@/components/Badge";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

export default function AlertsPage() {
  const [rows, setRows] = useState([]);
  const [filters, setFilters] = useState({ status: "", severity: "", detectorId: "" });
  const [error, setError] = useState("");

  async function load(nextFilters = filters) {
    setError("");
    try {
      const res = await api.getAlerts({ ...nextFilters, limit: 50 });
      setRows(res.data?.items || []);
    } catch (err) {
      setError(err.message || "Failed to load alerts");
    }
  }

  useEffect(() => {
    load(filters);
  }, []);

  const columns = useMemo(
    () => [
      {
        key: "severity",
        label: "Severity",
        render: (row) => <Badge className={severityClasses(row.severity)}>{row.severity}</Badge>,
      },
      { key: "status", label: "Status" },
      { key: "title", label: "Title" },
      { key: "detectorId", label: "Detector" },
      { key: "sourceIp", label: "Source" },
      { key: "route", label: "Route" },
      { key: "eventCount", label: "Events" },
      { key: "firstSeenAt", label: "First Seen", render: (row) => formatTimestamp(row.firstSeenAt) },
      { key: "lastSeenAt", label: "Last Seen", render: (row) => formatTimestamp(row.lastSeenAt) },
      {
        key: "actions",
        label: "Actions",
        render: (row) => (
          <div className="flex gap-2">
            <button className="btn-secondary" onClick={() => act(row.id, "ack")}>
              Ack
            </button>
            <button className="btn-secondary" onClick={() => act(row.id, "resolve")}>
              Resolve
            </button>
          </div>
        ),
      },
    ],
    [],
  );

  async function act(alertId, action) {
    try {
      if (action === "ack") await api.acknowledgeAlert(alertId);
      if (action === "resolve") await api.resolveAlert(alertId, "Resolved from console");
      await load();
    } catch (err) {
      setError(err.message || "Action failed");
    }
  }

  function updateFilter(key, value) {
    setFilters((current) => ({ ...current, [key]: value }));
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Alerts" subtitle="Actionable detections and operational lifecycle" actions={<button className="btn-primary" onClick={() => load()}>Refresh</button>} />
      {error ? <div className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">{error}</div> : null}
      <SectionCard title="Filters" right={<button className="btn-primary" onClick={() => load(filters)}>Apply</button>}>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <Select label="Status" value={filters.status} onChange={(e) => updateFilter("status", e.target.value)} options={["", "open", "acknowledged", "resolved", "suppressed"]} />
          <Select label="Severity" value={filters.severity} onChange={(e) => updateFilter("severity", e.target.value)} options={["", "critical", "high", "medium", "low"]} />
          <Field label="Detector" value={filters.detectorId} onChange={(e) => updateFilter("detectorId", e.target.value)} />
        </div>
      </SectionCard>
      <SectionCard title="Alert Queue">
        <SimpleTable columns={columns} rows={rows} emptyText="No alerts found" />
      </SectionCard>
    </div>
  );
}

function Field({ label, ...props }) {
  return <label className="block"><span className="mb-2 block text-sm font-medium text-slate-700">{label}</span><input {...props} className="w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm" /></label>;
}

function Select({ label, options, ...props }) {
  return <label className="block"><span className="mb-2 block text-sm font-medium text-slate-700">{label}</span><select {...props} className="w-full rounded-xl border border-slate-200 px-3 py-2.5 text-sm">{options.map((option) => <option key={option || "any"} value={option}>{option || "Any"}</option>)}</select></label>;
}
