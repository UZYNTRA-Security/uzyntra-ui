"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import { formatTimestamp } from "@/lib/format";
import SectionCard from "@/components/SectionCard";
import Badge from "@/components/Badge";

const defaultFilters = {
  status: "",
  path_contains: "",
  limit: 50,
};

export default function ApiInventoryPage() {
  const [rows, setRows] = useState([]);
  const [selected, setSelected] = useState(null);
  const [filters, setFilters] = useState(defaultFilters);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function loadInventory(nextFilters = filters) {
    setLoading(true);
    setError("");

    try {
      const response = await api.getApiInventory(nextFilters);
      const items = response?.data?.items || [];
      setRows(items);
      setSelected((current) => {
        if (!items.length) return null;
        if (!current) return items[0];
        return items.find((item) => item.id === current.id) || items[0];
      });
    } catch (err) {
      setError(err.message || "Failed to load API inventory");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadInventory(defaultFilters);
  }, []);

  function updateFilter(key, value) {
    setFilters((prev) => ({ ...prev, [key]: value }));
  }

  function applyFilters() {
    loadInventory(filters);
  }

  function resetFilters() {
    setFilters(defaultFilters);
    loadInventory(defaultFilters);
  }

  const tableRows = useMemo(() => rows || [], [rows]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-900">API Inventory</h1>
        <p className="mt-1 text-sm text-slate-500">
          Learned routes, schema signals, and detector coverage
        </p>
      </div>

      <SectionCard
        title="Filters"
        right={
          <div className="flex gap-2">
            <button
              onClick={resetFilters}
              className="rounded-xl border border-slate-200 px-3 py-2 text-sm text-slate-700 hover:bg-slate-50"
            >
              Reset
            </button>
            <button
              onClick={applyFilters}
              className="rounded-xl bg-slate-900 px-3 py-2 text-sm font-medium text-white hover:bg-slate-700"
            >
              Search
            </button>
          </div>
        }
      >
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <label className="block">
            <span className="mb-2 block text-sm font-medium text-slate-700">Status</span>
            <select
              value={filters.status}
              onChange={(event) => updateFilter("status", event.target.value)}
              className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-slate-400"
            >
              {["", "new", "known", "approved", "deprecated", "unknown"].map((status) => (
                <option key={status || "any"} value={status}>
                  {status || "Any"}
                </option>
              ))}
            </select>
          </label>
          <label className="block md:col-span-2">
            <span className="mb-2 block text-sm font-medium text-slate-700">Route contains</span>
            <input
              value={filters.path_contains}
              onChange={(event) => updateFilter("path_contains", event.target.value)}
              placeholder="/api/orders"
              className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none ring-0 placeholder:text-slate-400 focus:border-slate-400"
            />
          </label>
        </div>
      </SectionCard>

      {error ? (
        <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
          {error}
        </div>
      ) : null}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1.25fr_0.75fr]">
        <SectionCard
          title="Routes"
          right={
            <div className="text-xs text-slate-500">
              {loading ? "Loading..." : `${tableRows.length} route(s)`}
            </div>
          }
        >
          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-slate-500">
                  <th className="px-3 py-3 font-medium">Route</th>
                  <th className="px-3 py-3 font-medium">Methods</th>
                  <th className="px-3 py-3 font-medium">Status</th>
                  <th className="px-3 py-3 font-medium">Requests</th>
                  <th className="px-3 py-3 font-medium">Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {tableRows.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-3 py-8 text-center text-slate-500">
                      No inventory routes found
                    </td>
                  </tr>
                ) : (
                  tableRows.map((row) => {
                    const active = selected?.id === row.id;
                    return (
                      <tr
                        key={row.id}
                        onClick={() => setSelected(row)}
                        className={`cursor-pointer border-b border-slate-100 align-top transition ${
                          active ? "bg-slate-50" : "hover:bg-slate-50/70"
                        }`}
                      >
                        <td className="px-3 py-3 font-medium text-slate-900">
                          {row.routeTemplate}
                        </td>
                        <td className="px-3 py-3">{(row.methods || []).join(", ") || "-"}</td>
                        <td className="px-3 py-3">
                          <StatusBadge status={row.status} />
                        </td>
                        <td className="px-3 py-3">{row.observedRequestCount || 0}</td>
                        <td className="px-3 py-3">{formatTimestamp(row.lastSeenAt)}</td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </SectionCard>

        <SectionCard title="Route Detail">
          {!selected ? (
            <div className="text-sm text-slate-500">Select a route to inspect details.</div>
          ) : (
            <div className="space-y-5">
              <DetailItem label="Route" value={selected.routeTemplate} />
              <DetailItem label="Methods" value={(selected.methods || []).join(", ")} />
              <DetailItem label="Status" value={selected.status} />
              <DetailItem label="First Seen" value={formatTimestamp(selected.firstSeenAt)} />
              <DetailItem label="Last Seen" value={formatTimestamp(selected.lastSeenAt)} />
              <DetailItem
                label="Observed Status Codes"
                value={(selected.observedStatusCodes || []).join(", ")}
              />
              <DetailItem
                label="Content Types"
                value={(selected.contentTypes || []).join(", ")}
              />
              <div>
                <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Schema Summary
                </p>
                <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                  <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words text-xs text-slate-700">
                    {JSON.stringify(selected.learnedSchemaSummary || {}, null, 2)}
                  </pre>
                </div>
              </div>
            </div>
          )}
        </SectionCard>
      </div>
    </div>
  );
}

function StatusBadge({ status }) {
  const classes = {
    new: "bg-amber-50 text-amber-700 ring-amber-200",
    known: "bg-sky-50 text-sky-700 ring-sky-200",
    approved: "bg-emerald-50 text-emerald-700 ring-emerald-200",
    deprecated: "bg-rose-50 text-rose-700 ring-rose-200",
    unknown: "bg-slate-50 text-slate-700 ring-slate-200",
  };

  return <Badge className={classes[status] || classes.unknown}>{status || "unknown"}</Badge>;
}

function DetailItem({ label, value }) {
  return (
    <div>
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-1 break-all text-sm text-slate-900">{value || "-"}</p>
    </div>
  );
}
