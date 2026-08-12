"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import { formatTimestamp, severityClasses } from "@/lib/format";
import SectionCard from "@/components/SectionCard";
import Badge from "@/components/Badge";

const DEFAULT_LIMIT = 10;

const defaultFilters = {
  source_ip: "",
  attackType: "",
  actionTaken: "",
  severity: "",
  method: "",
  path_contains: "",
  limit: DEFAULT_LIMIT,
  cursor: "",
  nextCursor: "",
  hasMore: false,
};

export default function EventsPage() {
  const [rows, setRows] = useState([]);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [filters, setFilters] = useState(defaultFilters);

  async function loadEvents(nextFilters = filters) {
    setLoading(true);
    setError("");

    try {
      const response = await api.getSecurityEvents(nextFilters);
      const items = response?.data?.items || [];
      const pageInfo = response?.data?.pageInfo || {};

      setRows(items);
      setFilters((current) => ({
        ...current,
        nextCursor: pageInfo.nextCursor || "",
        hasMore: Boolean(pageInfo.hasMore),
      }));
      setSelected((current) => {
        if (!items.length) return null;
        if (!current) return items[0];
        return items.find((item) => item.id === current.id) || items[0];
      });
    } catch (err) {
      setError(err.message || "Failed to load events");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadEvents(defaultFilters);
  }, []);

  function updateFilter(key, value) {
    setFilters((prev) => ({
      ...prev,
      [key]: value,
    }));
  }

  function applyFilters() {
    const next = {
      ...filters,
      cursor: "",
      nextCursor: "",
      hasMore: false,
    };
    setFilters(next);
    loadEvents(next);
  }

  function resetFilters() {
    setFilters(defaultFilters);
    loadEvents(defaultFilters);
  }

  function nextPage() {
    if (!filters.nextCursor) {
      return;
    }

    const next = {
      ...filters,
      cursor: filters.nextCursor,
      nextCursor: "",
      hasMore: false,
    };
    setFilters(next);
    loadEvents(next);
  }

  const tableRows = useMemo(() => rows || [], [rows]);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-900">Events Explorer</h1>
        <p className="mt-1 text-sm text-slate-500">
          Search, review, and inspect organization security events
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
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          <Field
            label="Source IP"
            value={filters.source_ip}
            onChange={(event) => updateFilter("source_ip", event.target.value)}
            placeholder="203.0.113.10"
          />
          <Field
            label="Attack type"
            value={filters.attackType}
            onChange={(event) => updateFilter("attackType", event.target.value)}
            placeholder="sql_injection"
          />
          <SelectField
            label="Action"
            value={filters.actionTaken}
            onChange={(event) => updateFilter("actionTaken", event.target.value)}
            options={["", "blocked", "allowed", "rate_limited", "challenged"]}
          />
          <SelectField
            label="Severity"
            value={filters.severity}
            onChange={(event) => updateFilter("severity", event.target.value)}
            options={["", "critical", "high", "medium", "low"]}
          />
          <SelectField
            label="Method"
            value={filters.method}
            onChange={(event) => updateFilter("method", event.target.value)}
            options={["", "GET", "POST", "PUT", "PATCH", "DELETE"]}
          />
          <Field
            label="Path contains"
            value={filters.path_contains}
            onChange={(event) => updateFilter("path_contains", event.target.value)}
            placeholder="/api/orders"
          />
          <SelectField
            label="Page size"
            value={filters.limit}
            onChange={(event) => updateFilter("limit", Number(event.target.value))}
            options={[10, 20, 50]}
          />
        </div>
      </SectionCard>

      {error ? (
        <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
          {error}
        </div>
      ) : null}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1.3fr_0.9fr]">
        <SectionCard
          title="Results"
          right={
            <div className="text-xs text-slate-500">
              {loading ? "Loading..." : `${tableRows.length} item(s)`}
            </div>
          }
        >
          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-slate-500">
                  <th className="px-3 py-3 font-medium">Time</th>
                  <th className="px-3 py-3 font-medium">Source IP</th>
                  <th className="px-3 py-3 font-medium">Method</th>
                  <th className="px-3 py-3 font-medium">Path</th>
                  <th className="px-3 py-3 font-medium">Attack</th>
                  <th className="px-3 py-3 font-medium">Severity</th>
                  <th className="px-3 py-3 font-medium">Action</th>
                </tr>
              </thead>
              <tbody>
                {tableRows.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-3 py-8 text-center text-slate-500">
                      No events found
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
                        <td className="px-3 py-3">{formatTimestamp(row.occurredAt)}</td>
                        <td className="px-3 py-3">{row.sourceIp || "-"}</td>
                        <td className="px-3 py-3">{row.httpMethod || "-"}</td>
                        <td className="px-3 py-3">{row.requestPath || "-"}</td>
                        <td className="px-3 py-3">{row.attackType || "-"}</td>
                        <td className="px-3 py-3">
                          {row.severity ? (
                            <Badge className={severityClasses(row.severity)}>
                              {row.severity}
                            </Badge>
                          ) : (
                            "-"
                          )}
                        </td>
                        <td className="px-3 py-3">{row.actionTaken || "-"}</td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          <div className="mt-4 flex items-center justify-between">
            <p className="text-xs text-slate-500">Limit: {filters.limit}</p>

            <button
              onClick={nextPage}
              disabled={loading || !filters.hasMore}
              className="rounded-xl border border-slate-200 px-3 py-2 text-sm text-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </SectionCard>

        <SectionCard title="Event Details">
          {!selected ? (
            <div className="text-sm text-slate-500">Select an event to inspect details.</div>
          ) : (
            <div className="space-y-5">
              <DetailItem label="Event ID" value={selected.id} />
              <DetailItem label="Request ID" value={selected.requestId} />
              <DetailItem label="Timestamp" value={formatTimestamp(selected.occurredAt)} />
              <DetailItem label="Source IP" value={selected.sourceIp} />
              <DetailItem label="Method" value={selected.httpMethod} />
              <DetailItem label="Path" value={selected.requestPath} />
              <DetailItem label="Attack Type" value={selected.attackType} />
              <DetailItem label="Action" value={selected.actionTaken} />
              <DetailItem
                label="Confidence"
                value={
                  selected.confidence == null
                    ? "-"
                    : Number(selected.confidence).toFixed(2)
                }
              />

              <div>
                <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Metadata
                </p>
                <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                  <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-words text-xs text-slate-700">
                    {JSON.stringify(selected.rawMetadata || {}, null, 2)}
                  </pre>
                </div>
              </div>

              <div>
                <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Delivery
                </p>
                <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                  <p className="text-sm text-slate-800">
                    Received: {formatTimestamp(selected.receivedAt)}
                  </p>
                </div>
              </div>
            </div>
          )}
        </SectionCard>
      </div>
    </div>
  );
}

function Field({ label, ...props }) {
  return (
    <label className="block">
      <span className="mb-2 block text-sm font-medium text-slate-700">{label}</span>
      <input
        {...props}
        className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none ring-0 placeholder:text-slate-400 focus:border-slate-400"
      />
    </label>
  );
}

function SelectField({ label, options, value, onChange }) {
  return (
    <label className="block">
      <span className="mb-2 block text-sm font-medium text-slate-700">{label}</span>
      <select
        value={value}
        onChange={onChange}
        className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:border-slate-400"
      >
        {options.map((option) => (
          <option key={String(option)} value={option}>
            {option === "" ? "Any" : option}
          </option>
        ))}
      </select>
    </label>
  );
}

function DetailItem({ label, value }) {
  return (
    <div>
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-1 break-all text-sm text-slate-900">{value || "-"}</p>
    </div>
  );
}
