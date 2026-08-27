"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import MetricCard from "@/components/MetricCard";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

const DEFAULT_FORM = {
  metricType: "security_events",
  quantity: "0",
  source: "manual_validation",
};

export default function UsagePage() {
  const [data, setData] = useState(null);
  const [form, setForm] = useState(DEFAULT_FORM);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function load() {
    setError("");
    try {
      const response = await api.getUsage({ limit: 100 });
      setData(response.data);
    } catch (err) {
      setError(err.message || "Failed to load usage");
    }
  }

  async function create(event) {
    event.preventDefault();
    setError("");
    setMessage("");
    try {
      await api.recordUsage({ ...form, quantity: Number(form.quantity) });
      setMessage("Usage record saved");
      setForm(DEFAULT_FORM);
      await load();
    } catch (err) {
      setError(err.message || "Failed to save usage");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const summary = data?.summary || {};
  const byMetric = Object.entries(summary.byMetric || {}).map(([metricType, quantity]) => ({ metricType, quantity }));

  return (
    <div className="space-y-6">
      <PageHeader
        title="Usage"
        subtitle="Billing foundation metrics and tenant limit signals without payment-provider coupling"
        actions={<button className="btn-secondary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      {message ? <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-700">{message}</div> : null}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <MetricCard title="Total Usage" value={summary.totalQuantity} hint="Sum across current records" />
        <MetricCard title="Metric Types" value={byMetric.length} hint="Tracked billing signals" />
        <MetricCard title="Records" value={data?.items?.length || 0} hint="Current query result" />
      </div>

      <SectionCard title="Record Usage">
        <form className="grid grid-cols-1 gap-4 md:grid-cols-4" onSubmit={create}>
          <select className="select-ui" value={form.metricType} onChange={(e) => setForm({ ...form, metricType: e.target.value })}>
            <option value="api_requests">API Requests</option>
            <option value="security_events">Security Events</option>
            <option value="alerts">Alerts</option>
            <option value="incidents">Incidents</option>
            <option value="firewall_instances">Firewall Instances</option>
            <option value="api_routes">API Routes</option>
            <option value="notification_deliveries">Notification Deliveries</option>
            <option value="ai_investigations">AI Investigations</option>
            <option value="customer_tenants">Customer Tenants</option>
            <option value="analyst_seats">Analyst Seats</option>
          </select>
          <input className="input-ui" placeholder="Quantity" value={form.quantity} onChange={(e) => setForm({ ...form, quantity: e.target.value })} />
          <input className="input-ui md:col-span-2" placeholder="Source" value={form.source} onChange={(e) => setForm({ ...form, source: e.target.value })} />
          <button className="btn-primary md:col-span-4" type="submit">Save Usage</button>
        </form>
      </SectionCard>

      <SectionCard title="Usage By Metric">
        <SimpleTable
          columns={[
            { key: "metricType", label: "Metric" },
            { key: "quantity", label: "Quantity" },
          ]}
          rows={byMetric}
          emptyText="No usage has been recorded"
        />
      </SectionCard>

      <SectionCard title="Usage Records">
        <SimpleTable
          columns={[
            { key: "metricType", label: "Metric" },
            { key: "quantity", label: "Quantity" },
            { key: "source", label: "Source" },
            { key: "periodEnd", label: "Period End", render: (row) => row.periodEnd ? new Date(row.periodEnd).toLocaleDateString() : "" },
          ]}
          rows={data?.items || []}
          emptyText="No usage records are available"
        />
      </SectionCard>
    </div>
  );
}

function ErrorBanner({ message }) {
  return <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">{message}</div>;
}
