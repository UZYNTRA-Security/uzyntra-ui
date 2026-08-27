"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import MetricCard from "@/components/MetricCard";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import {
  LineTrendChart,
  NotificationHealthChart,
  chartLabel,
} from "@/components/SecurityOpsCharts";

export default function SecurityTrendsPage() {
  const [data, setData] = useState(null);
  const [health, setHealth] = useState(null);
  const [error, setError] = useState("");
  const [range, setRange] = useState("7");

  async function load(days = range) {
    setError("");
    try {
      const until = new Date();
      const since = new Date(until.getTime() - Number(days) * 24 * 60 * 60 * 1000);
      const params = { since: since.toISOString(), until: until.toISOString(), bucket: Number(days) > 7 ? "day" : "hour" };
      const [trendsRes, healthRes] = await Promise.all([
        api.getSecurityTrends(params),
        api.getNotificationHealth(params),
      ]);
      setData(trendsRes.data);
      setHealth(healthRes.data);
    } catch (err) {
      setError(err.message || "Failed to load security trends");
    }
  }

  useEffect(() => {
    load(range);
  }, [range]);

  const eventTrend = useMemo(
    () =>
      (data?.eventTrend || []).map((item) => ({
        ...item,
        label: chartLabel(item.bucket),
      })),
    [data],
  );
  const incidentTrend = useMemo(
    () =>
      (data?.incidentTrend || []).map((item) => ({
        ...item,
        label: chartLabel(item.bucket),
      })),
    [data],
  );
  const deliveryTrend = useMemo(
    () =>
      (health?.timeline || []).map((item) => ({
        ...item,
        label: chartLabel(item.bucket),
      })),
    [health],
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Trends"
        subtitle="Long-range attack, incident, and notification reliability trends"
        actions={
          <select className="select-ui w-36" value={range} onChange={(event) => setRange(event.target.value)}>
            <option value="7">7 days</option>
            <option value="30">30 days</option>
            <option value="90">90 days</option>
          </select>
        }
      />

      {error ? <ErrorBanner message={error} /> : null}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <MetricCard title="Alert Reliability" value={`${health?.reliability?.score ?? 100}%`} hint="Delivery success across selected range" />
        <MetricCard title="Failed Deliveries" value={health?.totals?.failed ?? 0} hint="Permanent or blocked delivery failures" />
        <MetricCard title="Retrying" value={health?.totals?.retrying ?? 0} hint="Temporary delivery pressure" />
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard title="Blocked and Total Events">
          <LineTrendChart
            data={eventTrend}
            lines={[
              { key: "total", color: "#2563eb" },
              { key: "blocked", color: "#0f766e" },
            ]}
          />
        </SectionCard>
        <SectionCard title="Incident Trend">
          <LineTrendChart
            data={incidentTrend}
            lines={[
              { key: "open", color: "#dc2626" },
              { key: "resolved", color: "#059669" },
            ]}
          />
        </SectionCard>
        <SectionCard title="Notification Reliability">
          <LineTrendChart
            data={deliveryTrend}
            lines={[{ key: "reliabilityScore", color: "#0f766e" }]}
          />
        </SectionCard>
        <SectionCard title="Delivery Composition">
          <NotificationHealthChart data={deliveryTrend} />
        </SectionCard>
      </div>
    </div>
  );
}

function ErrorBanner({ message }) {
  return (
    <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
      {message}
    </div>
  );
}
