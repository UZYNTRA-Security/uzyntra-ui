"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";
import {
  HorizontalBarChart,
  SeverityBarChart,
} from "@/components/SecurityOpsCharts";

export default function ThreatAnalyticsPage() {
  const [data, setData] = useState(null);
  const [deliveries, setDeliveries] = useState(null);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const [threatsRes, deliveriesRes] = await Promise.all([
        api.getTopThreats(),
        api.getNotificationDeliveries({ limit: 10 }),
      ]);
      setData(threatsRes.data);
      setDeliveries(deliveriesRes.data);
    } catch (err) {
      setError(err.message || "Failed to load threat analytics");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const attackTypes = useMemo(
    () => (data?.attackCategories || []).map((item) => ({ label: item.attackType, count: item.count })),
    [data],
  );
  const detectors = useMemo(
    () => (data?.topDetectors || []).map((item) => ({ label: item.detectorId, count: item.count })),
    [data],
  );
  const sources = useMemo(
    () => (data?.topSources || []).map((item) => ({ label: item.sourceIp, count: item.count })),
    [data],
  );
  const routes = useMemo(
    () => (data?.topRoutes || []).map((item) => ({ label: item.route, count: item.count })),
    [data],
  );
  const severity = useMemo(
    () => (data?.severityDistribution || []).map((item) => ({ label: item.severity, count: item.count })),
    [data],
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Threat Analytics"
        subtitle="Attack categories, detectors, source patterns, targeted routes, and delivery failure visibility"
        actions={<button className="btn-primary" onClick={load}>Refresh</button>}
      />

      {error ? <ErrorBanner message={error} /> : null}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard title="Attack Categories">
          <HorizontalBarChart data={attackTypes} />
        </SectionCard>
        <SectionCard title="Top Detectors">
          <HorizontalBarChart data={detectors} />
        </SectionCard>
        <SectionCard title="Top Sources">
          <HorizontalBarChart data={sources} />
        </SectionCard>
        <SectionCard title="Targeted Routes">
          <HorizontalBarChart data={routes} />
        </SectionCard>
        <SectionCard title="Severity Distribution">
          <SeverityBarChart data={severity} />
        </SectionCard>
        <SectionCard title="Recent Delivery Failures and Retries">
          <SimpleTable
            columns={[
              { key: "createdAt", label: "Created" },
              { key: "channelName", label: "Channel" },
              { key: "providerType", label: "Provider" },
              { key: "operationalStatus", label: "State" },
              { key: "attemptCount", label: "Attempts" },
              { key: "lastErrorCode", label: "Last Error" },
            ]}
            rows={deliveries?.items || []}
            emptyText="No delivery attempts in this window"
          />
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
