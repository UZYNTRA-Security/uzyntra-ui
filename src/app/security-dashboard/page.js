"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import { formatTimestamp, severityClasses } from "@/lib/format";
import Badge from "@/components/Badge";
import MetricCard from "@/components/MetricCard";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";
import {
  AttackTrendChart,
  HorizontalBarChart,
  NotificationHealthChart,
  SeverityBarChart,
  chartLabel,
} from "@/components/SecurityOpsCharts";

export default function SecurityDashboardPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      const response = await api.getSecurityDashboard();
      setData(response.data);
    } catch (err) {
      setError(err.message || "Failed to load security dashboard");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  const trend = useMemo(
    () =>
      (data?.metrics?.security?.timeline || []).map((item) => ({
        ...item,
        label: chartLabel(item.bucket),
      })),
    [data],
  );
  const threats = useMemo(
    () =>
      (data?.topThreats?.attackCategories || []).map((item) => ({
        label: item.attackType || "unknown",
        count: item.count,
      })),
    [data],
  );
  const severity = useMemo(
    () =>
      (data?.metrics?.security?.severityDistribution || []).map((item) => ({
        label: item.severity,
        count: item.count,
      })),
    [data],
  );
  const delivery = useMemo(
    () =>
      (data?.notificationHealth?.byProvider || []).map((item) => ({
        label: item.providerType,
        delivered: item.delivered,
        retrying: item.retrying,
        failed: item.failed,
      })),
    [data],
  );

  const recentColumns = useMemo(
    () => [
      { key: "occurredAt", label: "Time", render: (row) => formatTimestamp(row.occurredAt) },
      { key: "sourceIp", label: "Source" },
      { key: "requestPath", label: "Path" },
      { key: "detectorId", label: "Detector" },
      {
        key: "severity",
        label: "Severity",
        render: (row) => <Badge className={severityClasses(row.severity)}>{row.severity}</Badge>,
      },
      { key: "actionTaken", label: "Action" },
    ],
    [],
  );

  const executive = data?.executive || {};

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Operations"
        subtitle="Executive and analyst view of security posture, detections, incidents, and notification reliability"
        actions={<button className="btn-primary" onClick={load}>Refresh</button>}
      />

      {error ? <ErrorBanner message={error} /> : null}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-5">
        <MetricCard
          title="Security Score"
          value={loading ? "..." : `${executive.overallSecurityScore ?? 100}%`}
          hint="Current posture adjusted for active risk"
        />
        <MetricCard
          title="Active Incidents"
          value={loading ? "..." : executive.activeIncidents}
          hint="Unresolved incident groups"
        />
        <MetricCard
          title="Critical Alerts"
          value={loading ? "..." : executive.criticalAlerts}
          hint="Open critical alert conditions"
        />
        <MetricCard
          title="Blocked Attacks"
          value={loading ? "..." : executive.blockedAttacks}
          hint="Blocked detections in the selected window"
        />
        <MetricCard
          title="Alert Reliability"
          value={loading ? "..." : `${executive.alertReliabilityScore ?? 100}%`}
          hint="Delivered notifications over delivery attempts"
        />
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard title="Attack Trend">
          <AttackTrendChart data={trend} />
        </SectionCard>

        <SectionCard title="Severity Distribution">
          <SeverityBarChart data={severity} />
        </SectionCard>

        <SectionCard title="Top Threat Categories">
          <HorizontalBarChart data={threats} />
        </SectionCard>

        <SectionCard title="Notification Delivery Health">
          <NotificationHealthChart data={delivery} />
        </SectionCard>
      </div>

      <SectionCard title="Recent Security Events">
        <SimpleTable
          columns={recentColumns}
          rows={data?.analyst?.recentEvents || []}
          emptyText="No recent security events"
        />
      </SectionCard>
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
