"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import MetricCard from "@/components/MetricCard";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";
import { HorizontalBarChart, ProgressBar } from "@/components/SecurityOpsCharts";

export default function SecurityPosturePage() {
  const [posture, setPosture] = useState(null);
  const [notificationHealth, setNotificationHealth] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  async function load() {
    setLoading(true);
    setError("");
    try {
      const [postureRes, notificationRes] = await Promise.all([
        api.getSecurityPosture(),
        api.getNotificationHealth(),
      ]);
      setPosture(postureRes.data);
      setNotificationHealth(notificationRes.data);
    } catch (err) {
      setError(err.message || "Failed to load posture");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  const exposureBars = useMemo(
    () =>
      (posture?.apiExposure?.byStatus || []).map((item) => ({
        label: item.status,
        count: item.count,
      })),
    [posture],
  );
  const detectorRows = posture?.detectorCoverage?.topDetectors || [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Posture"
        subtitle="Tenant API exposure, policy coverage, detector coverage, and response readiness"
        actions={<button className="btn-primary" onClick={load}>Refresh</button>}
      />

      {error ? <ErrorBanner message={error} /> : null}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-5">
        <MetricCard title="Posture Score" value={loading ? "..." : `${posture?.scores?.securityPosture ?? 100}%`} hint="Weighted tenant posture" />
        <MetricCard title="API Exposure" value={loading ? "..." : `${posture?.scores?.apiExposure ?? 100}%`} hint="Known route quality" />
        <MetricCard title="Policy Coverage" value={loading ? "..." : `${posture?.scores?.policyCoverage ?? 100}%`} hint="Known or approved routes" />
        <MetricCard title="Detector Coverage" value={loading ? "..." : `${posture?.scores?.detectorCoverage ?? 0}%`} hint="Observed detector diversity" />
        <MetricCard title="Alert Reliability" value={loading ? "..." : `${notificationHealth?.reliability?.score ?? 100}%`} hint="Notification delivery success" />
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard title="Coverage Scores">
          <div className="space-y-5">
            <ProgressBar label="Security posture" value={posture?.scores?.securityPosture} />
            <ProgressBar label="API exposure" value={posture?.scores?.apiExposure} />
            <ProgressBar label="Policy coverage" value={posture?.scores?.policyCoverage} />
            <ProgressBar label="Detector coverage" value={posture?.scores?.detectorCoverage} />
            <ProgressBar label="Response readiness" value={posture?.scores?.responseReadiness} />
          </div>
        </SectionCard>

        <SectionCard title="API Exposure by Route State">
          <HorizontalBarChart data={exposureBars} />
        </SectionCard>
      </div>

      <SectionCard title="Detector Coverage">
        <SimpleTable
          columns={[
            { key: "detectorId", label: "Detector" },
            { key: "count", label: "Events" },
          ]}
          rows={detectorRows}
          emptyText="No detector activity in the selected window"
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
