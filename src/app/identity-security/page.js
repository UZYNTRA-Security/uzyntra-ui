"use client";

import { useEffect, useMemo, useState } from "react";
import Badge from "@/components/Badge";
import MetricCard from "@/components/MetricCard";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";
import { api } from "@/lib/api";
import { formatTimestamp, severityClasses } from "@/lib/format";

export default function IdentitySecurityPage() {
  const [data, setData] = useState(null);
  const [reviewName, setReviewName] = useState("Quarterly access review");
  const [reviewType, setReviewType] = useState("periodic");
  const [reportType, setReportType] = useState("user_inventory");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      const response = await api.getIdentitySecurityDashboard();
      setData(response.data);
    } catch (err) {
      setError(err.message || "Failed to load identity security");
    } finally {
      setLoading(false);
    }
  }

  async function createReview(event) {
    event.preventDefault();
    setSaving(true);
    setSaved("");
    setError("");
    try {
      await api.createIdentityAccessReview({
        name: reviewName,
        reviewType,
        status: "open",
        scope: { source: "identity-security-dashboard" },
      });
      setSaved("Access review created");
      await load();
    } catch (err) {
      setError(err.message || "Access review creation failed");
    } finally {
      setSaving(false);
    }
  }

  async function generateReport(event) {
    event.preventDefault();
    setSaving(true);
    setSaved("");
    setError("");
    try {
      await api.createIdentityComplianceReport({ reportType });
      setSaved("Identity compliance report generated");
      await load();
    } catch (err) {
      setError(err.message || "Identity report generation failed");
    } finally {
      setSaving(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  const executive = data?.executive || {};
  const activity = data?.authenticationActivity || {};
  const riskColumns = useMemo(
    () => [
      { key: "subjectType", label: "Subject" },
      { key: "score", label: "Score" },
      {
        key: "severity",
        label: "Severity",
        render: (row) => <Badge className={severityClasses(row.severity)}>{row.severity}</Badge>,
      },
      { key: "recommendedAction", label: "Action" },
      { key: "updatedAt", label: "Updated", render: (row) => formatTimestamp(row.updatedAt) },
    ],
    [],
  );
  const reviewColumns = useMemo(
    () => [
      { key: "name", label: "Review" },
      { key: "reviewType", label: "Type" },
      { key: "status", label: "Status" },
      { key: "dueAt", label: "Due", render: (row) => row.dueAt ? formatTimestamp(row.dueAt) : "-" },
    ],
    [],
  );
  const eventColumns = useMemo(
    () => [
      { key: "createdAt", label: "Time", render: (row) => formatTimestamp(row.createdAt) },
      { key: "eventType", label: "Event" },
      {
        key: "severity",
        label: "Severity",
        render: (row) => <Badge className={severityClasses(row.severity)}>{row.severity}</Badge>,
      },
      { key: "riskScore", label: "Risk" },
      { key: "action", label: "Action" },
    ],
    [],
  );
  const reportColumns = useMemo(
    () => [
      { key: "reportType", label: "Report" },
      { key: "status", label: "Status" },
      { key: "generatedAt", label: "Generated", render: (row) => formatTimestamp(row.generatedAt) },
    ],
    [],
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Identity Security"
        subtitle="Authentication risk, access governance, and identity compliance operations"
        actions={<button className="btn-primary" onClick={load}>Refresh</button>}
      />

      {error ? <div className="panel-soft rounded-xl p-4 text-sm text-red-700">{error}</div> : null}
      {saved ? <div className="panel-soft rounded-xl p-4 text-sm text-emerald-700">{saved}</div> : null}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-6">
        <MetricCard title="Identity Score" value={loading ? "..." : `${executive.identitySecurityScore ?? 100}%`} hint="Risk-adjusted identity posture" />
        <MetricCard title="Risky Identities" value={loading ? "..." : executive.riskyIdentities ?? 0} hint="Active identity risk records" />
        <MetricCard title="Open Reviews" value={loading ? "..." : executive.openAccessReviews ?? 0} hint="Access reviews requiring action" />
        <MetricCard title="MFA Adoption" value={loading ? "..." : `${executive.mfaAdoptionRate ?? 100}%`} hint="Active users with MFA methods" />
        <MetricCard title="SSO Failures" value={loading ? "..." : `${executive.ssoFailureRate ?? 0}%`} hint="Enterprise SSO failure rate" />
        <MetricCard title="SCIM Failures" value={loading ? "..." : `${executive.scimFailureRate ?? 0}%`} hint="Provisioning failure rate" />
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <SectionCard title="Authentication Activity">
          <div className="grid grid-cols-2 gap-3 text-sm">
            <MiniMetric label="Successful logins" value={activity.successfulLogins} />
            <MiniMetric label="Failed logins" value={activity.failedLogins} />
            <MiniMetric label="MFA failures" value={activity.mfaFailures} />
            <MiniMetric label="OAuth failures" value={activity.oauthFailures} />
            <MiniMetric label="SSO failures" value={activity.ssoFailures} />
            <MiniMetric label="SCIM failures" value={activity.scimFailures} />
          </div>
        </SectionCard>

        <SectionCard title="Provider Health">
          <div className="space-y-3 text-sm text-slate-600">
            <HealthRow label="MFA adoption" value={`${data?.mfaAdoption?.adoptionRate ?? 100}%`} />
            <HealthRow label="SSO active providers" value={data?.ssoHealth?.activeProviders ?? 0} />
            <HealthRow label="SCIM active providers" value={data?.scimHealth?.activeProviders ?? 0} />
            <HealthRow label="Running SCIM syncs" value={data?.scimHealth?.running ?? 0} />
          </div>
        </SectionCard>

        <SectionCard title="Create Access Review">
          <form onSubmit={createReview} className="space-y-3">
            <input className="input-ui" value={reviewName} onChange={(event) => setReviewName(event.target.value)} />
            <select className="select-ui" value={reviewType} onChange={(event) => setReviewType(event.target.value)}>
              <option value="periodic">periodic</option>
              <option value="privileged">privileged</option>
              <option value="inactive_accounts">inactive_accounts</option>
              <option value="orphaned_identities">orphaned_identities</option>
            </select>
            <button className="btn-primary" disabled={saving} type="submit">Create Review</button>
          </form>
        </SectionCard>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard title="Risky Identities">
          <SimpleTable columns={riskColumns} rows={data?.riskyIdentities || []} emptyText="No active identity risks" />
        </SectionCard>

        <SectionCard title="Access Reviews">
          <SimpleTable columns={reviewColumns} rows={data?.accessReviews || []} emptyText="No access reviews" />
        </SectionCard>
      </div>

      <SectionCard title="Compliance Reports">
        <form onSubmit={generateReport} className="mb-4 flex flex-col gap-3 md:flex-row">
          <select className="select-ui" value={reportType} onChange={(event) => setReportType(event.target.value)}>
            <option value="user_inventory">user_inventory</option>
            <option value="mfa_status">mfa_status</option>
            <option value="privileged_access">privileged_access</option>
            <option value="sso_configuration">sso_configuration</option>
            <option value="provisioning_history">provisioning_history</option>
          </select>
          <button className="btn-secondary" disabled={saving} type="submit">Generate Report</button>
        </form>
        <SimpleTable columns={reportColumns} rows={data?.complianceReports || []} emptyText="No identity reports generated" />
      </SectionCard>

      <SectionCard title="Recent Identity Security Events">
        <SimpleTable columns={eventColumns} rows={data?.recentEvents || []} emptyText="No identity security events" />
      </SectionCard>
    </div>
  );
}

function MiniMetric({ label, value }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-3">
      <p className="text-xs text-slate-500">{label}</p>
      <p className="mt-1 text-2xl font-semibold text-slate-950">{value ?? 0}</p>
    </div>
  );
}

function HealthRow({ label, value }) {
  return (
    <div className="flex items-center justify-between rounded-xl border border-slate-200 bg-white px-3 py-2">
      <span>{label}</span>
      <span className="font-semibold text-slate-950">{value}</span>
    </div>
  );
}
