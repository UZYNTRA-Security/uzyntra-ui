"use client";

import { useEffect, useMemo, useState } from "react";
import Badge from "@/components/Badge";
import MetricCard from "@/components/MetricCard";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";
import { api } from "@/lib/api";
import { formatTimestamp, severityClasses } from "@/lib/format";

export default function IdentityAdminPage() {
  const [security, setSecurity] = useState(null);
  const [observability, setObservability] = useState(null);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      const [securityResponse, observabilityResponse, reportResponse] = await Promise.all([
        api.getIdentitySecurityDashboard(),
        api.getIdentityObservability(),
        api.getIdentitySecurityReport(),
      ]);
      setSecurity(securityResponse.data);
      setObservability(observabilityResponse.data);
      setReport(reportResponse.data.report);
    } catch (err) {
      setError(err.message || "Failed to load identity administration");
    } finally {
      setLoading(false);
    }
  }

  async function generateReport() {
    setSaving(true);
    setSaved("");
    setError("");
    try {
      const response = await api.generateIdentitySecurityReport();
      setReport(response.data.report);
      setSaved("Identity security report generated");
      await load();
    } catch (err) {
      setError(err.message || "Identity security report generation failed");
    } finally {
      setSaving(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  const executive = security?.executive || {};
  const reportSummary = report?.summary || {};
  const methods = report?.authenticationMethods || {};
  const providerPosture = report?.providerPosture || {};
  const recovery = observability?.recovery || {};
  const readinessLabel =
    report?.releaseReadiness?.status === "ready_for_validation"
      ? "Ready"
      : report?.releaseReadiness?.status === "review_required"
        ? "Review"
        : report?.releaseReadiness?.status || "unknown";

  const providerRows = useMemo(
    () =>
      Object.entries(methods)
        .filter(([key]) => key !== "mfa")
        .map(([key, value]) => ({
          provider: value?.displayName || key,
          type: value?.providerType || key,
          status: value?.status || "disabled",
          enabled: value?.enabled ? "yes" : "no",
        })),
    [methods],
  );

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

  const providerColumns = useMemo(
    () => [
      { key: "provider", label: "Provider" },
      { key: "type", label: "Type" },
      {
        key: "status",
        label: "Status",
        render: (row) => (
          <Badge className={row.status === "active" ? "bg-emerald-50 text-emerald-700" : "bg-slate-100 text-slate-700"}>
            {row.status}
          </Badge>
        ),
      },
      { key: "enabled", label: "Enabled" },
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
    ],
    [],
  );

  const recoveryColumns = useMemo(
    () => [
      { key: "workflowType", label: "Workflow" },
      { key: "status", label: "Status" },
      { key: "mfaRequired", label: "MFA", render: (row) => (row.mfaRequired ? "required" : "not required") },
      { key: "expiresAt", label: "Expires", render: (row) => row.expiresAt ? formatTimestamp(row.expiresAt) : "-" },
    ],
    [],
  );

  const findingColumns = useMemo(
    () => [
      {
        key: "severity",
        label: "Severity",
        render: (row) => <Badge className={severityClasses(row.severity)}>{row.severity}</Badge>,
      },
      { key: "summary", label: "Finding" },
    ],
    [],
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Identity Admin"
        subtitle="Enterprise identity posture, provider readiness, access governance, and recovery operations"
        actions={
          <div className="flex flex-wrap gap-2">
            <button className="btn-secondary" onClick={generateReport} disabled={saving}>
              Generate Report
            </button>
            <button className="btn-primary" onClick={load}>
              Refresh
            </button>
          </div>
        }
      />

      {error ? <div className="panel-soft rounded-xl p-4 text-sm text-red-700">{error}</div> : null}
      {saved ? <div className="panel-soft rounded-xl p-4 text-sm text-emerald-700">{saved}</div> : null}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-6">
        <MetricCard title="Identity Score" value={loading ? "..." : `${executive.identitySecurityScore ?? 100}%`} hint="Release posture score" />
        <MetricCard title="MFA Coverage" value={loading ? "..." : `${reportSummary.mfaAdoptionRate ?? 100}%`} hint="Enterprise MFA adoption" />
        <MetricCard title="Risky Identities" value={loading ? "..." : reportSummary.riskyIdentities ?? 0} hint="Active risk records" />
        <MetricCard title="Open Reviews" value={loading ? "..." : reportSummary.openAccessReviews ?? 0} hint="Access reviews still open" />
        <MetricCard title="Recovery Open" value={loading ? "..." : reportSummary.openRecoveryWorkflows ?? 0} hint="Active recovery work" />
        <MetricCard title="Readiness" value={loading ? "..." : readinessLabel} hint="Security report gate" />
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <SectionCard title="Authentication Methods">
          <SimpleTable columns={providerColumns} rows={providerRows} emptyText="No providers configured" />
        </SectionCard>

        <SectionCard title="Provider Health">
          <div className="space-y-3 text-sm">
            <HealthRow label="OAuth health" value={`${providerPosture.oauth?.healthScore ?? 100}%`} />
            <HealthRow label="SSO health" value={`${providerPosture.sso?.healthScore ?? 100}%`} />
            <HealthRow label="SCIM health" value={`${providerPosture.scim?.healthScore ?? 100}%`} />
            <HealthRow label="SCIM active providers" value={providerPosture.scim?.activeProviders ?? 0} />
          </div>
        </SectionCard>

        <SectionCard title="Release Evidence">
          <div className="space-y-3 text-sm">
            <HealthRow label="Report type" value={report?.reportType || "identity_security_report"} />
            <HealthRow label="Generated" value={report?.generatedAt ? formatTimestamp(report.generatedAt) : "-"} />
            <HealthRow label="Critical findings" value={report?.releaseReadiness?.criticalFindings ?? 0} />
            <HealthRow label="High findings" value={report?.releaseReadiness?.highFindings ?? 0} />
          </div>
        </SectionCard>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard title="Risky Identities">
          <SimpleTable columns={riskColumns} rows={security?.riskyIdentities || []} emptyText="No risky identities" />
        </SectionCard>

        <SectionCard title="Access Reviews">
          <SimpleTable columns={reviewColumns} rows={security?.accessReviews || []} emptyText="No access reviews" />
        </SectionCard>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard title="Recovery Activity">
          <SimpleTable columns={recoveryColumns} rows={recovery.workflows || []} emptyText="No recovery workflows" />
        </SectionCard>

        <SectionCard title="Release Findings">
          <SimpleTable columns={findingColumns} rows={report?.releaseReadiness?.findings || []} emptyText="No findings" />
        </SectionCard>
      </div>

      <SectionCard title="Recent Identity Security Events">
        <SimpleTable columns={eventColumns} rows={security?.recentEvents || []} emptyText="No identity security events" />
      </SectionCard>
    </div>
  );
}

function HealthRow({ label, value }) {
  return (
    <div className="flex items-center justify-between border-b border-slate-100 py-2 last:border-b-0">
      <span className="text-slate-600">{label}</span>
      <span className="font-semibold text-slate-950">{value}</span>
    </div>
  );
}
