"use client";

import { useEffect, useMemo, useState } from "react";
import Badge from "@/components/Badge";
import MetricCard from "@/components/MetricCard";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";
import { api } from "@/lib/api";
import { formatTimestamp, severityClasses } from "@/lib/format";

export default function IdentityObservabilityPage() {
  const [data, setData] = useState(null);
  const [reportType, setReportType] = useState("identity_evidence");
  const [exportFormat, setExportFormat] = useState("json");
  const [workflowType, setWorkflowType] = useState("account_recovery");
  const [recoveryReason, setRecoveryReason] = useState("Operator recovery readiness validation");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");

  async function load() {
    setLoading(true);
    setError("");
    try {
      const response = await api.getIdentityObservability();
      setData(response.data);
    } catch (err) {
      setError(err.message || "Failed to load identity observability");
    } finally {
      setLoading(false);
    }
  }

  async function generateReport(event) {
    event.preventDefault();
    setSaving(true);
    setSaved("");
    setError("");
    try {
      await api.createIdentityAuditReport({ reportType, exportFormat });
      setSaved("Identity audit report generated");
      await load();
    } catch (err) {
      setError(err.message || "Report generation failed");
    } finally {
      setSaving(false);
    }
  }

  async function createRecovery(event) {
    event.preventDefault();
    setSaving(true);
    setSaved("");
    setError("");
    try {
      await api.createIdentityRecoveryWorkflow({
        workflowType,
        reason: recoveryReason,
        metadata: { source: "identity-observability" },
      });
      setSaved("Recovery workflow requested");
      await load();
    } catch (err) {
      setError(err.message || "Recovery workflow creation failed");
    } finally {
      setSaving(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  const executive = data?.executive || {};
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
  const reportColumns = useMemo(
    () => [
      { key: "reportType", label: "Report" },
      { key: "exportFormat", label: "Format" },
      { key: "rowCount", label: "Rows" },
      { key: "generatedAt", label: "Generated", render: (row) => formatTimestamp(row.generatedAt) },
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

  return (
    <div className="space-y-6">
      <PageHeader
        title="Identity Observability"
        subtitle="Authentication reliability, provider health, audit evidence, and recovery readiness"
        actions={<button className="btn-primary" onClick={load}>Refresh</button>}
      />

      {error ? <div className="panel-soft rounded-xl p-4 text-sm text-red-700">{error}</div> : null}
      {saved ? <div className="panel-soft rounded-xl p-4 text-sm text-emerald-700">{saved}</div> : null}

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-6">
        <MetricCard title="Login Success" value={loading ? "..." : `${executive.loginSuccessRate ?? 100}%`} hint="Successful primary auth rate" />
        <MetricCard title="Login Failure" value={loading ? "..." : `${executive.loginFailureRate ?? 0}%`} hint="Failed primary auth rate" />
        <MetricCard title="MFA Adoption" value={loading ? "..." : `${executive.mfaAdoptionRate ?? 100}%`} hint="Active users with MFA" />
        <MetricCard title="OAuth Health" value={loading ? "..." : `${executive.oauthHealth ?? 100}%`} hint="Google/GitHub callback health" />
        <MetricCard title="SSO Health" value={loading ? "..." : `${executive.ssoHealth ?? 100}%`} hint="Enterprise SSO health" />
        <MetricCard title="SCIM Health" value={loading ? "..." : `${executive.scimHealth ?? 100}%`} hint="Provisioning health" />
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <SectionCard title="Authentication Metrics">
          <div className="space-y-3 text-sm">
            <HealthRow label="Successful logins" value={data?.authentication?.successfulLogins ?? 0} />
            <HealthRow label="Failed logins" value={data?.authentication?.failedLogins ?? 0} />
            <HealthRow label="MFA failures" value={data?.authentication?.mfaFailures ?? 0} />
            <HealthRow label="Risky identities" value={data?.risky?.activeRiskCount ?? 0} />
          </div>
        </SectionCard>

        <SectionCard title="Provider Health">
          <div className="space-y-3 text-sm">
            <HealthRow label="OAuth failures" value={data?.oauth?.failures ?? 0} />
            <HealthRow label="SSO failures" value={data?.sso?.failures ?? 0} />
            <HealthRow label="SCIM active providers" value={data?.scim?.activeProviders ?? 0} />
            <HealthRow label="SCIM running syncs" value={data?.scim?.running ?? 0} />
          </div>
        </SectionCard>

        <SectionCard title="Recovery Readiness">
          <div className="space-y-3 text-sm">
            <HealthRow label="Open workflows" value={executive.openRecoveryWorkflows ?? 0} />
            <HealthRow label="Break-glass admins" value={data?.recovery?.breakGlassAdministrators?.length ?? 0} />
            <HealthRow label="Recovery events" value={data?.recovery?.events?.length ?? 0} />
          </div>
        </SectionCard>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard title="Generate Audit Evidence">
          <form onSubmit={generateReport} className="space-y-3">
            <select className="select-ui" value={reportType} onChange={(event) => setReportType(event.target.value)}>
              <option value="administrator_activity">administrator_activity</option>
              <option value="authentication_activity">authentication_activity</option>
              <option value="provisioning_activity">provisioning_activity</option>
              <option value="access_review">access_review</option>
              <option value="identity_evidence">identity_evidence</option>
            </select>
            <select className="select-ui" value={exportFormat} onChange={(event) => setExportFormat(event.target.value)}>
              <option value="json">json</option>
              <option value="csv">csv</option>
              <option value="evidence_timeline">evidence_timeline</option>
            </select>
            <button className="btn-primary" disabled={saving} type="submit">Generate Report</button>
          </form>
        </SectionCard>

        <SectionCard title="Request Recovery Workflow">
          <form onSubmit={createRecovery} className="space-y-3">
            <select className="select-ui" value={workflowType} onChange={(event) => setWorkflowType(event.target.value)}>
              <option value="account_recovery">account_recovery</option>
              <option value="lockout_recovery">lockout_recovery</option>
              <option value="break_glass_activation">break_glass_activation</option>
              <option value="identity_disaster_recovery">identity_disaster_recovery</option>
            </select>
            <textarea className="input-ui min-h-24" value={recoveryReason} onChange={(event) => setRecoveryReason(event.target.value)} />
            <button className="btn-secondary" disabled={saving} type="submit">Request Recovery</button>
          </form>
        </SectionCard>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard title="Risk Trends">
          <SimpleTable columns={riskColumns} rows={data?.risky?.topRisks || []} emptyText="No risky identities" />
        </SectionCard>

        <SectionCard title="Recovery Workflows">
          <SimpleTable columns={recoveryColumns} rows={data?.recovery?.workflows || []} emptyText="No recovery workflows" />
        </SectionCard>
      </div>

      <SectionCard title="Identity Audit Reports">
        <SimpleTable columns={reportColumns} rows={data?.reports || []} emptyText="No identity audit reports" />
      </SectionCard>
    </div>
  );
}

function HealthRow({ label, value }) {
  return (
    <div className="flex items-center justify-between rounded-xl border border-slate-200 bg-white px-3 py-2">
      <span className="text-slate-600">{label}</span>
      <span className="font-semibold text-slate-950">{value}</span>
    </div>
  );
}
