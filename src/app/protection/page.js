"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import MetricCard from "@/components/MetricCard";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";
import { HorizontalBarChart } from "@/components/SecurityOpsCharts";

export default function ProtectionPage() {
  const [rules, setRules] = useState(null);
  const [events, setEvents] = useState(null);
  const [credentials, setCredentials] = useState(null);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const [ruleRes, eventRes, credentialRes] = await Promise.all([
        api.getProtectionRules({ limit: 100 }),
        api.getEnforcementEvents({ limit: 50 }),
        api.getCredentialProtection({ limit: 50 }),
      ]);
      setRules(ruleRes.data);
      setEvents(eventRes.data);
      setCredentials(credentialRes.data);
    } catch (err) {
      setError(err.message || "Failed to load protection data");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const ruleItems = rules?.items || [];
  const eventItems = events?.items || [];
  const credentialItems = credentials?.items || [];
  const actionData = useMemo(() => {
    const counts = eventItems.reduce((acc, item) => {
      acc[item.action] = (acc[item.action] || 0) + 1;
      return acc;
    }, {});
    return Object.entries(counts).map(([label, count]) => ({ label, count }));
  }, [eventItems]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Adaptive Protection"
        subtitle="Protection actions layered on canonical Zero Trust policy decisions"
        actions={<button className="btn-primary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-4">
        <MetricCard title="Active Rules" value={ruleItems.filter((item) => item.status === "active").length} hint="Bounded tenant-scoped protection rules" />
        <MetricCard title="Enforcement Events" value={eventItems.length} hint="Recent adaptive outcomes" />
        <MetricCard title="Quarantines" value={eventItems.filter((item) => item.action === "quarantine").length} hint="Distinct quarantine actions" />
        <MetricCard title="Credential States" value={credentialItems.length} hint="Suspicious/restricted/suspended credentials" />
      </div>
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard title="Action Distribution">
          <HorizontalBarChart data={actionData} />
        </SectionCard>
        <SectionCard title="Protection Precedence">
          <div className="space-y-2 text-sm text-slate-700">
            {(rules?.precedence || []).map((item, index) => (
              <div key={item} className="flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 px-4 py-2">
                <span>{item.replaceAll("_", " ")}</span>
                <span className="font-semibold text-slate-950">{index + 1}</span>
              </div>
            ))}
          </div>
        </SectionCard>
        <SectionCard title="Active Protection Rules">
          <SimpleTable
            columns={[
              { key: "name", label: "Rule" },
              { key: "action", label: "Action" },
              { key: "mode", label: "Mode" },
              { key: "precedence", label: "Precedence" },
              { key: "updatedAt", label: "Updated", render: (row) => formatDate(row.updatedAt) },
            ]}
            rows={ruleItems}
            emptyText="No adaptive protection rules configured"
          />
        </SectionCard>
        <SectionCard title="Recent Enforcement">
          <SimpleTable
            columns={[
              { key: "createdAt", label: "Time", render: (row) => formatDate(row.createdAt) },
              { key: "action", label: "Action" },
              { key: "mode", label: "Mode" },
              { key: "outcome", label: "Outcome" },
              { key: "riskScore", label: "Risk" },
            ]}
            rows={eventItems.slice(0, 10)}
            emptyText="No enforcement events"
          />
        </SectionCard>
      </div>
    </div>
  );
}

function ErrorBanner({ message }) {
  return <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">{message}</div>;
}

function formatDate(value) {
  return value ? new Date(value).toLocaleString() : "";
}
