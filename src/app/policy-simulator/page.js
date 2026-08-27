"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import MetricCard from "@/components/MetricCard";
import SimpleTable from "@/components/SimpleTable";

const defaultPayload = JSON.stringify(
  {
    policySnapshot: {
      defaultDecision: "allow",
      rules: [
        {
          id: "critical-risk-block",
          name: "Critical risk block",
          decision: "block",
          reason: "critical risk request",
          conditions: [{ field: "risk_score", operator: "gte", value: 90 }],
        },
      ],
    },
    mode: "dry_run",
    context: {
      riskScore: 92,
      confidence: 0.91,
      severity: "critical",
      httpMethod: "POST",
      requestPath: "/api/admin/export",
      threatReputation: "malicious",
      detectorIds: ["behavior.reconnaissance"],
    },
  },
  null,
  2,
);

export default function PolicySimulatorPage() {
  const [payload, setPayload] = useState(defaultPayload);
  const [result, setResult] = useState(null);
  const [simulations, setSimulations] = useState([]);
  const [tests, setTests] = useState([]);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const [simulationRes, testRes] = await Promise.all([
        api.getPolicySimulations({ limit: 20 }),
        api.getPolicyTestCases({ limit: 20 }),
      ]);
      setSimulations(simulationRes.data.items || []);
      setTests(testRes.data.items || []);
    } catch (err) {
      setError(err.message || "Failed to load simulation history");
    }
  }

  async function run() {
    setError("");
    setResult(null);
    try {
      const body = JSON.parse(payload);
      const res = await api.simulateZeroTrustPolicy(body);
      setResult(res.data);
      load();
    } catch (err) {
      setError(err.message || "Simulation failed");
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Policy Simulator"
        subtitle="Evaluate adaptive access decisions without changing policy state"
        actions={<button className="btn-primary" onClick={run}>Run Simulation</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1fr)_420px]">
        <SectionCard title="Simulation Input">
          <textarea
            className="min-h-[520px] w-full rounded-xl border border-slate-200 bg-slate-950 p-4 font-mono text-sm text-slate-50 outline-none focus:border-emerald-400"
            value={payload}
            onChange={(event) => setPayload(event.target.value)}
            spellCheck={false}
          />
        </SectionCard>
        <div className="space-y-6">
          <div className="grid grid-cols-1 gap-6">
            <MetricCard title="Decision" value={result?.decision || "-"} hint="Policy decision before mode translation" />
            <MetricCard title="Effective" value={result?.effectiveDecision || "-"} hint="Decision after observe/simulate/enforce mode" />
            <MetricCard title="Risk" value={result?.riskScore ?? "-"} hint="Normalized 0-100 risk" />
          </div>
          <SectionCard title="Explanation">
            <pre className="max-h-[360px] overflow-auto rounded-xl bg-slate-950 p-4 text-xs text-slate-50">
              {result ? JSON.stringify(result, null, 2) : "No simulation result"}
            </pre>
          </SectionCard>
        </div>
      </div>
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <SectionCard title="Simulation History">
          <SimpleTable
            columns={[
              { key: "mode", label: "Mode" },
              { key: "status", label: "Status" },
              { key: "summary", label: "Summary" },
              { key: "completedAt", label: "Completed", render: (row) => formatDate(row.completedAt) },
            ]}
            rows={simulations}
            emptyText="No saved simulations"
          />
        </SectionCard>
        <SectionCard title="Regression Cases">
          <SimpleTable
            columns={[
              { key: "name", label: "Name" },
              { key: "expectedDecision", label: "Decision" },
              { key: "expectedAction", label: "Action" },
              { key: "lastResult", label: "Last Result" },
            ]}
            rows={tests}
            emptyText="No policy regression cases"
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
