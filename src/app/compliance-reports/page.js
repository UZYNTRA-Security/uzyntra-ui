"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

const DEFAULT_FORM = {
  reportType: "compliance_summary",
  framework: "nist_csf",
  title: "",
};

export default function ComplianceReportsPage() {
  const [rows, setRows] = useState([]);
  const [form, setForm] = useState(DEFAULT_FORM);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function load() {
    setError("");
    try {
      const response = await api.getComplianceReports({ limit: 100 });
      setRows(response.data?.items || []);
    } catch (err) {
      setError(err.message || "Failed to load compliance reports");
    }
  }

  async function create(event) {
    event.preventDefault();
    setError("");
    setMessage("");
    try {
      await api.createComplianceReport(form);
      setMessage("Compliance report foundation created");
      setForm(DEFAULT_FORM);
      await load();
    } catch (err) {
      setError(err.message || "Failed to create compliance report");
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Compliance Reports"
        subtitle="Evidence-backed report foundations for SOC, NIST, incident, executive, and customer summaries"
        actions={<button className="btn-secondary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      {message ? <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-700">{message}</div> : null}

      <SectionCard title="Create Report Foundation">
        <form className="grid grid-cols-1 gap-4 md:grid-cols-4" onSubmit={create}>
          <select className="select-ui" value={form.reportType} onChange={(e) => setForm({ ...form, reportType: e.target.value })}>
            <option value="security_posture">Security Posture</option>
            <option value="incident_summary">Incident Summary</option>
            <option value="compliance_summary">Compliance Summary</option>
            <option value="executive">Executive</option>
            <option value="customer_security">Customer Security</option>
          </select>
          <select className="select-ui" value={form.framework} onChange={(e) => setForm({ ...form, framework: e.target.value })}>
            <option value="nist_csf">NIST CSF</option>
            <option value="soc2">SOC 2</option>
            <option value="iso27001">ISO 27001</option>
            <option value="owasp_api">OWASP API</option>
          </select>
          <input className="input-ui md:col-span-2" placeholder="Optional title" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} />
          <button className="btn-primary md:col-span-4" type="submit">Generate Foundation</button>
        </form>
      </SectionCard>

      <SectionCard title="Report Foundations">
        <SimpleTable
          columns={[
            { key: "title", label: "Title" },
            { key: "reportType", label: "Type" },
            { key: "framework", label: "Framework" },
            { key: "status", label: "Status" },
            { key: "periodEnd", label: "Period End", render: (row) => row.periodEnd ? new Date(row.periodEnd).toLocaleDateString() : "" },
          ]}
          rows={rows}
          emptyText="No compliance reports have been created"
        />
      </SectionCard>
    </div>
  );
}

function ErrorBanner({ message }) {
  return <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">{message}</div>;
}
