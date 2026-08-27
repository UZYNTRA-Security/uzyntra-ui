"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";

export default function MarketplacePage() {
  const [rows, setRows] = useState([]);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const response = await api.getMarketplace({ limit: 100 });
      setRows(response.data?.items || []);
    } catch (err) {
      setError(err.message || "Failed to load marketplace");
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader title="Marketplace" subtitle="Enterprise integration marketplace readiness, publisher review, and capability visibility" actions={<button className="btn-secondary" onClick={load}>Refresh</button>} />
      {error ? <ErrorBanner message={error} /> : null}

      <SectionCard title="Marketplace Listings">
        <SimpleTable
          columns={[
            { key: "name", label: "Listing" },
            { key: "category", label: "Category" },
            { key: "status", label: "Status" },
            { key: "securityReviewStatus", label: "Review" },
            { key: "pricingModel", label: "Pricing" },
            { key: "integration", label: "Integration", render: (row) => row.integration?.name || row.integrationId },
          ]}
          rows={rows}
          emptyText="No marketplace listings have been published"
        />
      </SectionCard>
    </div>
  );
}

function ErrorBanner({ message }) {
  return <div className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">{message}</div>;
}
