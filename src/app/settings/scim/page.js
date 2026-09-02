"use client";

import { useEffect, useState } from "react";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import { api } from "@/lib/api";

const emptyProvider = {
  name: "Enterprise SCIM",
  status: "disabled",
  endpointConfigurationRef: "",
  baseUrl: "",
};

export default function ScimSettingsPage() {
  const [providers, setProviders] = useState([]);
  const [provider, setProvider] = useState(emptyProvider);
  const [tokenProviderId, setTokenProviderId] = useState("");
  const [tokenName, setTokenName] = useState("SCIM token");
  const [oneTimeToken, setOneTimeToken] = useState("");
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");

  async function load() {
    setError("");
    try {
      const response = await api.getScimProviders();
      const loaded = response.data?.providers || [];
      setProviders(loaded);
      if (!tokenProviderId && loaded[0]) setTokenProviderId(loaded[0].id);
    } catch (err) {
      setError(err.message || "Failed to load SCIM settings");
    }
  }

  async function saveProvider(event) {
    event.preventDefault();
    setSaved("");
    setOneTimeToken("");
    try {
      await api.createScimProvider(provider);
      setProvider(emptyProvider);
      setSaved("SCIM provider saved");
      await load();
    } catch (err) {
      setError(err.message || "SCIM provider save failed");
    }
  }

  async function generateToken(event) {
    event.preventDefault();
    setSaved("");
    setOneTimeToken("");
    try {
      const response = await api.generateScimToken({
        providerId: tokenProviderId,
        name: tokenName,
      });
      setOneTimeToken(response.data?.plaintextToken || "");
      setSaved("SCIM token generated");
    } catch (err) {
      setError(err.message || "SCIM token generation failed");
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader title="SCIM Provisioning" subtitle="Enterprise identity lifecycle automation" />
      {error ? <div className="panel-soft rounded-xl p-4 text-sm text-red-700">{error}</div> : null}
      {saved ? <div className="panel-soft rounded-xl p-4 text-sm text-emerald-700">{saved}</div> : null}

      <SectionCard title="SCIM Providers">
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="text-slate-500">
              <tr>
                <th className="px-3 py-2">Name</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Endpoint</th>
                <th className="px-3 py-2">Last Sync</th>
              </tr>
            </thead>
            <tbody>
              {providers.map((item) => (
                <tr key={item.id} className="border-t border-slate-200">
                  <td className="px-3 py-3 font-medium text-slate-900">{item.name}</td>
                  <td className="px-3 py-3 text-slate-600">{item.status}</td>
                  <td className="px-3 py-3 text-slate-600">/scim/v2</td>
                  <td className="px-3 py-3 text-slate-600">{item.lastSyncAt || "-"}</td>
                </tr>
              ))}
              {providers.length === 0 ? (
                <tr>
                  <td className="px-3 py-4 text-slate-500" colSpan={4}>No SCIM providers configured</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </SectionCard>

      <SectionCard title="Enable SCIM">
        <form onSubmit={saveProvider} className="grid gap-3 md:grid-cols-2">
          <input className="input-ui" value={provider.name} onChange={(event) => setProvider({ ...provider, name: event.target.value })} />
          <select className="select-ui" value={provider.status} onChange={(event) => setProvider({ ...provider, status: event.target.value })}>
            <option value="disabled">disabled</option>
            <option value="active">active</option>
          </select>
          <input className="input-ui" value={provider.endpointConfigurationRef} onChange={(event) => setProvider({ ...provider, endpointConfigurationRef: event.target.value })} placeholder="Endpoint configuration reference" />
          <input className="input-ui" value={provider.baseUrl} onChange={(event) => setProvider({ ...provider, baseUrl: event.target.value })} placeholder="https://console.uzyntra.com/scim/v2" />
          <div className="md:col-span-2">
            <button className="btn-primary" type="submit">Save Provider</button>
          </div>
        </form>
      </SectionCard>

      <SectionCard title="Access Token">
        <form onSubmit={generateToken} className="grid gap-3 md:grid-cols-[1fr_1fr_auto]">
          <select className="select-ui" value={tokenProviderId} onChange={(event) => setTokenProviderId(event.target.value)}>
            <option value="">Select provider</option>
            {providers.map((item) => (
              <option key={item.id} value={item.id}>{item.name}</option>
            ))}
          </select>
          <input className="input-ui" value={tokenName} onChange={(event) => setTokenName(event.target.value)} />
          <button className="btn-primary" type="submit">Generate</button>
        </form>
        {oneTimeToken ? (
          <div className="mt-4 rounded-xl border border-amber-200 bg-amber-50 p-4">
            <p className="text-xs font-semibold uppercase tracking-wide text-amber-700">One-time token</p>
            <pre className="mt-2 overflow-x-auto rounded-lg bg-white p-3 text-xs text-slate-800">{oneTimeToken}</pre>
          </div>
        ) : null}
      </SectionCard>
    </div>
  );
}
