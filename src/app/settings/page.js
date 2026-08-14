"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";

export default function SettingsPage() {
  const [settings, setSettings] = useState({
    mfaRequired: false,
    sessionTimeoutSeconds: 28800,
    allowedEmailDomains: [],
    securityLevel: "standard",
  });
  const [organization, setOrganization] = useState({ name: "", slug: "" });
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");

  async function load() {
    setError("");
    try {
      const response = await api.getOrganizationSettings();
      if (response.data?.settings) setSettings(response.data.settings);
    } catch (err) {
      setError(err.message || "Failed to load settings");
    }
  }

  async function save(event) {
    event.preventDefault();
    setSaved("");
    try {
      await api.updateOrganizationSettings(settings);
      setSaved("Settings saved");
      await load();
    } catch (err) {
      setError(err.message || "Settings update failed");
    }
  }

  async function createOrganization(event) {
    event.preventDefault();
    setSaved("");
    try {
      const created = await api.createOrganization(organization);
      await api.switchOrganization(created.data?.organization?.id);
      setSaved("Organization created");
      window.location.reload();
    } catch (err) {
      setError(err.message || "Organization creation failed");
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader title="Settings" subtitle="Organization configuration and platform security defaults" />
      {error ? <div className="panel-soft rounded-xl p-4 text-sm text-red-700">{error}</div> : null}
      {saved ? <div className="panel-soft rounded-xl p-4 text-sm text-emerald-700">{saved}</div> : null}
      <SectionCard title="Create Organization">
        <form onSubmit={createOrganization} className="grid gap-3 md:grid-cols-[1fr_220px_auto]">
          <input className="input-ui" value={organization.name} onChange={(e) => setOrganization({ ...organization, name: e.target.value })} placeholder="Acme Security" />
          <input className="input-ui" value={organization.slug} onChange={(e) => setOrganization({ ...organization, slug: e.target.value })} placeholder="acme-security" />
          <button className="btn-primary" type="submit">Create</button>
        </form>
      </SectionCard>
      <SectionCard title="Security Settings">
        <form onSubmit={save} className="grid gap-4 md:grid-cols-2">
          <label className="flex items-center gap-3 text-sm text-slate-700">
            <input
              type="checkbox"
              checked={settings.mfaRequired}
              onChange={(e) => setSettings({ ...settings, mfaRequired: e.target.checked })}
            />
            MFA required
          </label>
          <select className="select-ui" value={settings.securityLevel} onChange={(e) => setSettings({ ...settings, securityLevel: e.target.value })}>
            <option value="standard">standard</option>
            <option value="strict">strict</option>
            <option value="enterprise">enterprise</option>
          </select>
          <input
            className="input-ui"
            type="number"
            min="300"
            max="2592000"
            value={settings.sessionTimeoutSeconds}
            onChange={(e) => setSettings({ ...settings, sessionTimeoutSeconds: Number(e.target.value) })}
          />
          <input
            className="input-ui"
            value={(settings.allowedEmailDomains || []).join(",")}
            onChange={(e) =>
              setSettings({
                ...settings,
                allowedEmailDomains: e.target.value.split(",").map((item) => item.trim()),
              })
            }
            placeholder="example.com, uzyntra.com"
          />
          <div className="md:col-span-2">
            <button className="btn-primary" type="submit">Save</button>
          </div>
        </form>
      </SectionCard>
    </div>
  );
}
