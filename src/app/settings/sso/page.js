"use client";

import { useEffect, useState } from "react";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import { api } from "@/lib/api";

const emptyProvider = {
  providerKey: "",
  providerType: "saml",
  displayName: "",
  status: "disabled",
  issuer: "",
  clientId: "",
  allowedDomains: "",
  authorizationEndpoint: "",
  tokenEndpoint: "",
  userInfoEndpoint: "",
  metadataUrl: "",
  singleSignOnUrl: "",
  jwksUri: "",
  spEntityId: "",
  configurationRef: "",
  secretRef: "",
};

export default function EnterpriseSsoPage() {
  const [settings, setSettings] = useState({
    ssoMode: "optional",
    ssoAllowedDomains: [],
    ssoPasswordLoginDisabled: false,
    ssoMfaRequired: false,
  });
  const [providers, setProviders] = useState([]);
  const [provider, setProvider] = useState(emptyProvider);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");

  async function load() {
    setError("");
    try {
      const [settingsResponse, providersResponse] = await Promise.all([
        api.getOrganizationSettings(),
        api.getSsoProviders(),
      ]);
      if (settingsResponse.data?.settings) {
        setSettings({
          ...settings,
          ...settingsResponse.data.settings,
        });
      }
      setProviders(providersResponse.data?.providers || []);
    } catch (err) {
      setError(err.message || "Failed to load SSO settings");
    }
  }

  async function savePolicy(event) {
    event.preventDefault();
    setSaved("");
    try {
      await api.updateOrganizationSettings({
        ssoMode: settings.ssoMode,
        ssoAllowedDomains: normalizeCsv(settings.ssoAllowedDomains),
        ssoPasswordLoginDisabled: Boolean(settings.ssoPasswordLoginDisabled),
        ssoMfaRequired: Boolean(settings.ssoMfaRequired),
      });
      setSaved("SSO policy saved");
      await load();
    } catch (err) {
      setError(err.message || "SSO policy update failed");
    }
  }

  async function createProvider(event) {
    event.preventDefault();
    setSaved("");
    try {
      const configuration = {
        metadataUrl: provider.metadataUrl || undefined,
        singleSignOnUrl: provider.singleSignOnUrl || undefined,
        jwksUri: provider.jwksUri || undefined,
        spEntityId: provider.spEntityId || undefined,
        signatureRequired: true,
      };
      await api.createSsoProvider({
        providerKey: provider.providerKey,
        providerType: provider.providerType,
        displayName: provider.displayName,
        status: provider.status,
        issuer: provider.issuer,
        clientId: provider.clientId || undefined,
        allowedDomains: normalizeCsv(provider.allowedDomains),
        authorizationEndpoint: provider.authorizationEndpoint || provider.singleSignOnUrl,
        tokenEndpoint: provider.tokenEndpoint || undefined,
        userInfoEndpoint: provider.userInfoEndpoint || undefined,
        configuration,
        configurationRef: provider.configurationRef || undefined,
        secretRef: provider.secretRef || undefined,
      });
      setProvider(emptyProvider);
      setSaved("SSO provider saved");
      await load();
    } catch (err) {
      setError(err.message || "SSO provider creation failed");
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader title="Enterprise SSO" subtitle="Organization-controlled SAML and OIDC authentication" />
      {error ? <div className="panel-soft rounded-xl p-4 text-sm text-red-700">{error}</div> : null}
      {saved ? <div className="panel-soft rounded-xl p-4 text-sm text-emerald-700">{saved}</div> : null}

      <SectionCard title="SSO Policy">
        <form onSubmit={savePolicy} className="grid gap-4 md:grid-cols-2">
          <select
            className="select-ui"
            value={settings.ssoMode || "optional"}
            onChange={(event) => setSettings({ ...settings, ssoMode: event.target.value })}
          >
            <option value="optional">optional</option>
            <option value="required">required</option>
            <option value="disabled">disabled</option>
          </select>
          <input
            className="input-ui"
            value={Array.isArray(settings.ssoAllowedDomains) ? settings.ssoAllowedDomains.join(",") : ""}
            onChange={(event) =>
              setSettings({
                ...settings,
                ssoAllowedDomains: event.target.value.split(",").map((item) => item.trim()),
              })
            }
            placeholder="example.com, uzyntra.com"
          />
          <label className="flex items-center gap-3 text-sm text-slate-700">
            <input
              type="checkbox"
              checked={Boolean(settings.ssoPasswordLoginDisabled)}
              onChange={(event) =>
                setSettings({ ...settings, ssoPasswordLoginDisabled: event.target.checked })
              }
            />
            Disable password login for SSO members
          </label>
          <label className="flex items-center gap-3 text-sm text-slate-700">
            <input
              type="checkbox"
              checked={Boolean(settings.ssoMfaRequired)}
              onChange={(event) => setSettings({ ...settings, ssoMfaRequired: event.target.checked })}
            />
            Require MFA after SSO
          </label>
          <div className="md:col-span-2">
            <button className="btn-primary" type="submit">Save Policy</button>
          </div>
        </form>
      </SectionCard>

      <SectionCard title="Identity Providers">
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="text-slate-500">
              <tr>
                <th className="px-3 py-2">Provider</th>
                <th className="px-3 py-2">Type</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Domains</th>
                <th className="px-3 py-2">Issuer</th>
                <th className="px-3 py-2">Test</th>
              </tr>
            </thead>
            <tbody>
              {providers.map((item) => (
                <tr key={item.id} className="border-t border-slate-200">
                  <td className="px-3 py-3 font-medium text-slate-900">{item.displayName}</td>
                  <td className="px-3 py-3 text-slate-600">{item.providerType}</td>
                  <td className="px-3 py-3 text-slate-600">{item.status}</td>
                  <td className="px-3 py-3 text-slate-600">{(item.allowedDomains || []).join(", ")}</td>
                  <td className="px-3 py-3 text-slate-600">{item.issuer || "-"}</td>
                  <td className="px-3 py-3">
                    <a
                      className="text-sm font-medium text-emerald-700"
                      href={`/api/auth/sso/${item.providerType}/${item.providerKey}/login?redirect=/settings/sso`}
                    >
                      Test
                    </a>
                  </td>
                </tr>
              ))}
              {providers.length === 0 ? (
                <tr>
                  <td className="px-3 py-4 text-slate-500" colSpan={6}>No enterprise SSO providers configured</td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </SectionCard>

      <SectionCard title="Add Provider">
        <form onSubmit={createProvider} className="grid gap-3 md:grid-cols-2">
          <input className="input-ui" value={provider.providerKey} onChange={(event) => setProvider({ ...provider, providerKey: event.target.value })} placeholder="acme-saml" />
          <select className="select-ui" value={provider.providerType} onChange={(event) => setProvider({ ...provider, providerType: event.target.value })}>
            <option value="saml">saml</option>
            <option value="oidc">oidc</option>
          </select>
          <input className="input-ui" value={provider.displayName} onChange={(event) => setProvider({ ...provider, displayName: event.target.value })} placeholder="Acme SSO" />
          <select className="select-ui" value={provider.status} onChange={(event) => setProvider({ ...provider, status: event.target.value })}>
            <option value="disabled">disabled</option>
            <option value="active">active</option>
          </select>
          <input className="input-ui" value={provider.allowedDomains} onChange={(event) => setProvider({ ...provider, allowedDomains: event.target.value })} placeholder="acme.com" />
          <input className="input-ui" value={provider.issuer} onChange={(event) => setProvider({ ...provider, issuer: event.target.value })} placeholder="https://idp.example.com" />
          <input className="input-ui" value={provider.authorizationEndpoint} onChange={(event) => setProvider({ ...provider, authorizationEndpoint: event.target.value })} placeholder="Authorization or SSO URL" />
          <input className="input-ui" value={provider.tokenEndpoint} onChange={(event) => setProvider({ ...provider, tokenEndpoint: event.target.value })} placeholder="OIDC token endpoint" />
          <input className="input-ui" value={provider.userInfoEndpoint} onChange={(event) => setProvider({ ...provider, userInfoEndpoint: event.target.value })} placeholder="OIDC userinfo endpoint" />
          <input className="input-ui" value={provider.clientId} onChange={(event) => setProvider({ ...provider, clientId: event.target.value })} placeholder="OIDC client ID" />
          <input className="input-ui" value={provider.metadataUrl} onChange={(event) => setProvider({ ...provider, metadataUrl: event.target.value })} placeholder="SAML metadata URL" />
          <input className="input-ui" value={provider.singleSignOnUrl} onChange={(event) => setProvider({ ...provider, singleSignOnUrl: event.target.value })} placeholder="SAML SSO URL" />
          <input className="input-ui" value={provider.jwksUri} onChange={(event) => setProvider({ ...provider, jwksUri: event.target.value })} placeholder="OIDC JWKS URI" />
          <input className="input-ui" value={provider.spEntityId} onChange={(event) => setProvider({ ...provider, spEntityId: event.target.value })} placeholder="SP entity ID" />
          <input className="input-ui" value={provider.configurationRef} onChange={(event) => setProvider({ ...provider, configurationRef: event.target.value })} placeholder="Configuration reference" />
          <input className="input-ui" value={provider.secretRef} onChange={(event) => setProvider({ ...provider, secretRef: event.target.value })} placeholder="OIDC secret env var" />
          <div className="md:col-span-2">
            <button className="btn-primary" type="submit">Save Provider</button>
          </div>
        </form>
      </SectionCard>
    </div>
  );
}

function normalizeCsv(value) {
  if (Array.isArray(value)) {
    return value.map((item) => String(item || "").trim()).filter(Boolean);
  }
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}
