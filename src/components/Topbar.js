"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";

export default function Topbar() {
  const [context, setContext] = useState(null);
  const [firewalls, setFirewalls] = useState([]);

  async function load() {
    try {
      const [me, firewallRes] = await Promise.all([api.me(), api.getFirewalls()]);
      setContext(me);
      setFirewalls(firewallRes.data?.firewalls || []);
    } catch {
      setContext(null);
      setFirewalls([]);
    }
  }

  async function switchOrganization(event) {
    await api.switchOrganization(event.target.value);
    await load();
    window.location.reload();
  }

  async function switchFirewall(event) {
    await api.selectFirewall(event.target.value || null);
    await load();
    window.location.reload();
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <header className="border-b border-slate-200/80 bg-white/90 px-6 py-4 backdrop-blur">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-base font-semibold text-slate-950">
            UZYNTRA Command Center
          </p>
          <p className="text-sm text-slate-600">
            Advanced API Threat Intelligence &amp; Control
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <select
            value={context?.organizationId || ""}
            onChange={switchOrganization}
            className="h-10 rounded border border-slate-200 bg-white px-3 text-sm text-slate-700"
          >
            {(context?.organizations || []).map((organization) => (
              <option key={organization.id} value={organization.id}>
                {organization.name}
              </option>
            ))}
          </select>
          <select
            value={context?.activeFirewallInstanceId || ""}
            onChange={switchFirewall}
            className="h-10 rounded border border-slate-200 bg-white px-3 text-sm text-slate-700"
          >
            <option value="">No firewall selected</option>
            {firewalls
              .filter((firewall) => firewall.status === "active")
              .map((firewall) => (
                <option key={firewall.id} value={firewall.id}>
                  {firewall.name}
                </option>
              ))}
          </select>
        </div>
      </div>
    </header>
  );
}
