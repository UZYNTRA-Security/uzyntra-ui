"use client";

import Image from "next/image";
import Link from "next/link";
import { usePathname } from "next/navigation";

const links = [
  { href: "/", label: "Dashboard" },
  { href: "/security-dashboard", label: "Security Ops" },
  { href: "/security-posture", label: "Security Posture" },
  { href: "/threat-analytics", label: "Threat Analytics" },
  { href: "/security-trends", label: "Security Trends" },
  { href: "/detections", label: "Detections" },
  { href: "/detection-rules", label: "Detection Rules" },
  { href: "/risk-analysis", label: "Risk Analysis" },
  { href: "/correlation-events", label: "Correlation Events" },
  { href: "/threat-intelligence", label: "Threat Intel" },
  { href: "/intelligence-sources", label: "Intel Sources" },
  { href: "/threat-indicators", label: "Threat Indicators" },
  { href: "/zero-trust", label: "Zero Trust" },
  { href: "/policies", label: "ZT Policies" },
  { href: "/policy-simulator", label: "Policy Simulator" },
  { href: "/policy-decisions", label: "Policy Decisions" },
  { href: "/policy-history", label: "Policy History" },
  { href: "/approval-workflows", label: "Approvals" },
  { href: "/playbooks", label: "Playbooks" },
  { href: "/automation-runs", label: "Automation Runs" },
  { href: "/response-actions", label: "Response Actions" },
  { href: "/investigations", label: "Investigations" },
  { href: "/cases", label: "Cases" },
  { href: "/security-copilot", label: "AI Copilot" },
  { href: "/ai-investigations", label: "AI Investigations" },
  { href: "/ai-reports", label: "AI Reports" },
  { href: "/ai-history", label: "AI History" },
  { href: "/enterprise", label: "Enterprise" },
  { href: "/customer-tenants", label: "Customer Tenants" },
  { href: "/delegated-access", label: "Delegated Access" },
  { href: "/compliance-reports", label: "Compliance Reports" },
  { href: "/usage", label: "Usage" },
  { href: "/platform", label: "Platform" },
  { href: "/regions", label: "Regions" },
  { href: "/platform-health", label: "Platform Health" },
  { href: "/developer", label: "Developer" },
  { href: "/marketplace", label: "Marketplace" },
  { href: "/access-decisions", label: "Access Decisions" },
  { href: "/protection", label: "Protection" },
  { href: "/enforcement-events", label: "Enforcement Events" },
  { href: "/rate-limits", label: "Rate Limits" },
  { href: "/blocklists", label: "Blocklists" },
  { href: "/allowlists", label: "Allowlists" },
  { href: "/events", label: "Events" },
  { href: "/alerts", label: "Alerts" },
  { href: "/alert-rules", label: "Alert Rules" },
  { href: "/incidents", label: "Incidents" },
  { href: "/integrations", label: "Integrations" },
  { href: "/api-inventory", label: "API Inventory" },
  { href: "/mitigations", label: "Mitigations" },
  { href: "/reputation", label: "Reputation" },
  { href: "/audits", label: "Audits" },
  { href: "/policy", label: "Policy" },
  { href: "/firewalls", label: "Firewalls" },
  { href: "/team", label: "Team" },
  { href: "/service-accounts", label: "Service Accounts" },
  { href: "/api-keys", label: "API Keys" },
  { href: "/settings", label: "Settings" },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="flex h-screen w-72 shrink-0 flex-col border-r border-white/10 bg-[#06101c] text-white">
      <div className="border-b border-white/10 px-6 py-6">
        <div className="flex items-center gap-3">
          <div className="brand-glow overflow-hidden rounded-2xl bg-white/5 p-1">
            <Image
              src="/uzyntra-logo-mark.png"
              alt="UZYNTRA"
              width={52}
              height={52}
              className="rounded-xl object-cover"
            />
          </div>

          <div>
            <h1 className="text-xl font-semibold tracking-[0.18em] text-white">
              UZYNTRA
            </h1>
            <p className="mt-1 text-xs text-cyan-100/70">
              Threat Control Console
            </p>
          </div>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto px-4 py-4">
        <ul className="space-y-2">
          {links.map((link) => {
            const active = pathname === link.href;

            return (
              <li key={link.href}>
                <Link
                  href={link.href}
                  className={`block rounded-2xl px-4 py-3 text-sm font-medium transition ${
                    active
                      ? "bg-emerald-400/12 text-emerald-300 ring-1 ring-emerald-400/25"
                      : "text-slate-200 hover:bg-white/5 hover:text-white"
                  }`}
                >
                  {link.label}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      <div className="border-t border-white/10 px-4 py-4">
        <div className="rounded-2xl bg-white/5 px-4 py-3">
          <p className="text-xs uppercase tracking-[0.18em] text-cyan-100/60">
            UZYNTRA
          </p>
          <p className="mt-1 text-xs text-slate-300/70">
            Operator Console v1
          </p>
        </div>
      </div>
    </aside>
  );
}
