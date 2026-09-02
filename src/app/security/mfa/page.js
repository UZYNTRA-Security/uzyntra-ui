"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import SimpleTable from "@/components/SimpleTable";
import Badge from "@/components/Badge";

export default function MfaPage() {
  const [methods, setMethods] = useState([]);
  const [totpEnrollment, setTotpEnrollment] = useState(null);
  const [totpCode, setTotpCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState([]);
  const [webauthnChallenge, setWebauthnChallenge] = useState(null);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");

  async function load() {
    setError("");
    try {
      const response = await api.getMfaMethods();
      setMethods(response.data?.methods || []);
    } catch (err) {
      setError(err.message || "Failed to load MFA methods");
    }
  }

  async function startTotp() {
    setError("");
    setSaved("");
    try {
      const response = await api.enrollTotp();
      setTotpEnrollment(response.data);
    } catch (err) {
      setError(err.message || "Failed to start authenticator enrollment");
    }
  }

  async function verifyTotp(event) {
    event.preventDefault();
    setError("");
    setSaved("");
    try {
      await api.verifyTotp({ methodId: totpEnrollment?.method?.id, code: totpCode });
      setTotpEnrollment(null);
      setTotpCode("");
      setSaved("Authenticator enabled");
      await load();
    } catch (err) {
      setError(err.message || "Failed to verify authenticator");
    }
  }

  async function createRecoveryCodes() {
    setError("");
    setSaved("");
    try {
      const response = await api.generateRecoveryCodes();
      setRecoveryCodes(response.data?.recoveryCodes || []);
      setSaved("Recovery codes generated");
      await load();
    } catch (err) {
      setError(err.message || "Failed to generate recovery codes");
    }
  }

  async function startWebAuthn() {
    setError("");
    setSaved("");
    try {
      const response = await api.createWebAuthnChallenge();
      setWebauthnChallenge(response.data?.challenge || null);
      setSaved("Passkey challenge created");
    } catch (err) {
      setError(err.message || "Failed to create passkey challenge");
    }
  }

  async function disableMethod(methodId) {
    setError("");
    setSaved("");
    try {
      await api.disableMfaMethod(methodId);
      setSaved("MFA method disabled");
      await load();
    } catch (err) {
      setError(err.message || "Failed to disable MFA method");
    }
  }

  useEffect(() => {
    load();
  }, []);

  const columns = useMemo(
    () => [
      { key: "displayName", label: "Method" },
      { key: "methodType", label: "Type" },
      {
        key: "status",
        label: "Status",
        render: (row) => <Badge>{row.status}</Badge>,
      },
      {
        key: "lastUsedAt",
        label: "Last Used",
        render: (row) => row.lastUsedAt || "-",
      },
      {
        key: "actions",
        label: "",
        render: (row) =>
          row.status === "active" ? (
            <button className="text-sm font-semibold text-red-700" onClick={() => disableMethod(row.id)}>
              Disable
            </button>
          ) : (
            "-"
          ),
      },
    ],
    [],
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="MFA"
        subtitle="Strong authentication controls for your UZYNTRA account"
      />

      {error ? <div className="rounded border border-red-200 bg-red-50 p-4 text-sm text-red-700">{error}</div> : null}
      {saved ? <div className="rounded border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-700">{saved}</div> : null}

      <SectionCard title="Methods">
        <SimpleTable columns={columns} rows={methods} emptyText="No MFA methods registered" />
      </SectionCard>

      <div className="grid gap-6 xl:grid-cols-3">
        <SectionCard title="Authenticator App">
          <div className="space-y-4">
            <button className="btn-primary" onClick={startTotp}>
              Enable authenticator app
            </button>

            {totpEnrollment ? (
              <form onSubmit={verifyTotp} className="space-y-3">
                <div className="rounded border border-slate-200 bg-slate-50 p-3">
                  <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
                    Secret
                  </p>
                  <p className="mt-1 break-all font-mono text-sm text-slate-900">
                    {totpEnrollment.secret}
                  </p>
                </div>
                <div className="rounded border border-slate-200 bg-slate-50 p-3">
                  <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
                    URI
                  </p>
                  <p className="mt-1 break-all font-mono text-xs text-slate-700">
                    {totpEnrollment.otpauthUri}
                  </p>
                </div>
                <input
                  className="input-ui"
                  value={totpCode}
                  onChange={(event) => setTotpCode(event.target.value)}
                  inputMode="numeric"
                  placeholder="123456"
                />
                <button className="btn-primary" type="submit">
                  Verify
                </button>
              </form>
            ) : null}
          </div>
        </SectionCard>

        <SectionCard title="Recovery Codes">
          <div className="space-y-4">
            <button className="btn-primary" onClick={createRecoveryCodes}>
              Generate recovery codes
            </button>
            {recoveryCodes.length > 0 ? (
              <div className="grid gap-2">
                {recoveryCodes.map((code) => (
                  <code key={code} className="rounded bg-slate-100 px-3 py-2 text-sm text-slate-900">
                    {code}
                  </code>
                ))}
              </div>
            ) : null}
          </div>
        </SectionCard>

        <SectionCard title="Passkeys">
          <div className="space-y-4">
            <button className="btn-primary" onClick={startWebAuthn}>
              Register passkey
            </button>
            {webauthnChallenge ? (
              <div className="rounded border border-slate-200 bg-slate-50 p-3">
                <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
                  Challenge
                </p>
                <p className="mt-1 break-all font-mono text-xs text-slate-700">
                  {webauthnChallenge.id}
                </p>
              </div>
            ) : null}
          </div>
        </SectionCard>
      </div>
    </div>
  );
}
