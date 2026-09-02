"use client";

import { useState } from "react";

const oauthProviders = [
  { key: "google", label: "Continue with Google" },
  { key: "github", label: "Continue with GitHub" },
];

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaCode, setMfaCode] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submitPasswordLogin(event) {
    event.preventDefault();
    setError("");
    setLoading(true);

    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(payload.error || "Unable to sign in");
      }
      if (payload.mfaRequired) {
        setMfaRequired(true);
        return;
      }
      window.location.assign("/");
    } catch (err) {
      setError(err.message || "Unable to sign in");
    } finally {
      setLoading(false);
    }
  }

  async function submitMfa(event) {
    event.preventDefault();
    setError("");
    setLoading(true);

    try {
      const response = await fetch("/api/auth/mfa/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ code: mfaCode, recoveryCode: mfaCode }),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(payload.error || "Unable to verify MFA");
      }
      window.location.assign("/");
    } catch (err) {
      setError(err.message || "Unable to verify MFA");
    } finally {
      setLoading(false);
    }
  }

  function startOAuth(providerKey) {
    window.location.assign(`/api/auth/oauth/${providerKey}/login`);
  }

  return (
    <div className="mx-auto flex min-h-[70vh] max-w-md flex-col justify-center">
      <div className="rounded-2xl border border-slate-200 bg-white p-8 shadow-sm">
        <div className="mb-6">
          <p className="text-sm font-semibold uppercase tracking-[0.18em] text-emerald-700">
            UZYNTRA
          </p>
          <h1 className="mt-2 text-2xl font-semibold text-slate-950">
            Sign in
          </h1>
        </div>

        {error ? (
          <div className="mb-4 rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
            {error}
          </div>
        ) : null}

        {mfaRequired ? (
          <form onSubmit={submitMfa} className="space-y-4">
            <label className="block">
              <span className="text-sm font-medium text-slate-700">MFA code</span>
              <input
                value={mfaCode}
                onChange={(event) => setMfaCode(event.target.value)}
                inputMode="numeric"
                autoComplete="one-time-code"
                className="mt-1 h-11 w-full rounded border border-slate-200 px-3 text-sm text-slate-900 outline-none focus:border-emerald-500"
              />
            </label>

            <button
              disabled={loading}
              className="h-11 w-full rounded bg-slate-950 px-4 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading ? "Verifying..." : "Verify"}
            </button>
          </form>
        ) : (
        <form onSubmit={submitPasswordLogin} className="space-y-4">
          <label className="block">
            <span className="text-sm font-medium text-slate-700">Email</span>
            <input
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              type="email"
              autoComplete="email"
              className="mt-1 h-11 w-full rounded border border-slate-200 px-3 text-sm text-slate-900 outline-none focus:border-emerald-500"
            />
          </label>

          <label className="block">
            <span className="text-sm font-medium text-slate-700">Password</span>
            <input
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              type="password"
              autoComplete="current-password"
              className="mt-1 h-11 w-full rounded border border-slate-200 px-3 text-sm text-slate-900 outline-none focus:border-emerald-500"
            />
          </label>

          <button
            disabled={loading}
            className="h-11 w-full rounded bg-slate-950 px-4 text-sm font-semibold text-white disabled:cursor-not-allowed disabled:opacity-60"
          >
            {loading ? "Signing in..." : "Sign in"}
          </button>
        </form>
        )}

        {!mfaRequired ? (
        <>
        <div className="my-5 flex items-center gap-3">
          <div className="h-px flex-1 bg-slate-200" />
          <span className="text-xs font-medium uppercase tracking-[0.16em] text-slate-500">
            or
          </span>
          <div className="h-px flex-1 bg-slate-200" />
        </div>

        <div className="space-y-3">
          {oauthProviders.map((provider) => (
            <button
              key={provider.key}
              type="button"
              onClick={() => startOAuth(provider.key)}
              className="h-11 w-full rounded border border-slate-200 bg-white px-4 text-sm font-semibold text-slate-800 transition hover:border-emerald-500 hover:text-emerald-700"
            >
              {provider.label}
            </button>
          ))}
        </div>
        </>
        ) : null}
      </div>
    </div>
  );
}
