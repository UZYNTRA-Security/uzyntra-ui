"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import PageHeader from "@/components/PageHeader";
import SectionCard from "@/components/SectionCard";
import MetricCard from "@/components/MetricCard";

const starterPrompt = "Summarize the most important security activity and recommend next analyst steps.";

export default function SecurityCopilotPage() {
  const [sessions, setSessions] = useState([]);
  const [sessionId, setSessionId] = useState("");
  const [messages, setMessages] = useState([]);
  const [prompt, setPrompt] = useState(starterPrompt);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function load() {
    setError("");
    try {
      const res = await api.getAiSessions({ limit: 20, mine: true });
      const items = res.data.items || [];
      setSessions(items);
      if (!sessionId && items[0]?.id) {
        setSessionId(items[0].id);
        const messageRes = await api.getAiMessages({ sessionId: items[0].id });
        setMessages(messageRes.data.items || []);
      }
    } catch (err) {
      setError(err.message || "Failed to load copilot");
    }
  }

  async function send() {
    setLoading(true);
    setError("");
    try {
      let activeSessionId = sessionId;
      if (!activeSessionId) {
        const created = await api.createAiSession({ title: "Security Copilot" });
        activeSessionId = created.data.id;
        setSessionId(activeSessionId);
      }
      const res = await api.createAiMessage({ sessionId: activeSessionId, content: prompt });
      setMessages((current) => [...current, res.data.userMessage, res.data.assistantMessage]);
      setPrompt("");
      load();
    } catch (err) {
      setError(err.message || "Copilot request failed");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Security Copilot"
        subtitle="Advisory analyst assistant for explanations, summaries, recommendations, and evidence-backed triage"
        actions={<button className="btn-primary" onClick={load}>Refresh</button>}
      />
      {error ? <ErrorBanner message={error} /> : null}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
        <MetricCard title="Sessions" value={sessions.length} hint="Tenant-scoped analyst sessions" />
        <MetricCard title="Messages" value={messages.length} hint="Current conversation" />
        <MetricCard title="Authority" value="Advisory" hint="SOAR controls execution" />
      </div>
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[320px_minmax(0,1fr)]">
        <SectionCard title="History">
          <div className="space-y-2">
            {sessions.map((session) => (
              <button
                key={session.id}
                className={`w-full rounded-xl border px-3 py-2 text-left text-sm ${session.id === sessionId ? "border-emerald-300 bg-emerald-50 text-emerald-900" : "border-slate-200 bg-white text-slate-700"}`}
                onClick={async () => {
                  setSessionId(session.id);
                  const res = await api.getAiMessages({ sessionId: session.id });
                  setMessages(res.data.items || []);
                }}
              >
                <span className="block font-semibold">{session.title}</span>
                <span className="text-xs text-slate-500">{formatDate(session.updatedAt)}</span>
              </button>
            ))}
          </div>
        </SectionCard>
        <SectionCard title="Analyst Chat">
          <div className="space-y-4">
            <div className="max-h-[420px] space-y-3 overflow-auto rounded-xl border border-slate-200 bg-slate-50 p-4">
              {messages.length ? messages.map((message) => (
                <div key={message.id} className={`rounded-xl p-3 text-sm ${message.role === "assistant" ? "bg-white text-slate-800" : "bg-slate-900 text-white"}`}>
                  <p className="mb-1 text-xs uppercase tracking-wide opacity-60">{message.role}</p>
                  <p className="whitespace-pre-wrap">{message.content}</p>
                </div>
              )) : <p className="text-sm text-slate-500">No messages yet</p>}
            </div>
            <textarea
              className="min-h-28 w-full rounded-xl border border-slate-200 p-3 text-sm outline-none focus:border-emerald-400"
              value={prompt}
              onChange={(event) => setPrompt(event.target.value)}
            />
            <button className="btn-primary" onClick={send} disabled={loading || !prompt.trim()}>
              {loading ? "Analyzing..." : "Ask Copilot"}
            </button>
          </div>
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
