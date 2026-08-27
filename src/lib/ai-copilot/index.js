import "server-only";

import crypto from "node:crypto";
import { and, desc, eq, gte, isNull, lte } from "drizzle-orm";
import { db } from "../../db/client.js";
import {
  aiAnalysisReports,
  aiFeedback,
  aiMessages,
  aiSessions,
  alerts,
  automationRuns,
  correlationEvents,
  detectionFindings,
  enforcementEvents,
  evidenceItems,
  firewallInstances,
  incidents,
  notificationDeliveries,
  policyDecisions,
  responseActions,
  securityEvents,
  threatMatches,
} from "../../db/schema.js";
import { AUDIT_EVENT_TYPES, createAuditEvent } from "../audit/index.js";

export const AI_PROVIDER_KEYS = Object.freeze({
  LOCAL_ADVISORY: "local_advisory",
  OPENAI: "openai",
  AZURE_OPENAI: "azure_openai",
  LOCAL_MODEL: "local_model",
  PRIVATE_ENTERPRISE: "private_enterprise",
});

const REPORT_TYPES = ["executive", "analyst", "compliance", "incident_summary", "customer_security"];
const SESSION_STATUSES = ["active", "archived", "deleted"];
const FEEDBACK_RATINGS = ["helpful", "not_helpful", "unsafe", "incorrect", "needs_detail"];
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;
const MAX_CONTEXT_ITEMS = 20;
const MAX_CONTEXT_DAYS = 30;
const SENSITIVE_KEY = /password|secret|token|credential|authorization|cookie|session|private[_-]?key|api[_-]?key|body|payload|webhook|dsn/i;
const UNSAFE_PROMPT = /ignore previous|system prompt|developer message|print.*secret|show.*token|reveal.*credential|bypass approval|execute playbook|block traffic|disable credential|modify policy/i;

export class LocalAdvisoryAIProvider {
  constructor({ model = "deterministic-security-analyst-v1" } = {}) {
    this.key = AI_PROVIDER_KEYS.LOCAL_ADVISORY;
    this.model = model;
  }

  async analyze({ prompt = "", context = {}, task = "analysis" } = {}) {
    const summary = summarizeContext(context);
    return {
      provider: this.key,
      model: this.model,
      confidence: confidenceFor(context),
      content: [
        `Scope: ${context.scope?.organizationId || "tenant"} over ${context.scope?.since || "recent"} to ${context.scope?.until || "now"}.`,
        summary,
        recommendationText(context, task, prompt),
        "Authority boundary: advisory only; SOAR approval workflows control execution.",
      ].join("\n\n"),
      findings: findingsFor(context),
      recommendations: recommendationsFor(context),
      evidenceRefs: evidenceRefsFor(context),
    };
  }

  async summarize(args = {}) {
    return this.analyze({ ...args, task: "summary" });
  }

  async explain(args = {}) {
    return this.analyze({ ...args, task: "explanation" });
  }

  async generateReport(args = {}) {
    return this.analyze({ ...args, task: "report" });
  }
}

export function createAIProvider(config = {}) {
  const provider = config.provider || AI_PROVIDER_KEYS.LOCAL_ADVISORY;
  if (provider !== AI_PROVIDER_KEYS.LOCAL_ADVISORY) {
    return {
      key: provider,
      model: config.model || "not-configured",
      async analyze() {
        throw new Error("AI provider is not configured");
      },
      async summarize() {
        throw new Error("AI provider is not configured");
      },
      async explain() {
        throw new Error("AI provider is not configured");
      },
      async generateReport() {
        throw new Error("AI provider is not configured");
      },
    };
  }
  return new LocalAdvisoryAIProvider(config);
}

export async function listAiSessions({ database = db(), organizationId, userId, filters = {} } = {}) {
  const query = await normalizeAiQuery({ database, organizationId, filters });
  const predicates = [eq(aiSessions.organizationId, organizationId), isNull(aiSessions.deletedAt)];
  if (query.status) predicates.push(eq(aiSessions.status, query.status));
  if (query.firewallInstanceId) predicates.push(eq(aiSessions.firewallInstanceId, query.firewallInstanceId));
  if (filters.mine === "true" && userId) predicates.push(eq(aiSessions.userId, userId));

  const rows = await database.select().from(aiSessions).where(and(...predicates)).orderBy(desc(aiSessions.updatedAt)).limit(query.limit);
  return { items: rows.map(presentSession), pageInfo: { limit: query.limit, hasMore: rows.length === query.limit } };
}

export async function createAiSession({ database = db(), organizationId, userId, input = {}, auditContext = {} } = {}) {
  const firewallInstanceId = cleanString(input.firewallInstanceId, 160);
  if (firewallInstanceId) await validateFirewallOwnership(database, organizationId, firewallInstanceId);
  const [row] = await database
    .insert(aiSessions)
    .values({
      organizationId,
      userId,
      firewallInstanceId,
      title: cleanString(input.title, 200) || "Security Copilot Session",
      status: "active",
      purpose: cleanString(input.purpose, 80) || "security_analysis",
      metadata: sanitizeAiContext(input.metadata || {}),
    })
    .returning();
  await auditAi({ database, organizationId, userId, firewallInstanceId, eventType: AUDIT_EVENT_TYPES.AI_SESSION_CREATED, action: "ai.session.create", resourceType: "ai_session", resourceId: row.id, requestId: auditContext.requestId });
  return presentSession(row);
}

export async function listAiMessages({ database = db(), organizationId, filters = {} } = {}) {
  const sessionId = requiredString(filters.sessionId, "sessionId", 160);
  await requireAiSession(database, organizationId, sessionId);
  const rows = await database
    .select()
    .from(aiMessages)
    .where(and(eq(aiMessages.organizationId, organizationId), eq(aiMessages.sessionId, sessionId)))
    .orderBy(aiMessages.createdAt)
    .limit(limitValue(filters.limit, MAX_LIMIT));
  return { items: rows.map(presentMessage), pageInfo: { limit: limitValue(filters.limit, MAX_LIMIT), hasMore: rows.length === limitValue(filters.limit, MAX_LIMIT) } };
}

export async function createAiMessage({ database = db(), organizationId, userId, input = {}, auditContext = {} } = {}) {
  const session = await requireAiSession(database, organizationId, requiredString(input.sessionId, "sessionId", 160));
  const prompt = requiredString(input.content || input.prompt, "content", 8000);
  const guardrail = evaluateAiGuardrails({ prompt, operation: "message" });
  const context = guardrail.allowed
    ? await buildSecurityContext({ database, organizationId, filters: { ...input.context, firewallInstanceId: input.firewallInstanceId || session.firewallInstanceId } })
    : { scope: { organizationId, blocked: true }, evidenceRefs: [] };
  const provider = createAIProvider(input.providerConfig || {});

  const [userMessage] = await database.insert(aiMessages).values({
    organizationId,
    sessionId: session.id,
    userId,
    role: "user",
    content: redactText(prompt),
    sanitizedContext: sanitizeAiContext(input.context || {}),
    evidenceRefs: [],
    guardrailResult: sanitizeAiContext(guardrail),
    confidence: 1,
  }).returning();

  const answer = guardrail.allowed
    ? await provider.analyze({ prompt, context, task: "conversation" })
    : blockedAnswer(guardrail);

  const [assistantMessage] = await database.insert(aiMessages).values({
    organizationId,
    sessionId: session.id,
    userId: null,
    role: "assistant",
    content: redactText(answer.content),
    sanitizedContext: sanitizeAiContext({ scope: context.scope, totals: context.totals }),
    evidenceRefs: sanitizeAiContext(answer.evidenceRefs || []),
    guardrailResult: sanitizeAiContext(guardrail),
    provider: answer.provider || provider.key,
    model: answer.model || provider.model,
    confidence: numeric(answer.confidence, 0, 1, 0.6),
  }).returning();

  await database.update(aiSessions).set({ lastMessageAt: new Date(), updatedAt: new Date() }).where(eq(aiSessions.id, session.id));
  await auditAi({ database, organizationId, userId, firewallInstanceId: session.firewallInstanceId, eventType: AUDIT_EVENT_TYPES.AI_QUERY_EXECUTED, action: "ai.message.create", resourceType: "ai_message", resourceId: assistantMessage.id, requestId: auditContext.requestId, metadata: { allowed: guardrail.allowed, evidenceRefs: (answer.evidenceRefs || []).length } });
  return { userMessage: presentMessage(userMessage), assistantMessage: presentMessage(assistantMessage) };
}

export async function explainSecurityContext({ database = db(), organizationId, userId, input = {}, auditContext = {} } = {}) {
  const guardrail = evaluateAiGuardrails({ prompt: input.prompt || input.question || "Explain security context", operation: "explain" });
  if (!guardrail.allowed) return blockedAnswer(guardrail);
  const context = await buildSecurityContext({ database, organizationId, filters: input });
  const provider = createAIProvider(input.providerConfig || {});
  const response = await provider.explain({ prompt: input.prompt || "", context });
  await auditAi({ database, organizationId, userId, firewallInstanceId: context.scope.firewallInstanceId, eventType: AUDIT_EVENT_TYPES.AI_QUERY_EXECUTED, action: "ai.explain", resourceType: "ai_context", requestId: auditContext.requestId, metadata: { evidenceRefs: response.evidenceRefs.length } });
  return response;
}

export async function buildSecurityContext({ database = db(), organizationId, filters = {} } = {}) {
  const query = await normalizeAiQuery({ database, organizationId, filters, includeWindow: true });
  const securityEventPredicates = [eq(securityEvents.organizationId, organizationId), gte(securityEvents.occurredAt, query.since), lte(securityEvents.occurredAt, query.until)];
  const scopedPredicates = (table, timeColumn = table.createdAt) => {
    const predicates = [eq(table.organizationId, organizationId), gte(timeColumn, query.since), lte(timeColumn, query.until)];
    if (query.firewallInstanceId && table.firewallInstanceId) predicates.push(eq(table.firewallInstanceId, query.firewallInstanceId));
    return predicates;
  };
  if (query.firewallInstanceId) securityEventPredicates.push(eq(securityEvents.firewallInstanceId, query.firewallInstanceId));

  const [
    eventRows,
    findingRows,
    matchRows,
    decisionRows,
    enforcementRows,
    runRows,
    incidentRows,
    evidenceRows,
    deliveryRows,
  ] = await Promise.all([
    database.select().from(securityEvents).where(and(...securityEventPredicates)).orderBy(desc(securityEvents.occurredAt)).limit(query.limit),
    database.select().from(detectionFindings).where(and(...scopedPredicates(detectionFindings, detectionFindings.lastSeenAt))).orderBy(desc(detectionFindings.lastSeenAt)).limit(query.limit),
    database.select().from(threatMatches).where(and(...scopedPredicates(threatMatches, threatMatches.matchedAt))).orderBy(desc(threatMatches.matchedAt)).limit(query.limit),
    database.select().from(policyDecisions).where(and(...scopedPredicates(policyDecisions, policyDecisions.evaluatedAt))).orderBy(desc(policyDecisions.evaluatedAt)).limit(query.limit),
    database.select().from(enforcementEvents).where(and(...scopedPredicates(enforcementEvents, enforcementEvents.createdAt))).orderBy(desc(enforcementEvents.createdAt)).limit(query.limit),
    database.select().from(automationRuns).where(and(...scopedPredicates(automationRuns, automationRuns.startedAt))).orderBy(desc(automationRuns.startedAt)).limit(query.limit),
    database.select().from(incidents).where(and(...scopedPredicates(incidents, incidents.lastSeenAt))).orderBy(desc(incidents.lastSeenAt)).limit(query.limit),
    database.select().from(evidenceItems).where(and(...scopedPredicates(evidenceItems, evidenceItems.occurredAt), isNull(evidenceItems.deletedAt))).orderBy(desc(evidenceItems.occurredAt)).limit(query.limit),
    database.select().from(notificationDeliveries).where(and(eq(notificationDeliveries.organizationId, organizationId), gte(notificationDeliveries.createdAt, query.since), lte(notificationDeliveries.createdAt, query.until))).orderBy(desc(notificationDeliveries.createdAt)).limit(query.limit),
  ]);

  const context = sanitizeAiContext({
    scope: {
      organizationId,
      firewallInstanceId: query.firewallInstanceId,
      since: query.since.toISOString(),
      until: query.until.toISOString(),
      limit: query.limit,
    },
    totals: {
      securityEvents: eventRows.length,
      detectionFindings: findingRows.length,
      threatMatches: matchRows.length,
      policyDecisions: decisionRows.length,
      enforcementEvents: enforcementRows.length,
      automationRuns: runRows.length,
      incidents: incidentRows.length,
      evidenceItems: evidenceRows.length,
      notificationDeliveries: deliveryRows.length,
    },
    securityEvents: eventRows.map(eventSummary),
    detectionFindings: findingRows.map(findingSummary),
    threatMatches: matchRows.map(matchSummary),
    policyDecisions: decisionRows.map(decisionSummary),
    enforcementEvents: enforcementRows.map(enforcementSummary),
    automationRuns: runRows.map(runSummary),
    incidents: incidentRows.map(incidentSummary),
    evidenceItems: evidenceRows.map(evidenceSummary),
    notificationDeliveries: deliveryRows.map(deliverySummary),
  });
  return { ...context, evidenceRefs: evidenceRefsFor(context) };
}

export async function listAiReports({ database = db(), organizationId, filters = {} } = {}) {
  const query = await normalizeAiQuery({ database, organizationId, filters, includeWindow: true });
  const predicates = [eq(aiAnalysisReports.organizationId, organizationId), gte(aiAnalysisReports.generatedAt, query.since), lte(aiAnalysisReports.generatedAt, query.until)];
  if (query.firewallInstanceId) predicates.push(eq(aiAnalysisReports.firewallInstanceId, query.firewallInstanceId));
  if (query.reportType) predicates.push(eq(aiAnalysisReports.reportType, query.reportType));
  const rows = await database.select().from(aiAnalysisReports).where(and(...predicates)).orderBy(desc(aiAnalysisReports.generatedAt)).limit(query.limit);
  return { items: rows.map(presentReport), pageInfo: { limit: query.limit, hasMore: rows.length === query.limit } };
}

export async function generateAiReport({ database = db(), organizationId, userId, input = {}, auditContext = {} } = {}) {
  const reportType = enumValue(input.reportType || "analyst", REPORT_TYPES, "report type");
  const sessionId = cleanString(input.sessionId, 160);
  const incidentId = cleanString(input.incidentId, 160);
  if (sessionId) await requireAiSession(database, organizationId, sessionId);
  if (incidentId) await requireIncident(database, organizationId, incidentId);
  const context = await buildSecurityContext({ database, organizationId, filters: input });
  const provider = createAIProvider(input.providerConfig || {});
  const response = await provider.generateReport({ prompt: input.prompt || reportType, context });
  const [row] = await database.insert(aiAnalysisReports).values({
    organizationId,
    userId,
    sessionId,
    incidentId,
    firewallInstanceId: context.scope.firewallInstanceId || null,
    reportType,
    title: cleanString(input.title, 240) || titleForReport(reportType),
    summary: redactText(response.content),
    findings: sanitizeAiContext(response.findings || []),
    recommendations: sanitizeAiContext(response.recommendations || []),
    evidenceRefs: sanitizeAiContext(response.evidenceRefs || []),
    guardrailResult: sanitizeAiContext({ allowed: true, advisoryOnly: true }),
    provider: response.provider,
    model: response.model,
    confidence: numeric(response.confidence, 0, 1, 0.6),
    metadata: sanitizeAiContext({ generatedBy: "ai-copilot", advisoryOnly: true }),
  }).returning();
  await auditAi({ database, organizationId, userId, firewallInstanceId: row.firewallInstanceId, eventType: AUDIT_EVENT_TYPES.AI_REPORT_GENERATED, action: "ai.report.generate", resourceType: "ai_analysis_report", resourceId: row.id, requestId: auditContext.requestId, metadata: { reportType, evidenceRefs: (response.evidenceRefs || []).length } });
  return presentReport(row);
}

export async function submitAiFeedback({ database = db(), organizationId, userId, input = {}, auditContext = {} } = {}) {
  const messageId = cleanString(input.messageId, 160);
  const reportId = cleanString(input.reportId, 160);
  if (!messageId && !reportId) throw new Error("messageId or reportId is required");
  if (messageId) await requireAiMessage(database, organizationId, messageId);
  if (reportId) await requireAiReport(database, organizationId, reportId);
  const [row] = await database.insert(aiFeedback).values({
    organizationId,
    messageId,
    reportId,
    userId,
    rating: enumValue(input.rating, FEEDBACK_RATINGS, "rating"),
    feedback: cleanString(input.feedback, 2000),
    metadata: sanitizeAiContext(input.metadata || {}),
  }).returning();
  await auditAi({ database, organizationId, userId, eventType: AUDIT_EVENT_TYPES.AI_FEEDBACK_SUBMITTED, action: "ai.feedback.submit", resourceType: "ai_feedback", resourceId: row.id, requestId: auditContext.requestId, metadata: { rating: row.rating } });
  return presentFeedback(row);
}

export function evaluateAiGuardrails({ prompt = "", operation = "message" } = {}) {
  const text = String(prompt || "");
  const reasons = [];
  if (UNSAFE_PROMPT.test(text)) reasons.push("unsafe_or_out_of_authority_request");
  if (text.length > 8000) reasons.push("prompt_too_large");
  return {
    allowed: reasons.length === 0,
    reasons,
    operation,
    advisoryOnly: true,
    canExecuteActions: false,
    canModifyPolicy: false,
  };
}

export function sanitizeAiContext(value, depth = 0) {
  if (value == null) return value;
  if (depth > 4) return "[truncated]";
  if (Array.isArray(value)) return value.slice(0, MAX_CONTEXT_ITEMS).map((item) => sanitizeAiContext(item, depth + 1));
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .slice(0, 120)
        .filter(([key]) => !SENSITIVE_KEY.test(key))
        .map(([key, child]) => [cleanString(key, 80), sanitizeAiContext(child, depth + 1)]),
    );
  }
  if (typeof value === "string") return redactText(value);
  if (typeof value === "number") return Number.isFinite(value) ? value : 0;
  if (typeof value === "boolean") return value;
  return String(value);
}

function blockedAnswer(guardrail) {
  return {
    provider: AI_PROVIDER_KEYS.LOCAL_ADVISORY,
    model: "guardrail",
    confidence: 1,
    content: "The request was blocked by AI safety guardrails. I can summarize, explain, or recommend approval-gated actions, but I cannot expose secrets, bypass approvals, execute playbooks, or modify policies.",
    findings: [],
    recommendations: [{ title: "Reframe request", action: "ask_for_summary_or_recommendation", approvalRequired: false }],
    evidenceRefs: [],
    guardrail,
  };
}

async function normalizeAiQuery({ database, organizationId, filters = {}, includeWindow = false }) {
  const firewallInstanceId = cleanString(filters.firewallInstanceId, 160);
  if (firewallInstanceId) await validateFirewallOwnership(database, organizationId, firewallInstanceId);
  const until = includeWindow ? parseDate(filters.until) || new Date() : null;
  const since = includeWindow ? parseDate(filters.since) || new Date(until.getTime() - 24 * 60 * 60 * 1000) : null;
  if (includeWindow && until.getTime() - since.getTime() > MAX_CONTEXT_DAYS * 24 * 60 * 60 * 1000) {
    throw new Error("AI context window is limited to 30 days");
  }
  return {
    firewallInstanceId,
    reportType: filters.reportType ? enumValue(filters.reportType, REPORT_TYPES, "report type") : null,
    status: filters.status ? enumValue(filters.status, SESSION_STATUSES, "session status") : null,
    since,
    until,
    limit: limitValue(filters.limit, MAX_LIMIT),
  };
}

async function validateFirewallOwnership(database, organizationId, firewallInstanceId) {
  const [firewall] = await database.select({ id: firewallInstances.id }).from(firewallInstances).where(and(eq(firewallInstances.id, firewallInstanceId), eq(firewallInstances.organizationId, organizationId), isNull(firewallInstances.deletedAt))).limit(1);
  if (!firewall) throw new Error("firewall instance is not available for this organization");
  return firewall;
}

async function requireAiSession(database, organizationId, sessionId) {
  const [row] = await database.select().from(aiSessions).where(and(eq(aiSessions.id, sessionId), eq(aiSessions.organizationId, organizationId), isNull(aiSessions.deletedAt))).limit(1);
  if (!row) throw new Error("AI session not found");
  return row;
}

async function requireAiMessage(database, organizationId, messageId) {
  const [row] = await database.select({ id: aiMessages.id }).from(aiMessages).where(and(eq(aiMessages.id, messageId), eq(aiMessages.organizationId, organizationId))).limit(1);
  if (!row) throw new Error("AI message not found");
  return row;
}

async function requireAiReport(database, organizationId, reportId) {
  const [row] = await database.select({ id: aiAnalysisReports.id }).from(aiAnalysisReports).where(and(eq(aiAnalysisReports.id, reportId), eq(aiAnalysisReports.organizationId, organizationId))).limit(1);
  if (!row) throw new Error("AI report not found");
  return row;
}

async function requireIncident(database, organizationId, incidentId) {
  const [row] = await database.select({ id: incidents.id }).from(incidents).where(and(eq(incidents.id, incidentId), eq(incidents.organizationId, organizationId))).limit(1);
  if (!row) throw new Error("incident not found");
  return row;
}

function summarizeContext(context = {}) {
  const totals = context.totals || {};
  const incidentsCount = Number(totals.incidents || 0);
  const decisionsCount = Number(totals.policyDecisions || 0);
  const automationCount = Number(totals.automationRuns || 0);
  return `Observed ${totals.securityEvents || 0} events, ${totals.detectionFindings || 0} findings, ${totals.threatMatches || 0} intelligence matches, ${decisionsCount} policy decisions, ${automationCount} SOAR runs, and ${incidentsCount} incidents in scope.`;
}

function findingsFor(context = {}) {
  const findings = [];
  for (const incident of context.incidents || []) findings.push({ type: "incident", id: incident.id, severity: incident.severity, summary: incident.title });
  for (const event of context.securityEvents || []) findings.push({ type: "security_event", id: event.id, severity: event.severity, summary: `${event.attackType || event.eventType} on ${event.requestPath || "unknown route"}` });
  for (const decision of context.policyDecisions || []) findings.push({ type: "policy_decision", id: decision.id, severity: severityFromScore(decision.riskScore), summary: `${decision.decision} decision at score ${decision.riskScore}` });
  return findings.slice(0, 12);
}

function recommendationsFor(context = {}) {
  const recommendations = [];
  if ((context.incidents || []).some((item) => item.severity === "critical")) {
    recommendations.push({ title: "Review critical incidents", action: "open_incident_review", approvalRequired: false });
  }
  if ((context.policyDecisions || []).some((item) => ["block", "quarantine"].includes(item.decision))) {
    recommendations.push({ title: "Verify enforcement outcome", action: "review_enforcement_events", approvalRequired: false });
  }
  if ((context.automationRuns || []).some((item) => item.approvalState === "pending")) {
    recommendations.push({ title: "Review pending SOAR approvals", action: "review_soar_actions", approvalRequired: true });
  }
  recommendations.push({ title: "Preserve evidence references", action: "collect_sanitized_evidence", approvalRequired: false });
  return recommendations.slice(0, 8);
}

function recommendationText(context, task) {
  const recommendations = recommendationsFor(context);
  const lines = recommendations.map((item) => `- ${item.title}: ${item.action}${item.approvalRequired ? " (approval required)" : ""}`);
  return `${task === "report" ? "Report recommendations" : "Recommended next steps"}:\n${lines.join("\n")}`;
}

function evidenceRefsFor(context = {}) {
  return [
    ...(context.securityEvents || []).map((item) => ref("security_event", item.id)),
    ...(context.detectionFindings || []).map((item) => ref("detection_finding", item.id)),
    ...(context.threatMatches || []).map((item) => ref("threat_match", item.id)),
    ...(context.policyDecisions || []).map((item) => ref("policy_decision", item.id)),
    ...(context.enforcementEvents || []).map((item) => ref("enforcement_event", item.id)),
    ...(context.automationRuns || []).map((item) => ref("automation_run", item.id)),
    ...(context.incidents || []).map((item) => ref("incident", item.id)),
    ...(context.evidenceItems || []).map((item) => ref("evidence_item", item.id)),
    ...(context.notificationDeliveries || []).map((item) => ref("notification_delivery", item.id)),
  ].filter((item) => item.id).slice(0, 50);
}

function ref(type, id) {
  return { type, id };
}

function confidenceFor(context = {}) {
  const count = Object.values(context.totals || {}).reduce((sum, value) => sum + Number(value || 0), 0);
  return Math.max(0.45, Math.min(0.9, Math.round((0.5 + Math.min(count, 20) / 50) * 100) / 100));
}

function eventSummary(row) {
  return pick(row, ["id", "firewallInstanceId", "eventType", "attackType", "severity", "requestPath", "httpMethod", "confidence", "detectorId", "detectorIds", "score", "anomalyType", "actionTaken", "occurredAt"]);
}

function findingSummary(row) {
  return pick(row, ["id", "firewallInstanceId", "securityEventId", "findingType", "detectorId", "severity", "confidence", "riskScore", "status", "firstSeenAt", "lastSeenAt", "eventCount"]);
}

function matchSummary(row) {
  return pick(row, ["id", "firewallInstanceId", "securityEventId", "indicatorId", "indicatorType", "matchContext", "riskDelta", "confidenceDelta", "matchedAt"]);
}

function decisionSummary(row) {
  return pick(row, ["id", "firewallInstanceId", "securityEventId", "policyId", "policyVersionId", "decision", "decisionReason", "mode", "riskScore", "confidence", "evaluatedAt"]);
}

function enforcementSummary(row) {
  return pick(row, ["id", "firewallInstanceId", "policyDecisionId", "incidentId", "action", "mode", "outcome", "reason", "riskScore", "confidence", "createdAt"]);
}

function runSummary(row) {
  return pick(row, ["id", "firewallInstanceId", "playbookId", "incidentId", "triggerType", "status", "automationLevel", "approvalState", "resultSummary", "startedAt", "completedAt"]);
}

function incidentSummary(row) {
  return pick(row, ["id", "firewallInstanceId", "title", "severity", "status", "firstSeenAt", "lastSeenAt"]);
}

function evidenceSummary(row) {
  return pick(row, ["id", "firewallInstanceId", "investigationCaseId", "incidentId", "automationRunId", "sourceType", "sourceRefId", "evidenceType", "evidenceHash", "occurredAt"]);
}

function deliverySummary(row) {
  return pick(row, ["id", "channelId", "alertId", "incidentId", "eventType", "status", "attemptCount", "responseStatus", "lastErrorCode", "createdAt"]);
}

function pick(row, fields) {
  return Object.fromEntries(fields.map((field) => [field, row?.[field]]));
}

function titleForReport(type) {
  return `${type.replaceAll("_", " ")} report`.replace(/\b\w/g, (char) => char.toUpperCase());
}

function severityFromScore(score) {
  const value = Number(score || 0);
  if (value >= 90) return "critical";
  if (value >= 70) return "high";
  if (value >= 40) return "medium";
  return "low";
}

async function auditAi({ database, organizationId, userId, firewallInstanceId, eventType, action, resourceType, resourceId, requestId, metadata = {} }) {
  return createAuditEvent({
    database,
    organizationId,
    userId,
    firewallInstanceId,
    eventType,
    action,
    resourceType,
    resourceId,
    result: "success",
    severity: "info",
    requestId,
    metadata: sanitizeAiContext(metadata),
  });
}

function presentSession(row = {}) {
  return {
    id: row.id,
    title: row.title,
    status: row.status,
    purpose: row.purpose,
    firewallInstanceId: row.firewallInstanceId,
    lastMessageAt: row.lastMessageAt,
    updatedAt: row.updatedAt,
    createdAt: row.createdAt,
  };
}

function presentMessage(row = {}) {
  return {
    id: row.id,
    sessionId: row.sessionId,
    role: row.role,
    content: row.content,
    evidenceRefs: row.evidenceRefs || [],
    guardrailResult: row.guardrailResult || {},
    provider: row.provider,
    model: row.model,
    confidence: row.confidence,
    createdAt: row.createdAt,
  };
}

function presentReport(row = {}) {
  return {
    id: row.id,
    sessionId: row.sessionId,
    incidentId: row.incidentId,
    firewallInstanceId: row.firewallInstanceId,
    reportType: row.reportType,
    title: row.title,
    summary: row.summary,
    findings: row.findings || [],
    recommendations: row.recommendations || [],
    evidenceRefs: row.evidenceRefs || [],
    provider: row.provider,
    model: row.model,
    confidence: row.confidence,
    generatedAt: row.generatedAt,
  };
}

function presentFeedback(row = {}) {
  return {
    id: row.id,
    messageId: row.messageId,
    reportId: row.reportId,
    rating: row.rating,
    createdAt: row.createdAt,
  };
}

function enumValue(value, allowed, label) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!allowed.includes(normalized)) throw new Error(`${label} is invalid`);
  return normalized;
}

function requiredString(value, label, maxLength) {
  const text = cleanString(value, maxLength);
  if (!text) throw new Error(`${label} is required`);
  return text;
}

function cleanString(value, maxLength) {
  if (value === null || value === undefined) return "";
  return String(value).replace(/[^\x20-\x7E]/g, "").trim().slice(0, maxLength);
}

function redactText(value) {
  return cleanString(value, 12000).replace(/(bearer|token|secret|password|api[_-]?key)\s+[-A-Za-z0-9._~+/=]{8,}/gi, "$1 [redacted]");
}

function limitValue(value, max) {
  const number = Number(value || DEFAULT_LIMIT);
  if (!Number.isFinite(number)) return DEFAULT_LIMIT;
  return Math.max(1, Math.min(max, Math.floor(number)));
}

function parseDate(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function numeric(value, min, max, fallback) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.max(min, Math.min(max, number));
}
