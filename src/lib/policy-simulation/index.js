import "server-only";

import { and, desc, eq, gte, isNull, lte } from "drizzle-orm";
import { db } from "../../db/client.js";
import {
  enforcementEvents,
  firewallInstances,
  policyChangeRequests,
  policyDecisions,
  policySimulations,
  policyTestCases,
  protectionAllowlists,
  protectionBlocklists,
  protectionRules,
  rateLimitPolicies,
  securityEvents,
  simulationResults,
  zeroTrustPolicies,
  zeroTrustPolicyVersions,
} from "../../db/schema.js";
import { AUDIT_EVENT_TYPES, createAuditEvent } from "../audit/index.js";
import {
  ZERO_TRUST_DECISIONS,
  ZERO_TRUST_MODES,
  buildZeroTrustEvaluationContext,
  evaluateZeroTrustPolicy,
  normalizePolicySnapshot,
} from "../zero-trust/index.js";
import {
  PROTECTION_ACTIONS,
  PROTECTION_MODES,
  evaluateAdaptiveProtection,
} from "../adaptive-protection/index.js";

export const POLICY_SIMULATION_MODES = Object.freeze({
  DRY_RUN: "dry_run",
  SHADOW: "shadow",
  WHAT_IF: "what_if",
  HISTORICAL_REPLAY: "historical_replay",
});

export const POLICY_CHANGE_REQUEST_STATUSES = Object.freeze({
  DRAFT: "draft",
  REQUESTED: "requested",
  APPROVED: "approved",
  REJECTED: "rejected",
  EXPIRED: "expired",
  CANCELLED: "cancelled",
});

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;
const MAX_REPLAY_EVENTS = 100;
const MAX_CONTEXT_KEYS = 80;
const MAX_CONTEXT_STRING = 512;
const SENSITIVE_KEY = /password|secret|token|credential|authorization|cookie|session|private[_-]?key|api[_-]?key|body|payload|query/i;

export async function runPolicySimulation({
  database = db(),
  organizationId,
  userId,
  input = {},
  auditContext = {},
} = {}) {
  const values = await normalizeSimulationInput({ database, organizationId, input });
  const replayEvents = await loadReplayEvents({ database, organizationId, values });
  const targets = replayEvents.length ? replayEvents : [{ context: values.context }];
  const results = [];

  const [simulation] = await database
    .insert(policySimulations)
    .values({
      organizationId,
      firewallInstanceId: values.firewallInstanceId,
      policyId: values.policy?.id || null,
      policyVersionId: values.policyVersion?.id || null,
      sourceSecurityEventId: values.sourceSecurityEventId,
      sourcePolicyDecisionId: values.sourcePolicyDecisionId,
      sourceEnforcementEventId: values.sourceEnforcementEventId,
      mode: values.mode,
      status: "running",
      inputContext: sanitizeContext(values.context),
      simulationConfig: sanitizeContext(values.config),
      createdByUserId: userId || null,
      startedAt: new Date(),
    })
    .returning();

  try {
    for (const target of targets.slice(0, MAX_REPLAY_EVENTS)) {
      const result = evaluatePolicySimulation({
        policy: values.policy,
        policyVersion: values.policyVersion,
        policySnapshot: values.policySnapshot,
        context: target.context,
        protectionRules: values.protectionRules,
        allowlist: values.allowlist,
        blocklist: values.blocklist,
        rateLimitPolicy: values.rateLimitPolicy,
        credentialState: values.credentialState,
        actualAction: target.actualAction,
        mode: values.mode,
      });
      results.push({ ...result, sourceSecurityEventId: target.securityEventId || null });
    }

    const impact = summarizeImpact(results);
    const [updated] = await database
      .update(policySimulations)
      .set({
        status: "completed",
        completedAt: new Date(),
        impactSummary: impact,
        summary: impact.summary,
        updatedAt: new Date(),
      })
      .where(eq(policySimulations.id, simulation.id))
      .returning();

    const rows = await database
      .insert(simulationResults)
      .values(results.map((result) => resultRow({ organizationId, simulationId: simulation.id, result, values })))
      .returning();

    await auditPolicySimulation({
      database,
      organizationId,
      userId,
      firewallInstanceId: values.firewallInstanceId,
      eventType: AUDIT_EVENT_TYPES.POLICY_SIMULATION_RUN,
      action: "policy_simulation.run",
      resourceId: simulation.id,
      requestId: auditContext.requestId,
      metadata: { mode: values.mode, resultCount: rows.length, highImpact: impact.highImpact },
    });

    return presentSimulation({ ...updated, results: rows.map(presentSimulationResult) });
  } catch (error) {
    await database
      .update(policySimulations)
      .set({ status: "failed", errorMessage: cleanString(error.message, 2000), completedAt: new Date(), updatedAt: new Date() })
      .where(eq(policySimulations.id, simulation.id));
    throw error;
  }
}

export function evaluatePolicySimulation({
  policy = null,
  policyVersion = null,
  policySnapshot = null,
  context = {},
  protectionRules = [],
  allowlist = [],
  blocklist = [],
  credentialState = null,
  rateLimitPolicy = null,
  actualAction = null,
  mode = POLICY_SIMULATION_MODES.DRY_RUN,
} = {}) {
  const evaluationContext = buildZeroTrustEvaluationContext(context);
  const snapshot = normalizePolicySnapshot(policySnapshot || policyVersion?.policySnapshot || {});
  const zeroTrust = evaluateZeroTrustPolicy({
    policy: {
      id: policy?.id || null,
      organizationId: policy?.organizationId || evaluationContext.organizationId,
      firewallInstanceId: policy?.firewallInstanceId || evaluationContext.firewallInstanceId,
      mode: ZERO_TRUST_MODES.SIMULATE,
      failBehavior: policy?.failBehavior || "fail_open",
    },
    policyVersion: {
      id: policyVersion?.id || null,
      policySnapshot: snapshot,
    },
    context: evaluationContext,
    modeOverride: ZERO_TRUST_MODES.SIMULATE,
  });

  const adaptive = evaluateAdaptiveProtection({
    policyDecision: {
      id: "simulated-policy-decision",
      organizationId: zeroTrust.organizationId,
      firewallInstanceId: zeroTrust.firewallInstanceId,
      policyId: zeroTrust.policyId,
      policyVersionId: zeroTrust.policyVersionId,
      decision: zeroTrust.decision,
      decisionReason: zeroTrust.decisionReason,
      riskScore: zeroTrust.riskScore,
      confidence: zeroTrust.confidence,
      detectorReferences: zeroTrust.detectorReferences,
      threatIntelReferences: zeroTrust.threatIntelReferences,
    },
    context: evaluationContext,
    protectionRules,
    allowlist,
    blocklist,
    credentialState,
    rateLimitPolicy,
    mode: PROTECTION_MODES.SIMULATION,
  });

  const reasonCodes = reasonCodesFor({ zeroTrust, adaptive, context: evaluationContext });
  const falsePositiveRisk = estimateFalsePositiveRisk({ riskScore: zeroTrust.riskScore, confidence: zeroTrust.confidence, action: adaptive.action });

  return {
    mode: normalizeSimulationMode(mode),
    simulated: true,
    enforced: false,
    expectedDecision: zeroTrust.decision,
    expectedAction: adaptive.action,
    effectiveAction: PROTECTION_ACTIONS.ALLOW,
    actualAction: cleanAction(actualAction),
    policyId: zeroTrust.policyId,
    policyVersionId: zeroTrust.policyVersionId,
    matchedPolicyRuleId: zeroTrust.matchedRuleId,
    matchedProtectionRuleId: adaptive.protectionRuleId || null,
    riskScore: zeroTrust.riskScore,
    confidence: zeroTrust.confidence,
    reasonCodes,
    falsePositiveRisk,
    explanation: buildDecisionExplanation({ zeroTrust, adaptive, context: evaluationContext, reasonCodes, falsePositiveRisk }),
  };
}

export async function listPolicySimulations({ database = db(), organizationId, filters = {} } = {}) {
  const query = await normalizeSimulationQuery({ database, organizationId, filters, includeWindow: true });
  const predicates = [
    eq(policySimulations.organizationId, organizationId),
    gte(policySimulations.createdAt, query.since),
    lte(policySimulations.createdAt, query.until),
  ];
  if (query.firewallInstanceId) predicates.push(eq(policySimulations.firewallInstanceId, query.firewallInstanceId));
  if (query.policyId) predicates.push(eq(policySimulations.policyId, query.policyId));
  if (query.mode) predicates.push(eq(policySimulations.mode, query.mode));
  if (query.status) predicates.push(eq(policySimulations.status, query.status));

  const rows = await database
    .select()
    .from(policySimulations)
    .where(and(...predicates))
    .orderBy(desc(policySimulations.createdAt))
    .limit(query.limit);
  return { items: rows.map(presentSimulation), pageInfo: { limit: query.limit, hasMore: rows.length === query.limit } };
}

export async function explainPolicyDecision({ database = db(), organizationId, decisionId } = {}) {
  const id = requiredString(decisionId, "decisionId", 160);
  const [decision] = await database
    .select()
    .from(policyDecisions)
    .where(and(eq(policyDecisions.id, id), eq(policyDecisions.organizationId, organizationId)))
    .limit(1);
  if (!decision) throw new Error("policy decision not found");
  return {
    decision: presentDecision(decision),
    explanation: sanitizeContext({
      summary: decision.decisionReason,
      expectedAction: decision.decision,
      confidence: decision.confidence,
      riskScore: decision.riskScore,
      policyId: decision.policyId,
      policyVersionId: decision.policyVersionId,
      detectorReferences: decision.detectorReferences || [],
      threatIntelReferences: decision.threatIntelReferences || [],
      evidence: decision.explanation || {},
      simulated: false,
      immutable: true,
    }),
  };
}

export async function listPolicyTestCases({ database = db(), organizationId, filters = {} } = {}) {
  const query = await normalizeSimulationQuery({ database, organizationId, filters });
  const predicates = [eq(policyTestCases.organizationId, organizationId), isNull(policyTestCases.deletedAt)];
  if (query.firewallInstanceId) predicates.push(eq(policyTestCases.firewallInstanceId, query.firewallInstanceId));
  if (query.policyId) predicates.push(eq(policyTestCases.policyId, query.policyId));
  if (query.status) predicates.push(eq(policyTestCases.status, query.status));
  const rows = await database
    .select()
    .from(policyTestCases)
    .where(and(...predicates))
    .orderBy(desc(policyTestCases.updatedAt))
    .limit(query.limit);
  return { items: rows.map(presentTestCase), pageInfo: { limit: query.limit, hasMore: rows.length === query.limit } };
}

export async function createPolicyTestCase({
  database = db(),
  organizationId,
  userId,
  input = {},
  auditContext = {},
} = {}) {
  const values = await normalizeTestCaseInput({ database, organizationId, input });
  const [row] = await database
    .insert(policyTestCases)
    .values({ ...values, organizationId, createdByUserId: userId || null })
    .returning();
  await auditPolicySimulation({
    database,
    organizationId,
    userId,
    firewallInstanceId: values.firewallInstanceId,
    eventType: AUDIT_EVENT_TYPES.POLICY_TEST_CASE_CREATED,
    action: "policy_test_case.create",
    resourceId: row.id,
    requestId: auditContext.requestId,
    metadata: { expectedDecision: row.expectedDecision, expectedAction: row.expectedAction },
  });
  return presentTestCase(row);
}

export async function runPolicyTestCase({
  database = db(),
  organizationId,
  userId,
  testCaseId,
  auditContext = {},
} = {}) {
  const id = requiredString(testCaseId, "testCaseId", 160);
  const [testCase] = await database
    .select()
    .from(policyTestCases)
    .where(and(eq(policyTestCases.id, id), eq(policyTestCases.organizationId, organizationId), isNull(policyTestCases.deletedAt)))
    .limit(1);
  if (!testCase) throw new Error("policy test case not found");
  const simulation = await runPolicySimulation({
    database,
    organizationId,
    userId,
    input: {
      mode: POLICY_SIMULATION_MODES.DRY_RUN,
      policyId: testCase.policyId,
      policyVersionId: testCase.policyVersionId,
      firewallInstanceId: testCase.firewallInstanceId,
      context: testCase.inputContext,
      expectedDecision: testCase.expectedDecision,
      expectedAction: testCase.expectedAction,
    },
    auditContext,
  });
  const result = simulation.results?.[0];
  const passed = result?.expectedDecision === testCase.expectedDecision && result?.expectedAction === testCase.expectedAction;
  await database
    .update(policyTestCases)
    .set({ lastResult: passed ? "passed" : "failed", lastRunAt: new Date(), updatedAt: new Date() })
    .where(eq(policyTestCases.id, testCase.id));
  return { testCase: presentTestCase({ ...testCase, lastResult: passed ? "passed" : "failed", lastRunAt: new Date() }), simulation, passed };
}

export async function listPolicyChangeRequests({ database = db(), organizationId, filters = {} } = {}) {
  const query = await normalizeSimulationQuery({ database, organizationId, filters });
  const predicates = [eq(policyChangeRequests.organizationId, organizationId)];
  if (query.firewallInstanceId) predicates.push(eq(policyChangeRequests.firewallInstanceId, query.firewallInstanceId));
  if (query.policyId) predicates.push(eq(policyChangeRequests.policyId, query.policyId));
  if (query.status) predicates.push(eq(policyChangeRequests.status, query.status));
  const rows = await database
    .select()
    .from(policyChangeRequests)
    .where(and(...predicates))
    .orderBy(desc(policyChangeRequests.createdAt))
    .limit(query.limit);
  return { items: rows.map(presentChangeRequest), pageInfo: { limit: query.limit, hasMore: rows.length === query.limit } };
}

export async function createPolicyChangeRequest({
  database = db(),
  organizationId,
  userId,
  input = {},
  auditContext = {},
} = {}) {
  const values = await normalizeChangeRequestInput({ database, organizationId, input });
  const [row] = await database
    .insert(policyChangeRequests)
    .values({ ...values, organizationId, requestedByUserId: userId || null })
    .returning();
  await auditPolicySimulation({
    database,
    organizationId,
    userId,
    firewallInstanceId: values.firewallInstanceId,
    eventType: AUDIT_EVENT_TYPES.POLICY_CHANGE_REQUESTED,
    action: "policy_change_request.create",
    resourceId: row.id,
    requestId: auditContext.requestId,
    metadata: { requestedAction: row.requestedAction, status: row.status },
  });
  return presentChangeRequest(row);
}

async function normalizeSimulationInput({ database, organizationId, input }) {
  const mode = normalizeSimulationMode(input.mode || POLICY_SIMULATION_MODES.DRY_RUN);
  const policyId = cleanString(input.policyId, 160);
  const policy = policyId ? await requirePolicy(database, organizationId, policyId) : null;
  const policyVersion = await selectPolicyVersion({ database, organizationId, policy, versionId: input.policyVersionId });
  const policySnapshot = input.policySnapshot ? normalizePolicySnapshot(input.policySnapshot) : policyVersion?.policySnapshot || normalizePolicySnapshot({});
  const firewallInstanceId = cleanString(input.firewallInstanceId || policy?.firewallInstanceId, 160);
  if (firewallInstanceId) await validateFirewallOwnership(database, organizationId, firewallInstanceId);
  const sourceSecurityEventId = cleanString(input.securityEventId || input.sourceSecurityEventId, 160);
  const sourcePolicyDecisionId = cleanString(input.policyDecisionId || input.sourcePolicyDecisionId, 160);
  const sourceEnforcementEventId = cleanString(input.enforcementEventId || input.sourceEnforcementEventId, 160);
  if (sourcePolicyDecisionId) await requirePolicyDecision(database, organizationId, sourcePolicyDecisionId);
  if (sourceEnforcementEventId) await requireEnforcementEvent(database, organizationId, sourceEnforcementEventId);

  return {
    mode,
    policy,
    policyVersion,
    policySnapshot,
    firewallInstanceId,
    sourceSecurityEventId,
    sourcePolicyDecisionId,
    sourceEnforcementEventId,
    context: sanitizeContext({ ...(input.context || {}), organizationId, firewallInstanceId }),
    protectionRules: await loadProtectionRules(database, organizationId, firewallInstanceId),
    allowlist: await loadProtectionList(database, organizationId, firewallInstanceId, protectionAllowlists),
    blocklist: await loadProtectionList(database, organizationId, firewallInstanceId, protectionBlocklists),
    rateLimitPolicy: await loadRateLimitPolicy(database, organizationId, firewallInstanceId),
    credentialState: sanitizeContext(input.credentialState || null),
    config: { mode, expectedDecision: cleanDecision(input.expectedDecision), expectedAction: cleanAction(input.expectedAction) },
    since: parseDate(input.since),
    until: parseDate(input.until),
    limit: limitValue(input.limit, MAX_REPLAY_EVENTS),
  };
}

async function loadReplayEvents({ database, organizationId, values }) {
  if (values.sourceSecurityEventId) {
    const event = await requireSecurityEvent(database, organizationId, values.sourceSecurityEventId);
    return [eventToReplayTarget(event)];
  }
  if (values.mode !== POLICY_SIMULATION_MODES.HISTORICAL_REPLAY) return [];
  const until = values.until || new Date();
  const since = values.since || new Date(until.getTime() - 60 * 60 * 1000);
  if (since > until) throw new Error("since must be before until");
  if (until.getTime() - since.getTime() > 7 * 24 * 60 * 60 * 1000) {
    throw new Error("historical replay window is limited to 7 days");
  }
  const predicates = [
    eq(securityEvents.organizationId, organizationId),
    gte(securityEvents.occurredAt, since),
    lte(securityEvents.occurredAt, until),
  ];
  if (values.firewallInstanceId) predicates.push(eq(securityEvents.firewallInstanceId, values.firewallInstanceId));
  const rows = await database
    .select()
    .from(securityEvents)
    .where(and(...predicates))
    .orderBy(desc(securityEvents.occurredAt))
    .limit(values.limit);
  return rows.map(eventToReplayTarget);
}

function eventToReplayTarget(event) {
  return {
    securityEventId: event.id,
    actualAction: event.actionTaken === "blocked" ? "block" : event.actionTaken === "rate_limited" ? "rate_limit" : event.actionTaken === "challenged" ? "challenge" : "allow",
    context: {
      organizationId: event.organizationId,
      firewallInstanceId: event.firewallInstanceId,
      securityEventId: event.id,
      riskScore: event.score,
      confidence: event.confidence,
      severity: event.severity,
      httpMethod: event.httpMethod,
      requestPath: event.requestPath,
      sourceIp: event.sourceIp,
      country: event.country,
      userAgent: event.userAgent,
      detectorIds: event.detectorIds || [],
      apiRoute: event.apiRouteId,
      threatReputation: event.attackType,
    },
  };
}

function resultRow({ organizationId, simulationId, result, values }) {
  const expectedDecision = cleanDecision(values.config.expectedDecision) || result.expectedDecision;
  const expectedAction = cleanAction(values.config.expectedAction) || result.expectedAction;
  return {
    organizationId,
    simulationId,
    policyId: result.policyId || values.policy?.id || null,
    policyVersionId: result.policyVersionId || values.policyVersion?.id || null,
    expectedDecision: result.expectedDecision,
    expectedAction: result.expectedAction,
    actualAction: result.actualAction || null,
    riskScore: result.riskScore,
    confidence: result.confidence,
    matchedPolicyRuleId: result.matchedPolicyRuleId,
    matchedProtectionRuleId: result.matchedProtectionRuleId,
    reasonCodes: result.reasonCodes,
    explanation: result.explanation,
    regressionStatus: expectedDecision || expectedAction
      ? result.expectedDecision === expectedDecision && result.expectedAction === expectedAction
        ? "passed"
        : "failed"
      : "not_applicable",
    falsePositiveRisk: result.falsePositiveRisk,
  };
}

function buildDecisionExplanation({ zeroTrust, adaptive, context, reasonCodes, falsePositiveRisk }) {
  return sanitizeContext({
    summary: `${adaptive.action} recommended by simulated policy evaluation; live enforcement was not modified`,
    simulated: true,
    enforced: false,
    sourcePolicyVersion: zeroTrust.policyVersionId || null,
    sourceProtectionRule: adaptive.protectionRuleId || null,
    expectedAction: adaptive.action,
    confidence: zeroTrust.confidence,
    riskScore: zeroTrust.riskScore,
    reasonCodes,
    riskFactors: {
      severity: context.severity,
      detectorIds: context.detectorIds || [],
      threatReputation: context.threatReputation,
      apiRoute: context.apiRoute,
    },
    falsePositiveRisk,
    matchedConditions: zeroTrust.explanation?.matchedRule?.conditions || [],
  });
}

function summarizeImpact(results) {
  const actions = {};
  const highImpact = results.filter((result) => ["block", "quarantine", "credential_suspend"].includes(result.expectedAction)).length;
  for (const result of results) actions[result.expectedAction] = (actions[result.expectedAction] || 0) + 1;
  return {
    evaluated: results.length,
    actions,
    highImpact,
    falsePositiveRiskAverage: average(results.map((result) => result.falsePositiveRisk)),
    summary: `${results.length} request context${results.length === 1 ? "" : "s"} simulated; ${highImpact} high-impact action${highImpact === 1 ? "" : "s"} predicted`,
  };
}

function reasonCodesFor({ zeroTrust, adaptive, context }) {
  return [
    zeroTrust.decisionReason,
    adaptive.reason,
    ...(context.detectorIds || []),
    context.threatReputation && context.threatReputation !== "unknown" ? `threat:${context.threatReputation}` : null,
  ].filter(Boolean).slice(0, 20).map((value) => cleanString(value, 80));
}

function estimateFalsePositiveRisk({ riskScore, confidence, action }) {
  const impact = ["block", "quarantine", "credential_suspend"].includes(action) ? 0.2 : action === "rate_limit" ? 0.12 : 0.05;
  const uncertainty = 1 - Number(confidence || 0);
  const lowRiskPenalty = Math.max(0, 50 - Number(riskScore || 0)) / 100;
  return Math.max(0, Math.min(1, Math.round((impact + uncertainty * 0.5 + lowRiskPenalty) * 100) / 100));
}

async function loadProtectionRules(database, organizationId, firewallInstanceId) {
  const predicates = [eq(protectionRules.organizationId, organizationId), eq(protectionRules.status, "active"), isNull(protectionRules.deletedAt)];
  if (firewallInstanceId) predicates.push(eq(protectionRules.firewallInstanceId, firewallInstanceId));
  return database.select().from(protectionRules).where(and(...predicates)).orderBy(protectionRules.precedence).limit(100);
}

async function loadProtectionList(database, organizationId, firewallInstanceId, table) {
  const predicates = [eq(table.organizationId, organizationId), eq(table.status, "active"), isNull(table.deletedAt)];
  if (firewallInstanceId) predicates.push(eq(table.firewallInstanceId, firewallInstanceId));
  return database.select().from(table).where(and(...predicates)).limit(100);
}

async function loadRateLimitPolicy(database, organizationId, firewallInstanceId) {
  const predicates = [eq(rateLimitPolicies.organizationId, organizationId), eq(rateLimitPolicies.status, "active"), isNull(rateLimitPolicies.deletedAt)];
  if (firewallInstanceId) predicates.push(eq(rateLimitPolicies.firewallInstanceId, firewallInstanceId));
  const [policy] = await database.select().from(rateLimitPolicies).where(and(...predicates)).orderBy(desc(rateLimitPolicies.updatedAt)).limit(1);
  return policy || null;
}

async function selectPolicyVersion({ database, organizationId, policy, versionId }) {
  if (!policy) {
    if (versionId) throw new Error("policy is required when policyVersionId is provided");
    return null;
  }
  const predicates = [eq(zeroTrustPolicyVersions.organizationId, organizationId), eq(zeroTrustPolicyVersions.policyId, policy.id)];
  if (versionId) predicates.push(eq(zeroTrustPolicyVersions.id, cleanString(versionId, 160)));
  else if (policy.activeVersionId) predicates.push(eq(zeroTrustPolicyVersions.id, policy.activeVersionId));
  const [version] = await database.select().from(zeroTrustPolicyVersions).where(and(...predicates)).limit(1);
  if (!version) throw new Error("policy version not found");
  return version;
}

async function requirePolicy(database, organizationId, policyId) {
  const [policy] = await database
    .select()
    .from(zeroTrustPolicies)
    .where(and(eq(zeroTrustPolicies.id, policyId), eq(zeroTrustPolicies.organizationId, organizationId), isNull(zeroTrustPolicies.deletedAt)))
    .limit(1);
  if (!policy) throw new Error("policy not found");
  return policy;
}

async function requireSecurityEvent(database, organizationId, eventId) {
  const [event] = await database
    .select()
    .from(securityEvents)
    .where(and(eq(securityEvents.id, eventId), eq(securityEvents.organizationId, organizationId)))
    .limit(1);
  if (!event) throw new Error("security event not found");
  return event;
}

async function requirePolicyDecision(database, organizationId, decisionId) {
  const [decision] = await database
    .select({ id: policyDecisions.id })
    .from(policyDecisions)
    .where(and(eq(policyDecisions.id, decisionId), eq(policyDecisions.organizationId, organizationId)))
    .limit(1);
  if (!decision) throw new Error("policy decision not found");
  return decision;
}

async function requireEnforcementEvent(database, organizationId, enforcementEventId) {
  const [event] = await database
    .select({ id: enforcementEvents.id })
    .from(enforcementEvents)
    .where(and(eq(enforcementEvents.id, enforcementEventId), eq(enforcementEvents.organizationId, organizationId)))
    .limit(1);
  if (!event) throw new Error("enforcement event not found");
  return event;
}

async function validateFirewallOwnership(database, organizationId, firewallInstanceId) {
  const [firewall] = await database
    .select({ id: firewallInstances.id })
    .from(firewallInstances)
    .where(and(eq(firewallInstances.id, firewallInstanceId), eq(firewallInstances.organizationId, organizationId), eq(firewallInstances.status, "active"), isNull(firewallInstances.deletedAt)))
    .limit(1);
  if (!firewall) throw new Error("firewall instance is not available for this organization");
  return firewall;
}

async function normalizeTestCaseInput({ database, organizationId, input }) {
  const firewallInstanceId = cleanString(input.firewallInstanceId, 160);
  if (firewallInstanceId) await validateFirewallOwnership(database, organizationId, firewallInstanceId);
  const policyId = cleanString(input.policyId, 160);
  const policy = policyId ? await requirePolicy(database, organizationId, policyId) : null;
  const policyVersionId = cleanString(input.policyVersionId, 160);
  const policyVersion = policyVersionId
    ? await selectPolicyVersion({ database, organizationId, policy, versionId: policyVersionId })
    : null;
  return {
    firewallInstanceId,
    policyId,
    policyVersionId: policyVersion?.id || null,
    name: requiredString(input.name, "name", 160),
    description: cleanString(input.description, 2000),
    status: enumValue(input.status || "active", ["active", "disabled"], "status"),
    inputContext: sanitizeContext(input.inputContext || input.context || {}),
    expectedDecision: cleanDecision(input.expectedDecision) || ZERO_TRUST_DECISIONS.ALLOW,
    expectedAction: cleanAction(input.expectedAction) || PROTECTION_ACTIONS.ALLOW,
    metadata: sanitizeContext(input.metadata || {}),
  };
}

async function normalizeChangeRequestInput({ database, organizationId, input }) {
  const policy = await requirePolicy(database, organizationId, requiredString(input.policyId, "policyId", 160));
  const firewallInstanceId = cleanString(input.firewallInstanceId || policy.firewallInstanceId, 160);
  if (firewallInstanceId) await validateFirewallOwnership(database, organizationId, firewallInstanceId);
  const policyVersion = await selectPolicyVersion({
    database,
    organizationId,
    policy,
    versionId: input.policyVersionId || policy.activeVersionId,
  });
  const simulationId = cleanString(input.simulationId, 160);
  if (simulationId) await requireSimulation(database, organizationId, simulationId);
  return {
    firewallInstanceId,
    policyId: policy.id,
    policyVersionId: policyVersion?.id || null,
    simulationId,
    requestedAction: enumValue(input.requestedAction || "update", ["create", "update", "activate", "rollback", "promote_to_enforce"], "requested action"),
    status: enumValue(input.status || "requested", Object.values(POLICY_CHANGE_REQUEST_STATUSES), "status"),
    reason: requiredString(input.reason, "reason", 2000),
    reviewerUserId: cleanString(input.reviewerUserId, 160),
    expiresAt: parseDate(input.expiresAt),
    metadata: sanitizeContext(input.metadata || {}),
  };
}

async function requireSimulation(database, organizationId, simulationId) {
  const [simulation] = await database
    .select({ id: policySimulations.id })
    .from(policySimulations)
    .where(and(eq(policySimulations.id, simulationId), eq(policySimulations.organizationId, organizationId)))
    .limit(1);
  if (!simulation) throw new Error("policy simulation not found");
  return simulation;
}

async function normalizeSimulationQuery({ database, organizationId, filters = {}, includeWindow = false }) {
  const firewallInstanceId = cleanString(filters.firewallInstanceId, 160);
  if (firewallInstanceId) await validateFirewallOwnership(database, organizationId, firewallInstanceId);
  const until = includeWindow ? parseDate(filters.until) || new Date() : null;
  const since = includeWindow ? parseDate(filters.since) || new Date(until.getTime() - 7 * 24 * 60 * 60 * 1000) : null;
  if (includeWindow && since > until) throw new Error("since must be before until");
  if (includeWindow && until.getTime() - since.getTime() > 90 * 24 * 60 * 60 * 1000) {
    throw new Error("query window is limited to 90 days");
  }
  return {
    firewallInstanceId,
    policyId: cleanString(filters.policyId, 160),
    mode: filters.mode ? normalizeSimulationMode(filters.mode) : null,
    status: cleanString(filters.status, 32),
    since,
    until,
    limit: limitValue(filters.limit, MAX_LIMIT),
  };
}

async function auditPolicySimulation({
  database,
  organizationId,
  userId,
  firewallInstanceId,
  eventType,
  action,
  resourceId,
  requestId,
  metadata,
} = {}) {
  return createAuditEvent({
    database,
    organizationId,
    userId,
    firewallInstanceId,
    eventType,
    action,
    resourceType: "policy_simulation",
    resourceId,
    result: "success",
    severity: "info",
    requestId,
    metadata: sanitizeContext(metadata || {}),
  });
}

function presentSimulation(row = {}) {
  return {
    id: row.id,
    organizationId: row.organizationId,
    firewallInstanceId: row.firewallInstanceId,
    policyId: row.policyId,
    policyVersionId: row.policyVersionId,
    mode: row.mode,
    status: row.status,
    summary: row.summary,
    impactSummary: row.impactSummary || {},
    sourceSecurityEventId: row.sourceSecurityEventId,
    sourcePolicyDecisionId: row.sourcePolicyDecisionId,
    sourceEnforcementEventId: row.sourceEnforcementEventId,
    startedAt: row.startedAt,
    completedAt: row.completedAt,
    createdAt: row.createdAt,
    results: row.results,
  };
}

function presentSimulationResult(row = {}) {
  return {
    id: row.id,
    simulationId: row.simulationId,
    policyId: row.policyId,
    policyVersionId: row.policyVersionId,
    expectedDecision: row.expectedDecision,
    expectedAction: row.expectedAction,
    actualAction: row.actualAction,
    riskScore: row.riskScore,
    confidence: row.confidence,
    matchedPolicyRuleId: row.matchedPolicyRuleId,
    matchedProtectionRuleId: row.matchedProtectionRuleId,
    reasonCodes: row.reasonCodes || [],
    explanation: row.explanation || {},
    regressionStatus: row.regressionStatus,
    falsePositiveRisk: row.falsePositiveRisk,
    createdAt: row.createdAt,
  };
}

function presentTestCase(row = {}) {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    status: row.status,
    firewallInstanceId: row.firewallInstanceId,
    policyId: row.policyId,
    policyVersionId: row.policyVersionId,
    expectedDecision: row.expectedDecision,
    expectedAction: row.expectedAction,
    lastResult: row.lastResult,
    lastRunAt: row.lastRunAt,
    updatedAt: row.updatedAt,
  };
}

function presentChangeRequest(row = {}) {
  return {
    id: row.id,
    policyId: row.policyId,
    policyVersionId: row.policyVersionId,
    simulationId: row.simulationId,
    requestedAction: row.requestedAction,
    status: row.status,
    reason: row.reason,
    reviewerUserId: row.reviewerUserId,
    requestedByUserId: row.requestedByUserId,
    decidedAt: row.decidedAt,
    expiresAt: row.expiresAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function presentDecision(row = {}) {
  return {
    id: row.id,
    policyId: row.policyId,
    policyVersionId: row.policyVersionId,
    decision: row.decision,
    mode: row.mode,
    riskScore: row.riskScore,
    confidence: row.confidence,
    evaluatedAt: row.evaluatedAt,
  };
}

function cleanDecision(value) {
  if (!value) return "";
  return enumValue(value, Object.values(ZERO_TRUST_DECISIONS), "decision");
}

function cleanAction(value) {
  if (!value) return "";
  return enumValue(value, Object.values(PROTECTION_ACTIONS), "action");
}

function normalizeSimulationMode(value) {
  return enumValue(value, Object.values(POLICY_SIMULATION_MODES), "simulation mode");
}

function average(values) {
  const numbers = values.map(Number).filter(Number.isFinite);
  if (!numbers.length) return 0;
  return Math.round((numbers.reduce((sum, value) => sum + value, 0) / numbers.length) * 100) / 100;
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

function sanitizeContext(value, depth = 0) {
  if (value == null) return value;
  if (depth > 4) return "[truncated]";
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => sanitizeContext(item, depth + 1));
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .slice(0, MAX_CONTEXT_KEYS)
        .filter(([key]) => !SENSITIVE_KEY.test(key))
        .map(([key, child]) => [cleanString(key, 80), sanitizeContext(child, depth + 1)]),
    );
  }
  if (typeof value === "number" || typeof value === "boolean") return value;
  return cleanString(value, MAX_CONTEXT_STRING);
}
