import "server-only";

import { createHash } from "node:crypto";
import { and, desc, eq, gte, isNull, lte, or } from "drizzle-orm";
import { db } from "../../db/client.js";
import {
  credentialProtectionState,
  emergencyBypasses,
  enforcementEvents,
  firewallInstances,
  protectionAllowlists,
  protectionBlocklists,
  protectionRules,
  rateLimitPolicies,
} from "../../db/schema.js";
import { AUDIT_EVENT_TYPES, createAuditEvent } from "../audit/index.js";
import { ZERO_TRUST_DECISIONS } from "../zero-trust/index.js";

export const PROTECTION_ACTIONS = Object.freeze({
  ALLOW: "allow",
  CHALLENGE: "challenge",
  RATE_LIMIT: "rate_limit",
  BLOCK: "block",
  QUARANTINE: "quarantine",
  CREDENTIAL_SUSPEND: "credential_suspend",
});

export const PROTECTION_MODES = Object.freeze({
  OBSERVE: "observe",
  SIMULATION: "simulation",
  ENFORCEMENT: "enforcement",
});

export const PROTECTION_PRECEDENCE = Object.freeze([
  "emergency_bypass",
  "explicit_block",
  "quarantine",
  "credential_restriction",
  "adaptive_rate_limit",
  "challenge",
  "allow",
]);

const MAX_RULES = 100;
const MAX_CONDITIONS = 16;
const MAX_LIST_ENTRIES = 1000;
const MAX_CONTEXT_STRING = 512;
const MAX_CONTEXT_KEYS = 80;
const MAX_RATE_STATES = 5000;
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;
const SENSITIVE_KEY = /password|secret|token|credential|authorization|cookie|session|private[_-]?key|api[_-]?key|body|payload|query/i;
const hotRateState = new Map();

export function evaluateAdaptiveProtection({
  policyDecision,
  context = {},
  protectionRules: rules = [],
  allowlist = [],
  blocklist = [],
  credentialState = null,
  emergencyBypass = null,
  rateLimitPolicy = null,
  rateLimitStore = hotRateState,
  now = new Date(),
  mode,
} = {}) {
  const normalizedContext = normalizeProtectionContext({ policyDecision, context });
  const requestedMode = normalizeMode(mode || context.mode || policyDecision?.mode || PROTECTION_MODES.OBSERVE);

  if (!policyDecision?.id && !policyDecision?.decision) {
    return finalizeResult({
      action: PROTECTION_ACTIONS.BLOCK,
      effectiveAction: requestedMode === PROTECTION_MODES.ENFORCEMENT ? PROTECTION_ACTIONS.BLOCK : PROTECTION_ACTIONS.ALLOW,
      mode: requestedMode,
      outcome: requestedMode === PROTECTION_MODES.ENFORCEMENT ? "failed" : outcomeForMode(requestedMode),
      reason: "policy_decision_unavailable",
      policyDecision,
      context: normalizedContext,
      now,
      explanation: { failSafe: "policy decision missing" },
    });
  }

  if (isActive(emergencyBypass, now)) {
    return finalizeResult({
      action: PROTECTION_ACTIONS.ALLOW,
      effectiveAction: PROTECTION_ACTIONS.ALLOW,
      mode: requestedMode,
      outcome: "bypassed",
      reason: "emergency_bypass_active",
      policyDecision,
      context: normalizedContext,
      now,
      explanation: { precedence: "emergency_bypass", bypassId: emergencyBypass.id || null },
    });
  }

  const explicitBlock = firstMatchingListEntry(blocklist, normalizedContext, now);
  if (explicitBlock) {
    return resultFromCandidate({
      candidate: {
        action: PROTECTION_ACTIONS.BLOCK,
        reason: explicitBlock.reason || "explicit_blocklist_match",
        precedence: "explicit_block",
        source: "blocklist",
        protectionRuleId: explicitBlock.id,
      },
      mode: requestedMode,
      policyDecision,
      context: normalizedContext,
      now,
    });
  }

  const trustedAllow = firstMatchingListEntry(allowlist, normalizedContext, now);
  const sortedRules = normalizeRuleList(rules).sort((left, right) => left.precedence - right.precedence);
  const ruleCandidate = sortedRules.find((rule) => ruleMatches(rule, normalizedContext));
  const decisionCandidate = candidateFromPolicyDecision(policyDecision);
  const credentialCandidate = candidateFromCredentialState(credentialState, now);
  const candidates = [
    ruleCandidate,
    decisionCandidate,
    credentialCandidate,
  ].filter(Boolean);

  if (trustedAllow) {
    candidates.push({
      action: PROTECTION_ACTIONS.ALLOW,
      reason: trustedAllow.reason || "explicit_allowlist_match",
      precedence: "allow",
      source: "allowlist",
      protectionRuleId: trustedAllow.id,
    });
  }

  const selected = selectByPrecedence(candidates);
  if (selected?.action === PROTECTION_ACTIONS.RATE_LIMIT && rateLimitPolicy) {
    const rateResult = evaluateRateLimit({ policy: rateLimitPolicy, context: normalizedContext, store: rateLimitStore, now });
    const immediateThrottle =
      selected.source === "policy_decision" || selected.precedence === "credential_restriction";
    return resultFromCandidate({
      candidate: {
        ...selected,
        rateLimit: rateResult,
        action: immediateThrottle || rateResult.exceeded ? PROTECTION_ACTIONS.RATE_LIMIT : PROTECTION_ACTIONS.ALLOW,
        reason: immediateThrottle || rateResult.exceeded ? selected.reason : "rate_limit_window_available",
      },
      mode: requestedMode,
      policyDecision,
      context: normalizedContext,
      now,
    });
  }

  return resultFromCandidate({
    candidate: selected || { action: PROTECTION_ACTIONS.ALLOW, reason: "no_protection_match", precedence: "allow" },
    mode: requestedMode,
    policyDecision,
    context: normalizedContext,
    now,
  });
}

export function evaluateRateLimit({
  policy,
  context = {},
  store = hotRateState,
  now = new Date(),
} = {}) {
  const normalized = normalizeRateLimitPolicy(policy || {
    id: "default",
    dimension: "source",
    limitCount: 60,
    windowSeconds: 60,
  });
  const key = rateLimitKey(normalized, context);
  const windowMs = normalized.windowSeconds * 1000;
  const windowStartMs = Math.floor(now.getTime() / windowMs) * windowMs;
  const storeKey = `${normalized.id}:${key.hash}:${windowStartMs}`;
  trimRateStore(store, now);

  const existing = store.get(storeKey) || {
    count: 0,
    windowStart: new Date(windowStartMs),
    windowEnd: new Date(windowStartMs + windowMs),
    expiresAt: new Date(windowStartMs + windowMs + 60_000),
  };
  const next = { ...existing, count: existing.count + 1 };
  store.set(storeKey, next);

  return {
    policyId: normalized.id,
    dimension: normalized.dimension,
    keyHash: key.hash,
    keyLabel: key.label,
    count: next.count,
    limit: normalized.limitCount,
    windowStart: next.windowStart,
    windowEnd: next.windowEnd,
    resetAt: next.windowEnd,
    exceeded: next.count > normalized.limitCount,
  };
}

export async function listProtectionRules({ database = db(), organizationId, filters = {} } = {}) {
  const query = await normalizeProtectionQuery({ database, organizationId, filters });
  const predicates = [eq(protectionRules.organizationId, organizationId), isNull(protectionRules.deletedAt)];
  if (query.firewallInstanceId) predicates.push(eq(protectionRules.firewallInstanceId, query.firewallInstanceId));
  if (query.status) predicates.push(eq(protectionRules.status, query.status));
  if (query.action) predicates.push(eq(protectionRules.action, query.action));

  const rows = await database
    .select()
    .from(protectionRules)
    .where(and(...predicates))
    .orderBy(protectionRules.precedence, desc(protectionRules.updatedAt))
    .limit(query.limit);

  return { items: rows.map(presentProtectionRule), precedence: PROTECTION_PRECEDENCE };
}

export async function createProtectionRule({
  database = db(),
  organizationId,
  userId,
  input = {},
  auditContext = {},
} = {}) {
  const values = normalizeProtectionRuleInput(input);
  if (values.firewallInstanceId) await validateFirewallOwnership(database, organizationId, values.firewallInstanceId);
  const [row] = await database
    .insert(protectionRules)
    .values({ ...values, organizationId, createdByUserId: userId || null })
    .returning();
  await auditProtection({
    database,
    organizationId,
    userId,
    firewallInstanceId: values.firewallInstanceId,
    eventType: AUDIT_EVENT_TYPES.PROTECTION_RULE_CREATED,
    action: "protection_rule.create",
    resourceType: "protection_rule",
    resourceId: row.id,
    requestId: auditContext.requestId,
    metadata: { action: row.action, mode: row.mode, precedence: row.precedence },
  });
  return presentProtectionRule(row);
}

export async function listEnforcementEvents({ database = db(), organizationId, filters = {} } = {}) {
  const query = await normalizeProtectionQuery({ database, organizationId, filters, includeWindow: true });
  const predicates = [
    eq(enforcementEvents.organizationId, organizationId),
    gte(enforcementEvents.createdAt, query.since),
    lte(enforcementEvents.createdAt, query.until),
  ];
  if (query.firewallInstanceId) predicates.push(eq(enforcementEvents.firewallInstanceId, query.firewallInstanceId));
  if (query.action) predicates.push(eq(enforcementEvents.action, query.action));
  if (query.mode) predicates.push(eq(enforcementEvents.mode, query.mode));

  const rows = await database
    .select()
    .from(enforcementEvents)
    .where(and(...predicates))
    .orderBy(desc(enforcementEvents.createdAt))
    .limit(query.limit);

  return { items: rows.map(presentEnforcementEvent), pageInfo: { limit: query.limit, hasMore: rows.length === query.limit } };
}

export async function recordEnforcementEvent({
  database = db(),
  organizationId,
  input = {},
  auditContext = {},
} = {}) {
  const values = normalizeEnforcementEventInput({ ...input, organizationId });
  if (values.firewallInstanceId) await validateFirewallOwnership(database, organizationId, values.firewallInstanceId);
  const [row] = await database.insert(enforcementEvents).values(values).returning();

  if (row.action !== PROTECTION_ACTIONS.ALLOW || row.outcome === "failed") {
    await auditProtection({
      database,
      organizationId,
      firewallInstanceId: row.firewallInstanceId,
      eventType: AUDIT_EVENT_TYPES.ENFORCEMENT_EVENT_RECORDED,
      action: "adaptive_protection.enforcement_event",
      resourceType: "enforcement_event",
      resourceId: row.id,
      requestId: auditContext.requestId,
      metadata: { action: row.action, mode: row.mode, outcome: row.outcome, riskScore: row.riskScore },
    });
  }

  return presentEnforcementEvent(row);
}

export async function simulateAdaptiveProtection({
  database = db(),
  organizationId,
  userId,
  input = {},
  auditContext = {},
} = {}) {
  const firewallInstanceId = cleanString(input.firewallInstanceId, 160);
  if (firewallInstanceId) await validateFirewallOwnership(database, organizationId, firewallInstanceId);
  const result = evaluateAdaptiveProtection({
    policyDecision: input.policyDecision,
    context: { ...(input.context || {}), organizationId, firewallInstanceId },
    protectionRules: input.protectionRules || [],
    allowlist: input.allowlist || [],
    blocklist: input.blocklist || [],
    credentialState: input.credentialState || null,
    emergencyBypass: input.emergencyBypass || null,
    rateLimitPolicy: input.rateLimitPolicy || null,
    mode: PROTECTION_MODES.SIMULATION,
  });

  await auditProtection({
    database,
    organizationId,
    userId,
    firewallInstanceId,
    eventType: AUDIT_EVENT_TYPES.PROTECTION_SIMULATED,
    action: "adaptive_protection.simulate",
    resourceType: "adaptive_protection",
    resourceId: result.policyDecisionId || null,
    requestId: auditContext.requestId,
    metadata: { action: result.action, effectiveAction: result.effectiveAction, reason: result.reason },
  });

  return result;
}

export async function listRateLimitPolicies({ database = db(), organizationId, filters = {} } = {}) {
  const query = await normalizeProtectionQuery({ database, organizationId, filters });
  const predicates = [eq(rateLimitPolicies.organizationId, organizationId), isNull(rateLimitPolicies.deletedAt)];
  if (query.firewallInstanceId) predicates.push(eq(rateLimitPolicies.firewallInstanceId, query.firewallInstanceId));
  if (query.status) predicates.push(eq(rateLimitPolicies.status, query.status));
  const rows = await database.select().from(rateLimitPolicies).where(and(...predicates)).orderBy(desc(rateLimitPolicies.updatedAt)).limit(query.limit);
  return { items: rows.map(presentRateLimitPolicy) };
}

export async function createRateLimitPolicy({ database = db(), organizationId, userId, input = {}, auditContext = {} } = {}) {
  const values = normalizeRateLimitPolicyInput(input);
  if (values.firewallInstanceId) await validateFirewallOwnership(database, organizationId, values.firewallInstanceId);
  const [row] = await database.insert(rateLimitPolicies).values({ ...values, organizationId, createdByUserId: userId || null }).returning();
  await auditProtection({
    database,
    organizationId,
    userId,
    firewallInstanceId: values.firewallInstanceId,
    eventType: AUDIT_EVENT_TYPES.RATE_LIMIT_POLICY_CREATED,
    action: "rate_limit_policy.create",
    resourceType: "rate_limit_policy",
    resourceId: row.id,
    requestId: auditContext.requestId,
    metadata: { dimension: row.dimension, limitCount: row.limitCount, windowSeconds: row.windowSeconds },
  });
  return presentRateLimitPolicy(row);
}

export async function listProtectionList({ database = db(), organizationId, listType, filters = {} } = {}) {
  const table = listType === "allowlist" ? protectionAllowlists : protectionBlocklists;
  const query = await normalizeProtectionQuery({ database, organizationId, filters });
  const predicates = [eq(table.organizationId, organizationId), isNull(table.deletedAt)];
  if (query.firewallInstanceId) predicates.push(eq(table.firewallInstanceId, query.firewallInstanceId));
  if (query.status) predicates.push(eq(table.status, query.status));
  const rows = await database.select().from(table).where(and(...predicates)).orderBy(desc(table.updatedAt)).limit(query.limit);
  return { items: rows.map(presentProtectionListEntry) };
}

export async function createProtectionListEntry({
  database = db(),
  organizationId,
  userId,
  listType,
  input = {},
  auditContext = {},
} = {}) {
  const table = listType === "allowlist" ? protectionAllowlists : protectionBlocklists;
  const values = normalizeListEntryInput(input);
  if (values.firewallInstanceId) await validateFirewallOwnership(database, organizationId, values.firewallInstanceId);
  const [row] = await database.insert(table).values({ ...values, organizationId, createdByUserId: userId || null }).returning();
  await auditProtection({
    database,
    organizationId,
    userId,
    firewallInstanceId: values.firewallInstanceId,
    eventType: listType === "allowlist" ? AUDIT_EVENT_TYPES.PROTECTION_ALLOWLIST_UPDATED : AUDIT_EVENT_TYPES.PROTECTION_BLOCKLIST_UPDATED,
    action: `protection_${listType}.create`,
    resourceType: `protection_${listType}`,
    resourceId: row.id,
    requestId: auditContext.requestId,
    metadata: { entryType: row.entryType, expiresAt: row.expiresAt },
  });
  return presentProtectionListEntry(row);
}

export async function listCredentialProtection({ database = db(), organizationId, filters = {} } = {}) {
  const query = await normalizeProtectionQuery({ database, organizationId, filters });
  const predicates = [eq(credentialProtectionState.organizationId, organizationId)];
  if (query.firewallInstanceId) predicates.push(eq(credentialProtectionState.firewallInstanceId, query.firewallInstanceId));
  if (query.status) predicates.push(eq(credentialProtectionState.status, query.status));
  const rows = await database
    .select()
    .from(credentialProtectionState)
    .where(and(...predicates))
    .orderBy(desc(credentialProtectionState.updatedAt))
    .limit(query.limit);
  return { items: rows.map(presentCredentialProtectionState) };
}

export async function createCredentialProtection({
  database = db(),
  organizationId,
  userId,
  input = {},
  auditContext = {},
} = {}) {
  const values = normalizeCredentialProtectionInput(input);
  if (values.firewallInstanceId) await validateFirewallOwnership(database, organizationId, values.firewallInstanceId);
  const [row] = await database
    .insert(credentialProtectionState)
    .values({ ...values, organizationId, createdByUserId: userId || null })
    .returning();
  await auditProtection({
    database,
    organizationId,
    userId,
    firewallInstanceId: values.firewallInstanceId,
    eventType: AUDIT_EVENT_TYPES.CREDENTIAL_PROTECTION_UPDATED,
    action: "credential_protection.create",
    resourceType: "credential_protection",
    resourceId: row.id,
    requestId: auditContext.requestId,
    metadata: { status: row.status, restrictedUntil: row.restrictedUntil || null },
  });
  return presentCredentialProtectionState(row);
}

export async function normalizeProtectionQuery({
  database = db(),
  organizationId,
  filters = {},
  includeWindow = false,
} = {}) {
  const now = new Date();
  const until = includeWindow ? parseDate(filters.until) || now : null;
  const since = includeWindow ? parseDate(filters.since) || new Date(until.getTime() - 24 * 60 * 60 * 1000) : null;
  if (includeWindow && since > until) throw new Error("since must be before until");
  if (includeWindow && until.getTime() - since.getTime() > 90 * 24 * 60 * 60 * 1000) {
    throw new Error("adaptive protection query window is limited to 90 days");
  }
  const firewallInstanceId = cleanString(filters.firewallInstanceId, 160);
  if (firewallInstanceId) await validateFirewallOwnership(database, organizationId, firewallInstanceId);
  return {
    firewallInstanceId,
    status: cleanToken(filters.status, 32),
    action: filters.action ? normalizeAction(filters.action) : null,
    mode: filters.mode ? normalizeMode(filters.mode) : null,
    since,
    until,
    limit: limitValue(filters.limit, MAX_LIMIT),
  };
}

function resultFromCandidate({ candidate, mode, policyDecision, context, now }) {
  const effectiveAction = mode === PROTECTION_MODES.ENFORCEMENT ? candidate.action : PROTECTION_ACTIONS.ALLOW;
  return finalizeResult({
    action: candidate.action,
    effectiveAction,
    mode,
    outcome: outcomeForMode(mode),
    reason: candidate.reason,
    policyDecision,
    context,
    now,
    protectionRuleId: candidate.protectionRuleId || null,
    rateLimit: candidate.rateLimit || null,
    explanation: {
      precedence: candidate.precedence,
      source: candidate.source || "policy_decision",
      rateLimit: candidate.rateLimit || null,
    },
  });
}

function finalizeResult({
  action,
  effectiveAction,
  mode,
  outcome,
  reason,
  policyDecision,
  context,
  now,
  protectionRuleId = null,
  rateLimit = null,
  explanation = {},
}) {
  return {
    action: normalizeAction(action),
    effectiveAction: normalizeAction(effectiveAction),
    mode: normalizeMode(mode),
    outcome,
    reason: cleanString(reason, 240) || "adaptive_protection_decision",
    organizationId: context.organizationId || policyDecision?.organizationId || null,
    firewallInstanceId: context.firewallInstanceId || policyDecision?.firewallInstanceId || null,
    policyDecisionId: policyDecision?.id || null,
    policyId: policyDecision?.policyId || null,
    policyVersionId: policyDecision?.policyVersionId || null,
    protectionRuleId,
    rateLimitPolicyId: rateLimit?.policyId || null,
    riskScore: clampScore(policyDecision?.riskScore ?? context.riskScore),
    confidence: clampConfidence(policyDecision?.confidence ?? context.confidence),
    detectorReferences: normalizeArray(policyDecision?.detectorReferences || context.detectorReferences || context.detectorIds || [], 40, 80),
    enforcementKeyHash: rateLimit?.keyHash || null,
    expiresAt: actionExpiresAt(action, now),
    requestContext: sanitizeContext(context.requestContext || context),
    explanation: sanitizeContext({ ...explanation, precedenceOrder: PROTECTION_PRECEDENCE }),
  };
}

function candidateFromPolicyDecision(decision = {}) {
  const action = decisionToAction(decision.decision);
  return {
    action,
    reason: decision.decisionReason || "zero_trust_policy_decision",
    precedence: precedenceForAction(action),
    source: "policy_decision",
  };
}

function candidateFromCredentialState(state, now) {
  if (!state || state.status === "active" || state.status === "released") return null;
  if (state.restrictedUntil && new Date(state.restrictedUntil).getTime() <= now.getTime()) return null;
  if (state.status === "suspended") {
    return {
      action: PROTECTION_ACTIONS.CREDENTIAL_SUSPEND,
      reason: state.reason || "credential_suspended",
      precedence: "credential_restriction",
      source: "credential_protection",
    };
  }
  if (state.status === "restricted") {
    return {
      action: PROTECTION_ACTIONS.RATE_LIMIT,
      reason: state.reason || "credential_restricted",
      precedence: "credential_restriction",
      source: "credential_protection",
    };
  }
  return {
    action: PROTECTION_ACTIONS.CHALLENGE,
    reason: state.reason || "credential_suspicious",
    precedence: "challenge",
    source: "credential_protection",
  };
}

function selectByPrecedence(candidates) {
  if (!candidates.length) return null;
  return candidates.sort((left, right) => {
    const order = PROTECTION_PRECEDENCE.indexOf(left.precedence) - PROTECTION_PRECEDENCE.indexOf(right.precedence);
    if (order !== 0) return order;
    return actionWeight(right.action) - actionWeight(left.action);
  })[0];
}

function actionWeight(action) {
  return {
    allow: 0,
    challenge: 1,
    rate_limit: 2,
    credential_suspend: 3,
    quarantine: 4,
    block: 5,
  }[action] || 0;
}

function precedenceForAction(action) {
  if (action === PROTECTION_ACTIONS.BLOCK) return "explicit_block";
  if (action === PROTECTION_ACTIONS.QUARANTINE) return "quarantine";
  if (action === PROTECTION_ACTIONS.CREDENTIAL_SUSPEND) return "credential_restriction";
  if (action === PROTECTION_ACTIONS.RATE_LIMIT) return "adaptive_rate_limit";
  if (action === PROTECTION_ACTIONS.CHALLENGE) return "challenge";
  return "allow";
}

function decisionToAction(decision) {
  if (decision === ZERO_TRUST_DECISIONS.QUARANTINE) return PROTECTION_ACTIONS.QUARANTINE;
  if (decision === ZERO_TRUST_DECISIONS.BLOCK) return PROTECTION_ACTIONS.BLOCK;
  if (decision === ZERO_TRUST_DECISIONS.RATE_LIMIT) return PROTECTION_ACTIONS.RATE_LIMIT;
  if (decision === ZERO_TRUST_DECISIONS.CHALLENGE) return PROTECTION_ACTIONS.CHALLENGE;
  return PROTECTION_ACTIONS.ALLOW;
}

function ruleMatches(rule, context) {
  return rule.status === "active" && rule.conditions.every((condition) => conditionMatches(condition, context));
}

function conditionMatches(condition, context) {
  const actual = protectionContextValue(condition.field, context);
  const expected = condition.value;
  switch (condition.operator) {
    case "eq":
      return comparable(actual) === comparable(expected);
    case "neq":
      return comparable(actual) !== comparable(expected);
    case "gte":
      return Number(actual || 0) >= Number(expected || 0);
    case "lte":
      return Number(actual || 0) <= Number(expected || 0);
    case "in":
      return Array.isArray(expected) && expected.map(comparable).includes(comparable(actual));
    case "contains":
      if (Array.isArray(actual)) return actual.map(comparable).includes(comparable(expected));
      return comparable(actual).includes(comparable(expected));
    default:
      return false;
  }
}

function protectionContextValue(field, context) {
  return {
    risk_score: context.riskScore,
    confidence: context.confidence,
    action: context.policyDecision,
    route: context.route,
    source: context.source,
    credential: context.credentialFingerprint,
    detector: context.detectorReferences,
    indicator: context.indicatorReferences,
    firewall: context.firewallInstanceId,
  }[field];
}

function firstMatchingListEntry(entries, context, now) {
  return entries
    .slice(0, MAX_LIST_ENTRIES)
    .filter((entry) => entry.status === "active" && (!entry.expiresAt || new Date(entry.expiresAt).getTime() > now.getTime()))
    .find((entry) => listEntryMatches(entry, context));
}

function listEntryMatches(entry, context) {
  const normalized = normalizeListEntry(entry.entryType, entry.entryLabel || entry.value || "");
  const expected = entry.entryHash || normalized.entryHash;
  const candidates = listCandidateValues(entry.entryType, context);
  return candidates.some((value) => normalizeListEntry(entry.entryType, value).entryHash === expected);
}

function listCandidateValues(entryType, context) {
  if (entryType === "ip" || entryType === "cidr") return [context.source].filter(Boolean);
  if (entryType === "route") return [context.route, context.requestPath].filter(Boolean);
  if (entryType === "credential") return [context.credentialFingerprint].filter(Boolean);
  if (entryType === "detector") return context.detectorReferences || [];
  if (entryType === "indicator") return context.indicatorReferences || [];
  return [];
}

function normalizeProtectionContext({ policyDecision = {}, context = {} } = {}) {
  const requestContext = sanitizeContext(context.requestContext || policyDecision.requestContext || {});
  return sanitizeContext({
    organizationId: cleanString(context.organizationId || policyDecision.organizationId, 160),
    firewallInstanceId: cleanString(context.firewallInstanceId || policyDecision.firewallInstanceId, 160),
    policyDecision: cleanToken(policyDecision.decision, 32),
    riskScore: clampScore(context.riskScore ?? policyDecision.riskScore),
    confidence: clampConfidence(context.confidence ?? policyDecision.confidence),
    source: cleanString(context.source || context.sourceIp || requestContext.sourceIp, 160),
    route: cleanString(context.route || context.apiRoute || context.requestPath || requestContext.route || requestContext.path, 240),
    requestPath: cleanString(context.requestPath || requestContext.path, 240),
    credentialFingerprint: fingerprintValue(context.credentialFingerprint || requestContext.credentialFingerprint || ""),
    detectorReferences: normalizeArray(context.detectorReferences || policyDecision.detectorReferences || [], 40, 80),
    indicatorReferences: normalizeArray(context.indicatorReferences || policyDecision.threatIntelReferences || [], 40, 160),
    requestContext,
  });
}

function normalizeRuleList(rules = []) {
  return rules.slice(0, MAX_RULES).map((rule, index) => ({
    id: cleanString(rule.id, 160),
    protectionRuleId: cleanString(rule.id, 160),
    status: rule.status || "active",
    action: normalizeAction(rule.action),
    source: "protection_rule",
    precedence: Math.max(1, Math.min(10000, Number(rule.precedence || (index + 1) * 100))),
    reason: cleanString(rule.reason || rule.name || "protection_rule_match", 240),
    conditions: normalizeConditions(rule.conditions || []),
  }));
}

function normalizeProtectionRuleInput(input = {}) {
  return {
    firewallInstanceId: cleanString(input.firewallInstanceId, 160),
    name: requiredString(input.name, "name", 160),
    description: cleanString(input.description, 2000),
    status: enumValue(input.status || "active", ["active", "disabled"], "status"),
    mode: normalizeMode(input.mode || PROTECTION_MODES.OBSERVE),
    action: normalizeAction(input.action),
    precedence: Math.max(1, Math.min(10000, Number(input.precedence || 500))),
    conditions: normalizeConditions(input.conditions || []),
    ttlSeconds: input.ttlSeconds == null ? null : Math.max(60, Math.min(2_592_000, Number(input.ttlSeconds))),
    rateLimitPolicyId: cleanString(input.rateLimitPolicyId, 160),
    metadata: sanitizeContext(input.metadata || {}),
  };
}

function normalizeRateLimitPolicyInput(input = {}) {
  const policy = normalizeRateLimitPolicy(input);
  return {
    firewallInstanceId: cleanString(input.firewallInstanceId, 160),
    name: requiredString(input.name, "name", 160),
    status: enumValue(input.status || "active", ["active", "disabled"], "status"),
    dimension: policy.dimension,
    limitCount: policy.limitCount,
    windowSeconds: policy.windowSeconds,
    burstCount: input.burstCount == null ? null : Math.max(1, Math.min(100_000, Number(input.burstCount))),
    metadata: sanitizeContext(input.metadata || {}),
  };
}

function normalizeRateLimitPolicy(input = {}) {
  return {
    id: cleanString(input.id, 160) || "default",
    dimension: enumValue(input.dimension || "source", ["organization", "firewall", "route", "credential", "source"], "dimension"),
    limitCount: Math.max(1, Math.min(100_000, Number(input.limitCount || 60))),
    windowSeconds: Math.max(10, Math.min(86_400, Number(input.windowSeconds || 60))),
  };
}

function normalizeListEntryInput(input = {}) {
  const normalized = normalizeListEntry(input.entryType, input.value || input.entryLabel || "");
  return {
    firewallInstanceId: cleanString(input.firewallInstanceId, 160),
    entryType: normalized.entryType,
    entryHash: normalized.entryHash,
    entryLabel: normalized.entryLabel,
    reason: requiredString(input.reason, "reason", 2000),
    status: enumValue(input.status || "active", ["active", "disabled"], "status"),
    sourceDecisionId: cleanString(input.sourceDecisionId, 160),
    expiresAt: parseDate(input.expiresAt),
    metadata: sanitizeContext(input.metadata || {}),
  };
}

function normalizeCredentialProtectionInput(input = {}) {
  return {
    firewallInstanceId: cleanString(input.firewallInstanceId, 160),
    apiKeyId: cleanString(input.apiKeyId, 160),
    credentialFingerprint: fingerprintValue(requiredString(input.credentialFingerprint || input.credentialLabel, "credential", 160)),
    credentialLabel: cleanString(input.credentialLabel, 160),
    status: enumValue(input.status || "suspicious", ["active", "suspicious", "restricted", "suspended", "released"], "credential status"),
    reason: cleanString(input.reason, 2000),
    sourceDecisionId: cleanString(input.sourceDecisionId, 160),
    restrictedUntil: parseDate(input.restrictedUntil),
    metadata: sanitizeContext(input.metadata || {}),
  };
}

function normalizeEnforcementEventInput(input = {}) {
  return {
    organizationId: requiredString(input.organizationId, "organizationId", 160),
    firewallInstanceId: cleanString(input.firewallInstanceId, 160),
    policyDecisionId: cleanString(input.policyDecisionId, 160),
    policyId: cleanString(input.policyId, 160),
    policyVersionId: cleanString(input.policyVersionId, 160),
    protectionRuleId: cleanString(input.protectionRuleId, 160),
    rateLimitPolicyId: cleanString(input.rateLimitPolicyId, 160),
    credentialProtectionStateId: cleanString(input.credentialProtectionStateId, 160),
    alertId: cleanString(input.alertId, 160),
    incidentId: cleanString(input.incidentId, 160),
    action: normalizeAction(input.action),
    mode: normalizeMode(input.mode),
    outcome: enumValue(input.outcome || outcomeForMode(input.mode), ["observed", "simulated", "applied", "failed", "bypassed"], "outcome"),
    reason: requiredString(input.reason, "reason", 240),
    riskScore: clampScore(input.riskScore),
    confidence: clampConfidence(input.confidence),
    detectorReferences: normalizeArray(input.detectorReferences || [], 40, 80),
    enforcementKeyHash: cleanString(input.enforcementKeyHash, 64),
    expiresAt: parseDate(input.expiresAt),
    requestContext: sanitizeContext(input.requestContext || {}),
    explanation: sanitizeContext(input.explanation || {}),
  };
}

function normalizeConditions(conditions) {
  if (!Array.isArray(conditions)) throw new Error("conditions must be an array");
  if (conditions.length > MAX_CONDITIONS) throw new Error("condition count exceeds limit");
  return conditions.map((condition) => ({
    field: enumValue(condition.field, ["risk_score", "confidence", "action", "route", "source", "credential", "detector", "indicator", "firewall"], "condition field"),
    operator: enumValue(condition.operator || "eq", ["eq", "neq", "gte", "lte", "in", "contains"], "condition operator"),
    value: normalizeConditionValue(condition.value),
  }));
}

function normalizeConditionValue(value) {
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => cleanString(item, MAX_CONTEXT_STRING));
  if (typeof value === "number" || typeof value === "boolean") return value;
  return cleanString(value, MAX_CONTEXT_STRING);
}

function normalizeListEntry(entryType, value) {
  const normalizedType = enumValue(entryType, ["ip", "cidr", "route", "credential", "detector", "indicator"], "entry type");
  const label = requiredString(value, "entry value", 240).toLowerCase();
  return {
    entryType: normalizedType,
    entryLabel: label,
    entryHash: fingerprintValue(`${normalizedType}:${label}`),
  };
}

function rateLimitKey(policy, context) {
  const raw = {
    organization: context.organizationId,
    firewall: context.firewallInstanceId,
    route: context.route,
    credential: context.credentialFingerprint,
    source: context.source,
  }[policy.dimension] || "unknown";
  return {
    label: cleanString(raw, 240) || "unknown",
    hash: fingerprintValue(`${policy.dimension}:${raw || "unknown"}`),
  };
}

function trimRateStore(store, now) {
  if (store.size < MAX_RATE_STATES) {
    for (const [key, value] of store.entries()) {
      if (value.expiresAt && new Date(value.expiresAt).getTime() <= now.getTime()) store.delete(key);
    }
    return;
  }
  const entries = [...store.entries()].sort((a, b) => new Date(a[1].expiresAt).getTime() - new Date(b[1].expiresAt).getTime());
  for (const [key] of entries.slice(0, Math.ceil(MAX_RATE_STATES / 4))) store.delete(key);
}

async function validateFirewallOwnership(database, organizationId, firewallInstanceId) {
  const [firewall] = await database
    .select({ id: firewallInstances.id })
    .from(firewallInstances)
    .where(
      and(
        eq(firewallInstances.id, firewallInstanceId),
        eq(firewallInstances.organizationId, organizationId),
        eq(firewallInstances.status, "active"),
        isNull(firewallInstances.deletedAt),
      ),
    )
    .limit(1);
  if (!firewall) throw new Error("firewall instance is not available for this organization");
  return firewall;
}

async function auditProtection({
  database,
  organizationId,
  userId,
  firewallInstanceId,
  eventType,
  action,
  resourceType,
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
    resourceType,
    resourceId,
    result: "success",
    severity: "info",
    requestId,
    metadata: sanitizeContext(metadata || {}),
  });
}

function presentProtectionRule(row = {}) {
  return {
    id: row.id,
    organizationId: row.organizationId,
    firewallInstanceId: row.firewallInstanceId,
    name: row.name,
    description: row.description,
    status: row.status,
    mode: row.mode,
    action: row.action,
    precedence: row.precedence,
    conditions: row.conditions || [],
    ttlSeconds: row.ttlSeconds,
    rateLimitPolicyId: row.rateLimitPolicyId,
    updatedAt: row.updatedAt,
    createdAt: row.createdAt,
  };
}

function presentEnforcementEvent(row = {}) {
  return {
    id: row.id,
    organizationId: row.organizationId,
    firewallInstanceId: row.firewallInstanceId,
    policyDecisionId: row.policyDecisionId,
    policyId: row.policyId,
    policyVersionId: row.policyVersionId,
    protectionRuleId: row.protectionRuleId,
    action: row.action,
    mode: row.mode,
    outcome: row.outcome,
    reason: row.reason,
    riskScore: row.riskScore,
    confidence: row.confidence,
    detectorReferences: row.detectorReferences || [],
    expiresAt: row.expiresAt,
    explanation: row.explanation || {},
    createdAt: row.createdAt,
  };
}

function presentRateLimitPolicy(row = {}) {
  return {
    id: row.id,
    organizationId: row.organizationId,
    firewallInstanceId: row.firewallInstanceId,
    name: row.name,
    status: row.status,
    dimension: row.dimension,
    limitCount: row.limitCount,
    windowSeconds: row.windowSeconds,
    burstCount: row.burstCount,
    updatedAt: row.updatedAt,
  };
}

function presentProtectionListEntry(row = {}) {
  return {
    id: row.id,
    organizationId: row.organizationId,
    firewallInstanceId: row.firewallInstanceId,
    entryType: row.entryType,
    entryLabel: row.entryLabel,
    reason: row.reason,
    status: row.status,
    expiresAt: row.expiresAt,
    updatedAt: row.updatedAt,
  };
}

function presentCredentialProtectionState(row = {}) {
  return {
    id: row.id,
    organizationId: row.organizationId,
    firewallInstanceId: row.firewallInstanceId,
    apiKeyId: row.apiKeyId,
    credentialLabel: row.credentialLabel,
    status: row.status,
    reason: row.reason,
    restrictedUntil: row.restrictedUntil,
    releasedAt: row.releasedAt,
    updatedAt: row.updatedAt,
  };
}

function isActive(row, now) {
  return row?.status === "active" && (!row.expiresAt || new Date(row.expiresAt).getTime() > now.getTime());
}

function actionExpiresAt(action, now) {
  if ([PROTECTION_ACTIONS.BLOCK, PROTECTION_ACTIONS.QUARANTINE, PROTECTION_ACTIONS.CREDENTIAL_SUSPEND].includes(action)) {
    return new Date(now.getTime() + 60 * 60 * 1000);
  }
  return null;
}

function outcomeForMode(mode) {
  if (mode === PROTECTION_MODES.ENFORCEMENT) return "applied";
  if (mode === PROTECTION_MODES.SIMULATION) return "simulated";
  return "observed";
}

function normalizeAction(action) {
  return enumValue(action, Object.values(PROTECTION_ACTIONS), "protection action");
}

function normalizeMode(mode) {
  const normalized = String(mode || "").trim().toLowerCase();
  if (normalized === "simulate") return PROTECTION_MODES.SIMULATION;
  if (normalized === "enforce") return PROTECTION_MODES.ENFORCEMENT;
  return enumValue(normalized || PROTECTION_MODES.OBSERVE, Object.values(PROTECTION_MODES), "protection mode");
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

function cleanToken(value, maxLength) {
  return cleanString(value, maxLength).toLowerCase().replace(/[^a-z0-9._:-]/g, "");
}

function comparable(value) {
  if (Array.isArray(value)) return value.map(comparable).join(",");
  return String(value ?? "").trim().toLowerCase();
}

function normalizeArray(value, maxItems, maxLength) {
  const items = Array.isArray(value) ? value : value ? [value] : [];
  return [...new Set(items.map((item) => cleanString(item, maxLength)).filter(Boolean))].slice(0, maxItems);
}

function fingerprintValue(value) {
  const text = cleanString(value, 1024);
  return text ? createHash("sha256").update(text.toLowerCase()).digest("hex") : "";
}

function clampScore(value) {
  const number = Number(value || 0);
  if (!Number.isFinite(number)) return 0;
  return Math.max(0, Math.min(100, Math.round(number)));
}

function clampConfidence(value) {
  const number = Number(value || 0);
  if (!Number.isFinite(number)) return 0;
  return Math.max(0, Math.min(1, Math.round(number * 100) / 100));
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
