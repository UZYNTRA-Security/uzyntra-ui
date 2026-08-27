import "server-only";

import { createHash } from "node:crypto";
import { and, desc, eq, gte, isNull, lte, or, sql } from "drizzle-orm";
import { db } from "../../db/client.js";
import {
  emergencyBypasses,
  firewallInstances,
  policyDecisions,
  securityEvents,
  zeroTrustPolicies,
  zeroTrustPolicyVersions,
} from "../../db/schema.js";
import { AUDIT_EVENT_TYPES, createAuditEvent } from "../audit/index.js";

export const ZERO_TRUST_DECISIONS = Object.freeze({
  ALLOW: "allow",
  CHALLENGE: "challenge",
  RATE_LIMIT: "rate_limit",
  BLOCK: "block",
  QUARANTINE: "quarantine",
});

export const ZERO_TRUST_MODES = Object.freeze({
  OBSERVE: "observe",
  SIMULATE: "simulate",
  ENFORCE: "enforce",
});

export const ZERO_TRUST_FAIL_BEHAVIORS = Object.freeze({
  FAIL_OPEN: "fail_open",
  FAIL_CLOSED: "fail_closed",
});

const MAX_POLICY_RULES = 50;
const MAX_RULE_CONDITIONS = 12;
const MAX_LIST_VALUES = 50;
const MAX_CONTEXT_KEYS = 80;
const MAX_CONTEXT_STRING = 512;
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;

const CONDITION_FIELDS = Object.freeze([
  "risk_score",
  "confidence",
  "severity",
  "http_method",
  "api_route",
  "source_ip",
  "country",
  "identity_type",
  "detector_id",
  "threat_reputation",
  "request_path",
]);

const CONDITION_OPERATORS = Object.freeze(["eq", "neq", "gte", "lte", "in", "contains"]);

const SENSITIVE_CONTEXT_KEYS = /password|secret|token|credential|authorization|cookie|session|private[_-]?key|api[_-]?key/i;

export async function createZeroTrustPolicy({
  database = db(),
  organizationId,
  userId,
  input = {},
  auditContext = {},
} = {}) {
  const values = normalizePolicyInput(input);
  if (values.firewallInstanceId) {
    await validateFirewallOwnership(database, organizationId, values.firewallInstanceId);
  }

  const [policy] = await database
    .insert(zeroTrustPolicies)
    .values({
      organizationId,
      firewallInstanceId: values.firewallInstanceId,
      name: values.name,
      description: values.description,
      status: values.status,
      mode: values.mode,
      failBehavior: values.failBehavior,
      createdByUserId: userId || null,
      metadata: values.metadata,
    })
    .returning();

  const version = await createZeroTrustPolicyVersion({
    database,
    organizationId,
    userId,
    policyId: policy.id,
    input: {
      policySnapshot: values.policySnapshot,
      status: "active",
    },
    auditContext,
    skipPolicyLookup: true,
  });

  const [updated] = await database
    .update(zeroTrustPolicies)
    .set({
      activeVersionId: version.id,
      activatedAt: new Date(),
      updatedAt: new Date(),
    })
    .where(eq(zeroTrustPolicies.id, policy.id))
    .returning();

  await auditZeroTrust({
    database,
    organizationId,
    userId,
    firewallInstanceId: policy.firewallInstanceId,
    eventType: AUDIT_EVENT_TYPES.ZERO_TRUST_POLICY_CREATED,
    action: "zero_trust_policy.create",
    resourceId: policy.id,
    requestId: auditContext.requestId,
    metadata: {
      mode: policy.mode,
      failBehavior: policy.failBehavior,
      activeVersionId: version.id,
    },
  });

  return presentPolicy({ ...updated, activeVersion: version });
}

export async function listZeroTrustPolicies({
  database = db(),
  organizationId,
  filters = {},
} = {}) {
  const query = await normalizeZeroTrustQuery({ database, organizationId, filters });
  const predicates = [eq(zeroTrustPolicies.organizationId, organizationId), isNull(zeroTrustPolicies.deletedAt)];
  if (query.firewallInstanceId) predicates.push(eq(zeroTrustPolicies.firewallInstanceId, query.firewallInstanceId));
  if (query.status) predicates.push(eq(zeroTrustPolicies.status, query.status));
  if (query.mode) predicates.push(eq(zeroTrustPolicies.mode, query.mode));

  const rows = await database
    .select()
    .from(zeroTrustPolicies)
    .where(and(...predicates))
    .orderBy(desc(zeroTrustPolicies.updatedAt))
    .limit(query.limit);

  return { items: rows.map(presentPolicy), pageInfo: { limit: query.limit, hasMore: rows.length === query.limit } };
}

export async function getZeroTrustPolicy({
  database = db(),
  organizationId,
  policyId,
} = {}) {
  const policy = await requirePolicy(database, organizationId, policyId);
  const versions = await database
    .select()
    .from(zeroTrustPolicyVersions)
    .where(and(eq(zeroTrustPolicyVersions.policyId, policy.id), eq(zeroTrustPolicyVersions.organizationId, organizationId)))
    .orderBy(desc(zeroTrustPolicyVersions.versionNumber))
    .limit(50);

  return presentPolicy({
    ...policy,
    versions: versions.map(presentPolicyVersion),
  });
}

export async function createZeroTrustPolicyVersion({
  database = db(),
  organizationId,
  userId,
  policyId,
  input = {},
  auditContext = {},
  skipPolicyLookup = false,
} = {}) {
  const policy = skipPolicyLookup
    ? { id: policyId, organizationId }
    : await requirePolicy(database, organizationId, policyId);
  const snapshot = normalizePolicySnapshot(input.policySnapshot || input);
  const digest = digestPolicySnapshot(snapshot);
  const [current] = await database
    .select({ maxVersion: sql`coalesce(max(${zeroTrustPolicyVersions.versionNumber}), 0)` })
    .from(zeroTrustPolicyVersions)
    .where(eq(zeroTrustPolicyVersions.policyId, policy.id));
  const versionNumber = Number(current?.maxVersion || 0) + 1;
  const previousVersionId = await currentActiveVersionId(database, policy.id);
  const status = enumValue(input.status || "draft", ["draft", "active"], "policy version status");
  const now = new Date();

  const [version] = await database
    .insert(zeroTrustPolicyVersions)
    .values({
      organizationId,
      policyId: policy.id,
      versionNumber,
      previousVersionId,
      status,
      policySnapshot: snapshot,
      policyDigest: digest,
      createdByUserId: userId || null,
      activatedAt: status === "active" ? now : null,
    })
    .returning();

  if (status === "active" && !skipPolicyLookup) {
    await setActiveVersion({ database, policyId: policy.id, versionId: version.id, now });
  }

  await auditZeroTrust({
    database,
    organizationId,
    userId,
    eventType: AUDIT_EVENT_TYPES.ZERO_TRUST_POLICY_UPDATED,
    action: "zero_trust_policy.version_create",
    resourceId: policy.id,
    requestId: auditContext.requestId,
    metadata: { versionId: version.id, versionNumber, status, digest },
  });

  return presentPolicyVersion(version);
}

export async function activateZeroTrustPolicyVersion({
  database = db(),
  organizationId,
  userId,
  policyId,
  versionId,
  auditContext = {},
} = {}) {
  const policy = await requirePolicy(database, organizationId, policyId);
  const version = await requirePolicyVersion(database, organizationId, policy.id, versionId);
  await setActiveVersion({ database, policyId: policy.id, versionId: version.id, now: new Date() });

  await auditZeroTrust({
    database,
    organizationId,
    userId,
    firewallInstanceId: policy.firewallInstanceId,
    eventType: AUDIT_EVENT_TYPES.ZERO_TRUST_POLICY_ACTIVATED,
    action: "zero_trust_policy.activate",
    resourceId: policy.id,
    requestId: auditContext.requestId,
    metadata: { versionId: version.id, versionNumber: version.versionNumber },
  });

  return getZeroTrustPolicy({ database, organizationId, policyId });
}

export async function rollbackZeroTrustPolicy({
  database = db(),
  organizationId,
  userId,
  policyId,
  targetVersionId,
  auditContext = {},
} = {}) {
  const policy = await requirePolicy(database, organizationId, policyId);
  const target = await requirePolicyVersion(database, organizationId, policy.id, targetVersionId);
  const rollback = await createZeroTrustPolicyVersion({
    database,
    organizationId,
    userId,
    policyId: policy.id,
    input: {
      policySnapshot: target.policySnapshot,
      status: "active",
    },
    auditContext,
  });

  await database
    .update(zeroTrustPolicyVersions)
    .set({ rollbackFromVersionId: target.id, updatedAt: new Date() })
    .where(eq(zeroTrustPolicyVersions.id, rollback.id));

  await auditZeroTrust({
    database,
    organizationId,
    userId,
    firewallInstanceId: policy.firewallInstanceId,
    eventType: AUDIT_EVENT_TYPES.ZERO_TRUST_POLICY_ROLLED_BACK,
    action: "zero_trust_policy.rollback",
    resourceId: policy.id,
    requestId: auditContext.requestId,
    metadata: { targetVersionId: target.id, newVersionId: rollback.id },
  });

  return getZeroTrustPolicy({ database, organizationId, policyId });
}

export async function listPolicyDecisions({
  database = db(),
  organizationId,
  filters = {},
} = {}) {
  const query = await normalizeZeroTrustQuery({ database, organizationId, filters, includeWindow: true });
  const predicates = [
    eq(policyDecisions.organizationId, organizationId),
    gte(policyDecisions.evaluatedAt, query.since),
    lte(policyDecisions.evaluatedAt, query.until),
  ];
  if (query.firewallInstanceId) predicates.push(eq(policyDecisions.firewallInstanceId, query.firewallInstanceId));
  if (query.decision) predicates.push(eq(policyDecisions.decision, query.decision));
  if (query.mode) predicates.push(eq(policyDecisions.mode, query.mode));

  const rows = await database
    .select()
    .from(policyDecisions)
    .where(and(...predicates))
    .orderBy(desc(policyDecisions.evaluatedAt))
    .limit(query.limit);

  return { items: rows.map(presentPolicyDecision), filters: query, pageInfo: { limit: query.limit, hasMore: rows.length === query.limit } };
}

export async function recordPolicyDecision({
  database = db(),
  organizationId,
  input = {},
  auditContext = {},
} = {}) {
  const values = normalizeDecisionInput({ ...input, organizationId });
  if (values.firewallInstanceId) await validateFirewallOwnership(database, organizationId, values.firewallInstanceId);
  const [row] = await database.insert(policyDecisions).values(values).returning();

  if (values.decision !== ZERO_TRUST_DECISIONS.ALLOW) {
    await auditZeroTrust({
      database,
      organizationId,
      firewallInstanceId: values.firewallInstanceId,
      eventType: AUDIT_EVENT_TYPES.ZERO_TRUST_DECISION_RECORDED,
      action: "zero_trust_policy.decision",
      resourceId: row.id,
      requestId: auditContext.requestId,
      metadata: {
        decision: values.decision,
        mode: values.mode,
        riskScore: values.riskScore,
        policyId: values.policyId || null,
      },
    });
  }

  return presentPolicyDecision(row);
}

export async function simulateZeroTrustPolicy({
  database = db(),
  organizationId,
  userId,
  input = {},
  auditContext = {},
} = {}) {
  const context = buildZeroTrustEvaluationContext(input.context || input);
  const policyId = cleanString(input.policyId, 160);
  let policy = null;
  let version = null;
  if (policyId) {
    policy = await requirePolicy(database, organizationId, policyId);
    version = await activePolicyVersion(database, organizationId, policy);
  }

  const snapshot = version?.policySnapshot || normalizePolicySnapshot(input.policySnapshot || input.policy || {});
  const result = evaluateZeroTrustPolicy({
    policy,
    policyVersion: version ? { ...version, policySnapshot: snapshot } : { policySnapshot: snapshot },
    context,
    modeOverride: ZERO_TRUST_MODES.SIMULATE,
  });

  await auditZeroTrust({
    database,
    organizationId,
    userId,
    firewallInstanceId: policy?.firewallInstanceId || context.firewallInstanceId || null,
    eventType: AUDIT_EVENT_TYPES.ZERO_TRUST_POLICY_SIMULATED,
    action: "zero_trust_policy.simulate",
    resourceId: policy?.id || null,
    requestId: auditContext.requestId,
    metadata: {
      decision: result.decision,
      riskScore: result.riskScore,
      matchedRuleId: result.matchedRuleId || null,
    },
  });

  return result;
}

export function evaluateZeroTrustPolicy({
  policy = {},
  policyVersion = {},
  context = {},
  emergencyBypass = null,
  modeOverride,
  now = new Date(),
} = {}) {
  const mode = enumValue(modeOverride || policy.mode || ZERO_TRUST_MODES.OBSERVE, Object.values(ZERO_TRUST_MODES), "policy mode");
  const failBehavior = enumValue(policy.failBehavior || ZERO_TRUST_FAIL_BEHAVIORS.FAIL_OPEN, Object.values(ZERO_TRUST_FAIL_BEHAVIORS), "fail behavior");
  const normalizedContext = buildZeroTrustEvaluationContext(context);

  try {
    if (emergencyBypass && isBypassActive(emergencyBypass, now)) {
      return decisionResult({
        decision: ZERO_TRUST_DECISIONS.ALLOW,
        reason: "emergency_bypass_active",
        mode,
        failBehavior,
        context: normalizedContext,
        policy,
        policyVersion,
        matchedRule: null,
        riskScore: normalizedContext.riskScore,
        confidence: normalizedContext.confidence,
        enforcementMetadata: { bypassId: emergencyBypass.id || null, enforcedDecision: "allow" },
      });
    }

    const snapshot = normalizePolicySnapshot(policyVersion.policySnapshot || {});
    for (const rule of snapshot.rules) {
      if (rule.conditions.every((condition) => matchesCondition(normalizedContext, condition))) {
        return decisionResult({
          decision: rule.decision,
          reason: rule.reason || `matched rule ${rule.name}`,
          mode,
          failBehavior,
          context: normalizedContext,
          policy,
          policyVersion,
          matchedRule: rule,
          riskScore: normalizedContext.riskScore,
          confidence: normalizedContext.confidence,
        });
      }
    }

    return decisionResult({
      decision: snapshot.defaultDecision,
      reason: "default_policy_decision",
      mode,
      failBehavior,
      context: normalizedContext,
      policy,
      policyVersion,
      matchedRule: null,
      riskScore: normalizedContext.riskScore,
      confidence: normalizedContext.confidence,
    });
  } catch (error) {
    const decision = failBehavior === ZERO_TRUST_FAIL_BEHAVIORS.FAIL_CLOSED
      ? ZERO_TRUST_DECISIONS.BLOCK
      : ZERO_TRUST_DECISIONS.ALLOW;
    return decisionResult({
      decision,
      reason: "policy_evaluation_failed",
      mode,
      failBehavior,
      context: normalizedContext,
      policy,
      policyVersion,
      matchedRule: null,
      riskScore: normalizedContext.riskScore,
      confidence: 0.1,
      enforcementMetadata: { errorClass: "evaluation_error" },
      errors: [error.message || "evaluation failed"],
    });
  }
}

export function buildZeroTrustEvaluationContext(input = {}) {
  const event = input.event || input.securityEvent || {};
  const request = input.requestContext || input.request || {};
  const identity = input.identityContext || input.identity || {};
  const threat = input.threatContext || input.threatIntel || {};
  const riskScore = clampScore(input.riskScore ?? event.score ?? threat.reputationScore ?? 0);
  const confidence = clampConfidence(input.confidence ?? event.confidence ?? threat.confidence ?? 0.5);
  const detectorIds = normalizeArray(input.detectorIds || event.detectorIds || event.detectorId || [], 40, 80);
  if (event.detectorId && !detectorIds.includes(event.detectorId)) detectorIds.unshift(cleanToken(event.detectorId, 80));

  return sanitizeContext({
    organizationId: cleanString(input.organizationId || event.organizationId, 160),
    firewallInstanceId: cleanString(input.firewallInstanceId || event.firewallInstanceId, 160),
    securityEventId: cleanString(input.securityEventId || event.id, 160),
    riskScore,
    confidence,
    severity: cleanToken(input.severity || event.severity || severityFromScore(riskScore), 32),
    httpMethod: cleanToken(input.httpMethod || request.httpMethod || event.httpMethod, 16),
    apiRoute: cleanString(input.apiRoute || event.apiRouteId || request.apiRoute, 240),
    requestPath: cleanString(input.requestPath || event.requestPath || request.path, 240),
    sourceIp: cleanString(input.sourceIp || event.sourceIp || request.sourceIp, 45),
    country: cleanToken(input.country || event.country || request.country, 8),
    userAgent: cleanString(input.userAgent || event.userAgent || request.userAgent, 240),
    identityType: cleanToken(input.identityType || identity.type || identity.identityType || "unknown", 64),
    identityFingerprint: cleanString(input.identityFingerprint || identity.fingerprint, 128),
    detectorIds,
    threatReputation: cleanToken(input.threatReputation || threat.reputation || threat.category || "unknown", 80),
    threatScore: clampScore(input.threatScore ?? threat.riskDelta ?? threat.reputationScore ?? 0),
    raw: sanitizeContext({ request, identity, threat }, 2),
  });
}

export function normalizePolicySnapshot(input = {}) {
  const defaultDecision = enumValue(input.defaultDecision || ZERO_TRUST_DECISIONS.ALLOW, Object.values(ZERO_TRUST_DECISIONS), "default decision");
  const rules = Array.isArray(input.rules) ? input.rules.slice(0, MAX_POLICY_RULES).map(normalizeRule) : [];
  if (Array.isArray(input.rules) && input.rules.length > MAX_POLICY_RULES) {
    throw new Error("policy rule count exceeds limit");
  }

  return {
    version: "8.4.v1",
    defaultDecision,
    rules,
  };
}

export async function listEmergencyBypasses({
  database = db(),
  organizationId,
  filters = {},
} = {}) {
  const query = await normalizeZeroTrustQuery({ database, organizationId, filters });
  const predicates = [eq(emergencyBypasses.organizationId, organizationId)];
  if (query.firewallInstanceId) predicates.push(eq(emergencyBypasses.firewallInstanceId, query.firewallInstanceId));
  if (query.status) predicates.push(eq(emergencyBypasses.status, query.status));

  const rows = await database
    .select()
    .from(emergencyBypasses)
    .where(and(...predicates))
    .orderBy(desc(emergencyBypasses.createdAt))
    .limit(query.limit);

  return { items: rows.map(presentEmergencyBypass) };
}

export async function createEmergencyBypass({
  database = db(),
  organizationId,
  userId,
  input = {},
  auditContext = {},
} = {}) {
  const reason = requiredString(input.reason, "reason", 2000);
  const firewallInstanceId = cleanString(input.firewallInstanceId, 160);
  if (firewallInstanceId) await validateFirewallOwnership(database, organizationId, firewallInstanceId);
  const expiresAt = parseDate(input.expiresAt) || new Date(Date.now() + 15 * 60 * 1000);
  const maxExpiry = Date.now() + 4 * 60 * 60 * 1000;
  if (expiresAt.getTime() > maxExpiry) throw new Error("emergency bypass duration is limited to four hours");

  const [row] = await database
    .insert(emergencyBypasses)
    .values({
      organizationId,
      firewallInstanceId,
      reason,
      expiresAt,
      createdByUserId: userId || null,
      metadata: sanitizeContext(input.metadata || {}),
    })
    .returning();

  await auditZeroTrust({
    database,
    organizationId,
    userId,
    firewallInstanceId,
    eventType: AUDIT_EVENT_TYPES.EMERGENCY_BYPASS_CREATED,
    action: "emergency_bypass.create",
    resourceId: row.id,
    requestId: auditContext.requestId,
    metadata: { expiresAt: row.expiresAt, scopedToFirewall: Boolean(firewallInstanceId) },
  });

  return presentEmergencyBypass(row);
}

export async function normalizeZeroTrustQuery({
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
    throw new Error("zero trust query window is limited to 90 days");
  }
  const firewallInstanceId = cleanString(filters.firewallInstanceId, 160);
  if (firewallInstanceId) await validateFirewallOwnership(database, organizationId, firewallInstanceId);

  return {
    firewallInstanceId,
    status: filters.status ? cleanToken(filters.status, 32) : null,
    mode: filters.mode ? enumValue(filters.mode, Object.values(ZERO_TRUST_MODES), "mode") : null,
    decision: filters.decision ? enumValue(filters.decision, Object.values(ZERO_TRUST_DECISIONS), "decision") : null,
    since,
    until,
    limit: limitValue(filters.limit, MAX_LIMIT),
  };
}

function normalizePolicyInput(input = {}) {
  return {
    firewallInstanceId: cleanString(input.firewallInstanceId, 160),
    name: requiredString(input.name, "name", 160),
    description: cleanString(input.description, 2000),
    status: enumValue(input.status || "active", ["active", "disabled"], "policy status"),
    mode: enumValue(input.mode || ZERO_TRUST_MODES.OBSERVE, Object.values(ZERO_TRUST_MODES), "policy mode"),
    failBehavior: enumValue(input.failBehavior || ZERO_TRUST_FAIL_BEHAVIORS.FAIL_OPEN, Object.values(ZERO_TRUST_FAIL_BEHAVIORS), "fail behavior"),
    policySnapshot: normalizePolicySnapshot(input.policySnapshot || input),
    metadata: sanitizeContext(input.metadata || {}),
  };
}

function normalizeRule(rule = {}, index = 0) {
  const conditions = Array.isArray(rule.conditions) ? rule.conditions : [];
  if (conditions.length > MAX_RULE_CONDITIONS) throw new Error("policy rule condition count exceeds limit");
  return {
    id: cleanToken(rule.id, 80) || `rule-${index + 1}`,
    name: requiredString(rule.name || `Rule ${index + 1}`, "rule name", 160),
    decision: enumValue(rule.decision, Object.values(ZERO_TRUST_DECISIONS), "rule decision"),
    reason: cleanString(rule.reason, 240) || "zero_trust_rule_match",
    conditions: conditions.map(normalizeCondition),
  };
}

function normalizeCondition(condition = {}) {
  const field = enumValue(condition.field, CONDITION_FIELDS, "condition field");
  const operator = enumValue(condition.operator || "eq", CONDITION_OPERATORS, "condition operator");
  return {
    field,
    operator,
    value: normalizeConditionValue(condition.value),
  };
}

function normalizeConditionValue(value) {
  if (Array.isArray(value)) {
    if (value.length > MAX_LIST_VALUES) throw new Error("condition list exceeds limit");
    return value.map((item) => cleanString(item, MAX_CONTEXT_STRING));
  }
  if (typeof value === "number" || typeof value === "boolean") return value;
  return cleanString(value, MAX_CONTEXT_STRING);
}

function matchesCondition(context, condition) {
  const actual = contextValue(context, condition.field);
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

function contextValue(context, field) {
  const map = {
    risk_score: context.riskScore,
    confidence: context.confidence,
    severity: context.severity,
    http_method: context.httpMethod,
    api_route: context.apiRoute,
    source_ip: context.sourceIp,
    country: context.country,
    identity_type: context.identityType,
    detector_id: context.detectorIds,
    threat_reputation: context.threatReputation,
    request_path: context.requestPath,
  };
  return map[field];
}

function decisionResult({
  decision,
  reason,
  mode,
  failBehavior,
  context,
  policy,
  policyVersion,
  matchedRule,
  riskScore,
  confidence,
  enforcementMetadata = {},
  errors = [],
}) {
  const effectiveDecision = mode === ZERO_TRUST_MODES.ENFORCE ? decision : ZERO_TRUST_DECISIONS.ALLOW;
  return {
    decision,
    effectiveDecision,
    mode,
    failBehavior,
    decisionReason: reason,
    riskScore: clampScore(riskScore),
    confidence: clampConfidence(confidence),
    matchedRuleId: matchedRule?.id || null,
    policyId: policy?.id || null,
    policyVersionId: policyVersion?.id || null,
    organizationId: context.organizationId || policy?.organizationId || null,
    firewallInstanceId: context.firewallInstanceId || policy?.firewallInstanceId || null,
    securityEventId: context.securityEventId || null,
    detectorReferences: normalizeArray(context.detectorIds || [], 40, 80),
    threatIntelReferences: normalizeArray(enforcementMetadata.threatIntelReferences || [], 40, 160),
    enforcementMetadata: sanitizeContext({
      ...enforcementMetadata,
      enforcedDecision: effectiveDecision,
      observeOnly: mode !== ZERO_TRUST_MODES.ENFORCE,
    }),
    explanation: sanitizeContext({
      matchedRule: matchedRule ? { id: matchedRule.id, name: matchedRule.name, conditions: matchedRule.conditions } : null,
      reason,
      errors,
      contextSummary: {
        riskScore: clampScore(riskScore),
        confidence: clampConfidence(confidence),
        severity: context.severity,
        apiRoute: context.apiRoute,
        threatReputation: context.threatReputation,
      },
    }),
  };
}

function normalizeDecisionInput(input = {}) {
  const context = buildZeroTrustEvaluationContext(input.context || input);
  return {
    organizationId: requiredString(input.organizationId || context.organizationId, "organizationId", 160),
    firewallInstanceId: cleanString(input.firewallInstanceId || context.firewallInstanceId, 160),
    securityEventId: cleanString(input.securityEventId || context.securityEventId, 160),
    policyId: cleanString(input.policyId, 160),
    policyVersionId: cleanString(input.policyVersionId, 160),
    correlationEventId: cleanString(input.correlationEventId, 160),
    alertId: cleanString(input.alertId, 160),
    incidentId: cleanString(input.incidentId, 160),
    decision: enumValue(input.decision, Object.values(ZERO_TRUST_DECISIONS), "decision"),
    decisionReason: requiredString(input.decisionReason || input.reason, "decisionReason", 240),
    mode: enumValue(input.mode || ZERO_TRUST_MODES.OBSERVE, Object.values(ZERO_TRUST_MODES), "mode"),
    failBehavior: enumValue(input.failBehavior || ZERO_TRUST_FAIL_BEHAVIORS.FAIL_OPEN, Object.values(ZERO_TRUST_FAIL_BEHAVIORS), "fail behavior"),
    riskScore: clampScore(input.riskScore),
    confidence: clampConfidence(input.confidence),
    identityContext: sanitizeContext(input.identityContext || context.raw?.identity || {}),
    requestContext: sanitizeContext(input.requestContext || context.raw?.request || {}),
    detectorReferences: normalizeArray(input.detectorReferences || context.detectorIds || [], 40, 80),
    threatIntelReferences: normalizeArray(input.threatIntelReferences || [], 40, 160),
    enforcementMetadata: sanitizeContext(input.enforcementMetadata || {}),
    explanation: sanitizeContext(input.explanation || {}),
    evaluatedAt: parseDate(input.evaluatedAt) || new Date(),
  };
}

async function requirePolicy(database, organizationId, policyId) {
  const id = requiredString(policyId, "policyId", 160);
  const [policy] = await database
    .select()
    .from(zeroTrustPolicies)
    .where(and(eq(zeroTrustPolicies.id, id), eq(zeroTrustPolicies.organizationId, organizationId), isNull(zeroTrustPolicies.deletedAt)))
    .limit(1);
  if (!policy) throw new Error("zero trust policy not found");
  return policy;
}

async function requirePolicyVersion(database, organizationId, policyId, versionId) {
  const id = requiredString(versionId, "versionId", 160);
  const [version] = await database
    .select()
    .from(zeroTrustPolicyVersions)
    .where(
      and(
        eq(zeroTrustPolicyVersions.id, id),
        eq(zeroTrustPolicyVersions.organizationId, organizationId),
        eq(zeroTrustPolicyVersions.policyId, policyId),
      ),
    )
    .limit(1);
  if (!version) throw new Error("zero trust policy version not found");
  return version;
}

async function activePolicyVersion(database, organizationId, policy) {
  if (!policy.activeVersionId) throw new Error("zero trust policy has no active version");
  return requirePolicyVersion(database, organizationId, policy.id, policy.activeVersionId);
}

async function currentActiveVersionId(database, policyId) {
  const [policy] = await database
    .select({ activeVersionId: zeroTrustPolicies.activeVersionId })
    .from(zeroTrustPolicies)
    .where(eq(zeroTrustPolicies.id, policyId))
    .limit(1);
  return policy?.activeVersionId || null;
}

async function setActiveVersion({ database, policyId, versionId, now }) {
  await database
    .update(zeroTrustPolicyVersions)
    .set({ status: "retired", retiredAt: now, updatedAt: now })
    .where(and(eq(zeroTrustPolicyVersions.policyId, policyId), eq(zeroTrustPolicyVersions.status, "active")));
  await database
    .update(zeroTrustPolicyVersions)
    .set({ status: "active", activatedAt: now, retiredAt: null, updatedAt: now })
    .where(eq(zeroTrustPolicyVersions.id, versionId));
  await database
    .update(zeroTrustPolicies)
    .set({ activeVersionId: versionId, activatedAt: now, updatedAt: now })
    .where(eq(zeroTrustPolicies.id, policyId));
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

async function auditZeroTrust({
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
    resourceType: "zero_trust_policy",
    resourceId,
    result: "success",
    severity: "info",
    requestId,
    metadata: sanitizeContext(metadata || {}),
  });
}

function presentPolicy(row = {}) {
  return {
    id: row.id,
    organizationId: row.organizationId,
    firewallInstanceId: row.firewallInstanceId,
    name: row.name,
    description: row.description,
    status: row.status,
    mode: row.mode,
    failBehavior: row.failBehavior,
    activeVersionId: row.activeVersionId,
    activeVersion: row.activeVersion || null,
    versions: row.versions || undefined,
    activatedAt: row.activatedAt,
    updatedAt: row.updatedAt,
    createdAt: row.createdAt,
  };
}

function presentPolicyVersion(row = {}) {
  return {
    id: row.id,
    policyId: row.policyId,
    versionNumber: row.versionNumber,
    previousVersionId: row.previousVersionId,
    rollbackFromVersionId: row.rollbackFromVersionId,
    status: row.status,
    policySnapshot: row.policySnapshot,
    policyDigest: row.policyDigest,
    activatedAt: row.activatedAt,
    retiredAt: row.retiredAt,
    createdAt: row.createdAt,
  };
}

function presentPolicyDecision(row = {}) {
  return {
    id: row.id,
    organizationId: row.organizationId,
    firewallInstanceId: row.firewallInstanceId,
    securityEventId: row.securityEventId,
    policyId: row.policyId,
    policyVersionId: row.policyVersionId,
    decision: row.decision,
    decisionReason: row.decisionReason,
    mode: row.mode,
    failBehavior: row.failBehavior,
    riskScore: row.riskScore,
    confidence: row.confidence,
    detectorReferences: row.detectorReferences || [],
    threatIntelReferences: row.threatIntelReferences || [],
    enforcementMetadata: row.enforcementMetadata || {},
    explanation: row.explanation || {},
    evaluatedAt: row.evaluatedAt,
  };
}

function presentEmergencyBypass(row = {}) {
  return {
    id: row.id,
    organizationId: row.organizationId,
    firewallInstanceId: row.firewallInstanceId,
    reason: row.reason,
    status: row.status,
    expiresAt: row.expiresAt,
    usedAt: row.usedAt,
    revokedAt: row.revokedAt,
    createdAt: row.createdAt,
  };
}

function digestPolicySnapshot(snapshot) {
  return createHash("sha256").update(stableStringify(snapshot)).digest("hex");
}

function stableStringify(value) {
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sanitizeContext(value, depth = 0) {
  if (value == null) return value;
  if (depth > 4) return "[truncated]";
  if (Array.isArray(value)) return value.slice(0, MAX_LIST_VALUES).map((item) => sanitizeContext(item, depth + 1));
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .slice(0, MAX_CONTEXT_KEYS)
        .filter(([key]) => !SENSITIVE_CONTEXT_KEYS.test(key))
        .map(([key, child]) => [cleanString(key, 80), sanitizeContext(child, depth + 1)]),
    );
  }
  if (typeof value === "number" || typeof value === "boolean") return value;
  return cleanString(value, MAX_CONTEXT_STRING);
}

function isBypassActive(bypass, now) {
  return bypass.status === "active" && new Date(bypass.expiresAt).getTime() > now.getTime();
}

function severityFromScore(score) {
  if (score >= 90) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
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
