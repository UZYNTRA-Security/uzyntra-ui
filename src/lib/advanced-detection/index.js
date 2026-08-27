import "server-only";

import { createHash } from "node:crypto";
import { and, desc, eq, gte, isNull, lte, or, sql } from "drizzle-orm";
import { db } from "../../db/client.js";
import {
  apiInventoryRoutes,
  behavioralBaselines,
  correlationEvents,
  detectionFindings,
  detectorConfigurations,
  detectorFeedback,
  firewallInstances,
  securityEvents,
} from "../../db/schema.js";
import { createAuditEvent } from "../audit/index.js";
import { enrichEventWithThreatIntelligence } from "../threat-intelligence/index.js";

const DEFAULT_WINDOW_SECONDS = 900;
const MAX_RECENT_EVENTS = 500;
const DEFAULT_DETECTOR_THRESHOLD = 0.5;

export const ADVANCED_DETECTORS = Object.freeze({
  BEHAVIOR_UNUSUAL_ACCESS: "behavior.unusual_access",
  BEHAVIOR_ENDPOINT_DISCOVERY: "behavior.endpoint_discovery",
  BEHAVIOR_ABNORMAL_SEQUENCE: "behavior.abnormal_sequence",
  BEHAVIOR_RECONNAISSANCE: "behavior.reconnaissance",
  BEHAVIOR_CLIENT_CHANGE: "behavior.client_change",
  ABUSE_CREDENTIAL_STUFFING: "abuse.credential_stuffing",
  ABUSE_TOKEN_REPLAY: "abuse.token_replay",
  ABUSE_OBJECT_ENUMERATION: "abuse.object_enumeration",
  ABUSE_SCRAPER: "abuse.scraper",
  ABUSE_SCANNER: "abuse.scanner",
  CORRELATION_ATTACK_CHAIN: "correlation.attack_chain",
});

export async function runAdvancedDetectionForEvent({
  database = db(),
  event,
  now = new Date(),
  windowSeconds = DEFAULT_WINDOW_SECONDS,
} = {}) {
  if (!event?.id) throw new Error("security event is required for advanced detection");

  const windowStart = new Date(new Date(event.occurredAt || now).getTime() - windowSeconds * 1000);
  const recentEvents = await listRecentEvents({ database, event, windowStart });
  const apiContext = await getApiRiskContext({ database, event });
  const detectorConfig = await getDetectorConfigMap({ database, event });
  const baseline = await upsertBehaviorBaseline({ database, event, recentEvents, now });
  const threatIntel = await enrichEventWithThreatIntelligence({ database, event });
  const context = buildDetectionContext({
    event,
    recentEvents,
    apiContext,
    detectorConfig,
    baseline,
    threatIntel,
    windowStart,
    windowEnd: now,
  });

  const candidateFindings = buildBehavioralFindings(context).filter((finding) =>
    detectorEnabled(detectorConfig, finding.detectorId),
  );
  const findings = [];
  for (const candidate of candidateFindings) {
    if (candidate.confidence < detectorThreshold(detectorConfig, candidate.detectorId)) continue;
    findings.push(await upsertDetectionFinding({ database, event, candidate, now }));
  }

  const correlations = [];
  const correlation = buildCorrelationCandidate(context, findings);
  if (correlation && detectorEnabled(detectorConfig, correlation.detectorId)) {
    correlations.push(await upsertCorrelationEvent({ database, event, candidate: correlation, now }));
  }

  return {
    findings,
    correlations,
    baseline,
    context: summarizeContext(context),
  };
}

export function calculateCompositeRisk({ event, signals = [], apiContext = {}, tenantContext = {}, threatIntel = {} } = {}) {
  const eventRisk = clampScore(Number(event?.score ?? severityWeight(event?.severity)));
  const clientRisk = clampScore(Math.max(0, ...signals.map((signal) => Number(signal.clientRisk || 0))));
  const apiRisk = clampScore(
    (apiContext.isShadow ? 30 : 0) +
      (apiContext.isSensitive ? 30 : 0) +
      (apiContext.isDeprecated ? 20 : 0) +
      (apiContext.isUnknown ? 15 : 0),
  );
  const tenantRisk = clampScore(
    (tenantContext.activeIncidents || 0) * 8 + (tenantContext.openCriticalAlerts || 0) * 10,
  );
  const threatRisk = clampScore(Number(threatIntel.riskDelta || 0));
  const overall = clampScore(
    eventRisk * 0.38 + clientRisk * 0.22 + apiRisk * 0.16 + tenantRisk * 0.09 + threatRisk * 0.15,
  );
  const confidence = clampConfidence(
    Math.min(
      1,
      Math.max(
        Number(event?.confidence ?? 0.45),
        Math.min(0.95, 0.35 + signals.length * 0.12 + (apiContext.isSensitive ? 0.1 : 0)),
      ) + Number(threatIntel.confidenceDelta || 0),
    ),
  );

  return {
    score: Math.round(overall),
    severity: mapSeverity(overall, confidence),
    confidence,
    components: {
      event: Math.round(eventRisk),
      client: Math.round(clientRisk),
      api: Math.round(apiRisk),
      tenant: Math.round(tenantRisk),
      threat: Math.round(threatRisk),
    },
    factors: signals.map((signal) => signal.reasonCode).filter(Boolean).slice(0, 20),
    version: "8.2.v1",
  };
}

export function classifyThreatContext(event = {}) {
  const userAgent = String(event.userAgent || "").toLowerCase();
  const scanner = /sqlmap|nuclei|nikto|masscan|zgrab|acunetix|burp|zap|dirbuster/.test(userAgent);
  const automation = /curl|python-requests|go-http-client|httpclient|wget|axios/.test(userAgent);
  const country = event.country || null;

  return {
    ipReputation: scanner ? "suspicious" : "unknown",
    asn: null,
    geo: country ? { country } : null,
    userAgentFamily: scanner ? "scanner" : automation ? "automation" : "browser_or_unknown",
    scannerSignature: scanner ? userAgent.slice(0, 120) : null,
    confidence: scanner ? 0.86 : automation ? 0.55 : 0.35,
  };
}

export function evaluateAdvancedDetectionCandidates({
  event,
  recentEvents = [],
  apiContext = {},
  now = new Date(),
  threatIntel = {},
} = {}) {
  const windowStart = new Date(now.getTime() - DEFAULT_WINDOW_SECONDS * 1000);
  const context = buildDetectionContext({
    event,
    recentEvents,
    apiContext,
    detectorConfig: new Map(),
    baseline: null,
    threatIntel,
    windowStart,
    windowEnd: now,
  });
  const findings = buildBehavioralFindings(context);
  return {
    findings,
    correlation: buildCorrelationCandidate(context, findings),
    context: summarizeContext(context),
  };
}

export async function listDetectionFindings({
  database = db(),
  organizationId,
  filters = {},
} = {}) {
  const query = await normalizeAdvancedDetectionQuery({ database, organizationId, filters });
  const predicates = [
    eq(detectionFindings.organizationId, organizationId),
    gte(detectionFindings.lastSeenAt, query.since),
    lte(detectionFindings.lastSeenAt, query.until),
  ];
  if (query.firewallInstanceId) predicates.push(eq(detectionFindings.firewallInstanceId, query.firewallInstanceId));
  if (query.status) predicates.push(eq(detectionFindings.status, query.status));
  if (query.detectorId) predicates.push(eq(detectionFindings.detectorId, query.detectorId));

  const items = await database
    .select()
    .from(detectionFindings)
    .where(and(...predicates))
    .orderBy(desc(detectionFindings.lastSeenAt), desc(detectionFindings.riskScore))
    .limit(query.limit);

  return { items, filters: query, pageInfo: { limit: query.limit, hasMore: items.length === query.limit } };
}

export async function listCorrelationEvents({
  database = db(),
  organizationId,
  filters = {},
} = {}) {
  const query = await normalizeAdvancedDetectionQuery({ database, organizationId, filters });
  const predicates = [
    eq(correlationEvents.organizationId, organizationId),
    gte(correlationEvents.windowEnd, query.since),
    lte(correlationEvents.windowEnd, query.until),
  ];
  if (query.firewallInstanceId) predicates.push(eq(correlationEvents.firewallInstanceId, query.firewallInstanceId));
  if (query.status) predicates.push(eq(correlationEvents.status, query.status));

  const items = await database
    .select()
    .from(correlationEvents)
    .where(and(...predicates))
    .orderBy(desc(correlationEvents.windowEnd), desc(correlationEvents.riskScore))
    .limit(query.limit);

  return { items, filters: query, pageInfo: { limit: query.limit, hasMore: items.length === query.limit } };
}

export async function getRiskAnalysis({ database = db(), organizationId, filters = {} } = {}) {
  const query = await normalizeAdvancedDetectionQuery({ database, organizationId, filters });
  const findingWhere = scopedTimeWhere(detectionFindings, organizationId, query, detectionFindings.lastSeenAt);
  const correlationWhere = scopedTimeWhere(correlationEvents, organizationId, query, correlationEvents.windowEnd);

  const [findingSummary] = await database
    .select({
      total: sql`count(*)`,
      critical: sql`sum(case when ${detectionFindings.severity} = 'critical' then 1 else 0 end)`,
      high: sql`sum(case when ${detectionFindings.severity} = 'high' then 1 else 0 end)`,
      avgRisk: sql`avg(${detectionFindings.riskScore})`,
      maxRisk: sql`max(${detectionFindings.riskScore})`,
      avgConfidence: sql`avg(${detectionFindings.confidence})`,
    })
    .from(detectionFindings)
    .where(findingWhere);

  const [correlationSummary] = await database
    .select({
      total: sql`count(*)`,
      critical: sql`sum(case when ${correlationEvents.severity} = 'critical' then 1 else 0 end)`,
      avgRisk: sql`avg(${correlationEvents.riskScore})`,
    })
    .from(correlationEvents)
    .where(correlationWhere);

  const topDetectors = await database
    .select({ detectorId: detectionFindings.detectorId, count: sql`count(*)`, avgRisk: sql`avg(${detectionFindings.riskScore})` })
    .from(detectionFindings)
    .where(findingWhere)
    .groupBy(detectionFindings.detectorId)
    .orderBy(sql`count(*) desc`)
    .limit(10);

  const baselineRows = await database
    .select()
    .from(behavioralBaselines)
    .where(
      and(
        eq(behavioralBaselines.organizationId, organizationId),
        ...(query.firewallInstanceId ? [eq(behavioralBaselines.firewallInstanceId, query.firewallInstanceId)] : []),
      ),
    )
    .orderBy(desc(behavioralBaselines.learnedAt))
    .limit(20);

  return {
    summary: {
      findings: numberSummary(findingSummary),
      correlations: numberSummary(correlationSummary),
      compositeRisk: Math.round(Math.max(numberValue(findingSummary?.maxRisk), numberValue(correlationSummary?.avgRisk))),
    },
    topDetectors: topDetectors.map((row) => ({
      detectorId: row.detectorId,
      count: numberValue(row.count),
      avgRisk: Math.round(numberValue(row.avgRisk)),
    })),
    baselines: baselineRows.map(presentBaseline),
    filters: query,
  };
}

export async function listDetectorConfigurations({
  database = db(),
  organizationId,
  filters = {},
} = {}) {
  const predicates = [eq(detectorConfigurations.organizationId, organizationId), isNull(detectorConfigurations.deletedAt)];
  if (filters.firewallInstanceId) {
    await validateFirewallOwnership(database, organizationId, filters.firewallInstanceId);
    predicates.push(eq(detectorConfigurations.firewallInstanceId, filters.firewallInstanceId));
  }
  if (filters.status) predicates.push(eq(detectorConfigurations.status, enumValue(filters.status, ["active", "observe", "disabled", "deleted"], "detector status")));

  const configured = await database
    .select()
    .from(detectorConfigurations)
    .where(and(...predicates))
    .orderBy(detectorConfigurations.detectorId)
    .limit(limitValue(filters.limit, 100));

  return { items: configured.map(presentDetectorConfiguration) };
}

export async function upsertDetectorConfiguration({
  database = db(),
  organizationId,
  userId,
  input = {},
  auditContext = {},
} = {}) {
  const values = normalizeDetectorConfigurationInput(input);
  if (values.firewallInstanceId) await validateFirewallOwnership(database, organizationId, values.firewallInstanceId);

  const [existing] = await database
    .select()
    .from(detectorConfigurations)
    .where(
      and(
        eq(detectorConfigurations.organizationId, organizationId),
        values.firewallInstanceId
          ? eq(detectorConfigurations.firewallInstanceId, values.firewallInstanceId)
          : isNull(detectorConfigurations.firewallInstanceId),
        eq(detectorConfigurations.detectorId, values.detectorId),
        isNull(detectorConfigurations.deletedAt),
      ),
    )
    .limit(1);

  const payload = {
    ...values,
    organizationId,
    createdByUserId: userId || existing?.createdByUserId || null,
    updatedAt: new Date(),
  };

  const [row] = existing
    ? await database
        .update(detectorConfigurations)
        .set(payload)
        .where(eq(detectorConfigurations.id, existing.id))
        .returning()
    : await database.insert(detectorConfigurations).values(payload).returning();

  await createAuditEvent({
    database,
    organizationId,
    userId,
    firewallInstanceId: values.firewallInstanceId,
    eventType: "detector.configuration.updated",
    action: "detector_configuration.upsert",
    resourceType: "detector_configuration",
    resourceId: row.id,
    result: "success",
    severity: "info",
    requestId: auditContext.requestId,
    metadata: {
      detectorId: row.detectorId,
      status: row.status,
      confidenceThreshold: row.confidenceThreshold,
    },
  });

  return presentDetectorConfiguration(row);
}

export async function createDetectorFeedback({
  database = db(),
  organizationId,
  userId,
  input = {},
  auditContext = {},
} = {}) {
  const values = normalizeDetectorFeedbackInput(input);
  if (values.firewallInstanceId) await validateFirewallOwnership(database, organizationId, values.firewallInstanceId);
  const [row] = await database
    .insert(detectorFeedback)
    .values({
      ...values,
      organizationId,
      createdByUserId: userId || null,
    })
    .returning();

  await createAuditEvent({
    database,
    organizationId,
    userId,
    firewallInstanceId: values.firewallInstanceId,
    eventType: "detector.feedback.created",
    action: "detector_feedback.create",
    resourceType: "detector_feedback",
    resourceId: row.id,
    result: "success",
    severity: values.feedbackType === "false_positive" ? "medium" : "info",
    requestId: auditContext.requestId,
    metadata: {
      detectorId: values.detectorId,
      feedbackType: values.feedbackType,
      findingId: values.findingId || null,
    },
  });

  return row;
}

export async function normalizeAdvancedDetectionQuery({ database = db(), organizationId, filters = {} } = {}) {
  const now = new Date();
  const until = parseDate(filters.until) || now;
  const since = parseDate(filters.since) || new Date(until.getTime() - 24 * 60 * 60 * 1000);
  if (since > until) throw new Error("since must be before until");
  if (until.getTime() - since.getTime() > 90 * 24 * 60 * 60 * 1000) {
    throw new Error("advanced detection query window is limited to 90 days");
  }

  const firewallInstanceId = cleanString(filters.firewallInstanceId, 160);
  if (firewallInstanceId) await validateFirewallOwnership(database, organizationId, firewallInstanceId);

  return {
    since,
    until,
    firewallInstanceId,
    detectorId: cleanToken(filters.detectorId, 80),
    status: filters.status ? enumValue(filters.status, ["open", "acknowledged", "suppressed", "resolved"], "status") : null,
    limit: limitValue(filters.limit, 100),
  };
}

async function listRecentEvents({ database, event, windowStart }) {
  return database
    .select()
    .from(securityEvents)
    .where(
      and(
        eq(securityEvents.organizationId, event.organizationId),
        eq(securityEvents.firewallInstanceId, event.firewallInstanceId),
        gte(securityEvents.occurredAt, windowStart),
        lte(securityEvents.occurredAt, event.occurredAt || new Date()),
        or(
          event.sourceIp ? eq(securityEvents.sourceIp, event.sourceIp) : sql`false`,
          event.requestId ? eq(securityEvents.requestId, event.requestId) : sql`false`,
          event.userAgent ? eq(securityEvents.userAgent, event.userAgent) : sql`false`,
        ),
      ),
    )
    .orderBy(desc(securityEvents.occurredAt))
    .limit(MAX_RECENT_EVENTS);
}

async function getApiRiskContext({ database, event }) {
  if (!event.requestPath) return {};
  const [route] = await database
    .select()
    .from(apiInventoryRoutes)
    .where(
      and(
        eq(apiInventoryRoutes.organizationId, event.organizationId),
        eq(apiInventoryRoutes.firewallInstanceId, event.firewallInstanceId),
        eq(apiInventoryRoutes.routeTemplate, event.requestPath),
      ),
    )
    .limit(1);

  const metadata = event.rawMetadata || {};
  const sensitive = Boolean(metadata.sensitive_route || metadata.sensitiveRoute || /admin|token|secret|export|users|billing/i.test(event.requestPath || ""));
  return {
    status: route?.status || "unknown",
    isShadow: route?.status === "new" || route?.status === "unknown",
    isUnknown: !route,
    isDeprecated: route?.status === "deprecated",
    isSensitive: sensitive,
    observedRequestCount: Number(route?.observedRequestCount || 0),
  };
}

async function getDetectorConfigMap({ database, event }) {
  const rows = await database
    .select()
    .from(detectorConfigurations)
    .where(
      and(
        eq(detectorConfigurations.organizationId, event.organizationId),
        isNull(detectorConfigurations.deletedAt),
        or(
          isNull(detectorConfigurations.firewallInstanceId),
          eq(detectorConfigurations.firewallInstanceId, event.firewallInstanceId),
        ),
      ),
    )
    .limit(200);

  return new Map(rows.map((row) => [row.detectorId, row]));
}

async function upsertBehaviorBaseline({ database, event, recentEvents, now }) {
  const clientFingerprint = fingerprint([event.sourceIp || "unknown", event.userAgent || "unknown"].join("|"));
  const routeFrequency = frequencyMap(recentEvents.map((item) => item.requestPath || "unknown"), 25);
  const methodMix = frequencyMap(recentEvents.map((item) => item.httpMethod || "UNKNOWN"), 10);
  const windowSeconds = DEFAULT_WINDOW_SECONDS;
  const baselineKeyHash = fingerprint(`client:${clientFingerprint}`);
  const sampleCount = recentEvents.length;
  const requestRatePerMinute = roundNumber(sampleCount / (windowSeconds / 60), 2);
  const label = maskLabel(event.sourceIp || event.userAgent || "unknown-client");

  const [existing] = await database
    .select()
    .from(behavioralBaselines)
    .where(
      and(
        eq(behavioralBaselines.organizationId, event.organizationId),
        eq(behavioralBaselines.firewallInstanceId, event.firewallInstanceId),
        eq(behavioralBaselines.baselineType, "client"),
        eq(behavioralBaselines.baselineKeyHash, baselineKeyHash),
      ),
    )
    .limit(1);

  const values = {
    organizationId: event.organizationId,
    firewallInstanceId: event.firewallInstanceId,
    baselineType: "client",
    baselineKeyHash,
    baselineKeyLabel: label,
    windowSeconds,
    sampleCount,
    requestRatePerMinute,
    methodMix,
    routeFrequency,
    clientFingerprint,
    learnedAt: now,
    expiresAt: new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000),
    metadata: {
      retention: "30 days rolling behavioral baseline",
      storesSensitivePayload: false,
    },
    updatedAt: now,
  };

  const [row] = existing
    ? await database.update(behavioralBaselines).set(values).where(eq(behavioralBaselines.id, existing.id)).returning()
    : await database.insert(behavioralBaselines).values(values).returning();

  return row;
}

function buildDetectionContext({ event, recentEvents, apiContext, detectorConfig, baseline, threatIntel = {}, windowStart, windowEnd }) {
  const sameSource = recentEvents.filter((item) => item.sourceIp && item.sourceIp === event.sourceIp);
  const routeSet = new Set(recentEvents.map((item) => item.requestPath).filter(Boolean));
  const detectorSet = new Set(recentEvents.flatMap((item) => [item.detectorId, ...(item.detectorIds || [])]).filter(Boolean));
  const attackSet = new Set(recentEvents.map((item) => item.attackType).filter(Boolean));
  const authFailures = recentEvents.filter((item) => item.attackType === "credential_attack" || item.anomalyType === "auth_failure").length;
  const destructiveWithoutRead = isDestructive(event.httpMethod) && !recentEvents.some((item) => item.httpMethod === "GET" && item.requestPath === event.requestPath);
  const threatContext = classifyThreatContext(event);

  return {
    event,
    recentEvents,
    sameSource,
    routeSet,
    detectorSet,
    attackSet,
    authFailures,
    destructiveWithoutRead,
    apiContext,
    detectorConfig,
    baseline,
    threatIntel,
    threatContext: { ...threatContext, ...(threatIntel.threatContext || {}) },
    windowStart,
    windowEnd,
  };
}

function buildBehavioralFindings(context) {
  const { event, routeSet, detectorSet, authFailures, destructiveWithoutRead, apiContext, threatContext, recentEvents } = context;
  const signals = [];
  if (apiContext.isShadow || apiContext.isUnknown) {
    signals.push(signal("unusual_api_access", "behavior.unusual_api_access", 18));
  }
  if (routeSet.size >= 12) {
    signals.push(signal("endpoint_discovery", "route_enumeration", Math.min(40, routeSet.size * 2)));
  }
  if (routeSet.size >= 20 && detectorSet.size >= 2) {
    signals.push(signal("automated_reconnaissance", "scanner_behavior", 42));
  }
  if (destructiveWithoutRead) {
    signals.push(signal("abnormal_request_sequence", "abnormal_sequence", 25));
  }
  if (threatContext.userAgentFamily === "scanner") {
    signals.push(signal("scanner_user_agent", "known_scanner_signature", 40));
  }
  if (authFailures >= 8) {
    signals.push(signal("credential_stuffing_pattern", "credential_attack", Math.min(50, authFailures * 4)));
  }
  if (event.attackType === "object_enumeration" || /(\?|&)id=\d+/i.test(event.requestPath || "")) {
    signals.push(signal("object_enumeration_pattern", "object_enumeration", 30));
  }
  if (recentEvents.length >= 80 && ["GET", "HEAD"].includes(event.httpMethod || "")) {
    signals.push(signal("scraper_velocity", "scraping_behavior", 32));
  }
  if (event.rawMetadata?.tokenReplay === true || event.anomalyType === "token_replay") {
    signals.push(signal("token_replay_indicator", "token_replay_suspected", 45));
  }

  return signals.map((entry) => buildFindingCandidate(context, entry));
}

function buildFindingCandidate(context, entry) {
  const risk = calculateCompositeRisk({
    event: context.event,
    signals: [{ reasonCode: entry.reasonCode, clientRisk: entry.clientRisk }],
    apiContext: context.apiContext,
    threatIntel: context.threatIntel,
  });
  const detectorId = detectorForSignal(entry.type);
  return {
    findingType: entry.type,
    detectorId,
    severity: risk.severity,
    confidence: Math.max(risk.confidence, entry.clientRisk >= 40 ? 0.78 : 0.58),
    riskScore: Math.max(risk.score, entry.clientRisk),
    compositeRisk: risk,
    evidence: safeEvidence({
      reasonCodes: [entry.reasonCode],
      routeCount: context.routeSet.size,
      detectorCount: context.detectorSet.size,
      authFailures: context.authFailures,
      apiContext: context.apiContext,
      threatContext: context.threatContext,
      threatIntel: {
        matchCount: context.threatIntel?.matches?.length || 0,
        riskDelta: context.threatIntel?.riskDelta || 0,
        sourceIds: context.threatIntel?.threatContext?.sourceIds || [],
        categories: context.threatIntel?.threatContext?.categories || [],
      },
      windowStart: context.windowStart,
      windowEnd: context.windowEnd,
      storesSensitivePayload: false,
    }),
  };
}

function buildCorrelationCandidate(context, findings) {
  const relatedDetectorIds = Array.from(new Set([
    ...context.detectorSet,
    ...findings.map((finding) => finding.detectorId),
    context.event.detectorId,
  ].filter(Boolean))).slice(0, 25);
  const highSignal =
    findings.length >= 2 ||
    (context.attackSet.has("sql_injection") && context.routeSet.size >= 8) ||
    (context.authFailures >= 5 && context.routeSet.size >= 8);

  if (!highSignal) return null;

  const signals = findings.map((finding) => ({
    reasonCode: finding.findingType,
    clientRisk: finding.riskScore,
  }));
  const risk = calculateCompositeRisk({
    event: context.event,
    signals,
    apiContext: context.apiContext,
    threatIntel: context.threatIntel,
  });
  return {
    detectorId: ADVANCED_DETECTORS.CORRELATION_ATTACK_CHAIN,
    correlationType: "multi_signal_attack_chain",
    severity: risk.severity,
    confidence: Math.max(0.72, risk.confidence),
    riskScore: Math.max(65, risk.score),
    relatedEventIds: context.recentEvents.map((item) => item.id).filter(Boolean).slice(0, 50),
    relatedDetectorIds,
    identityFingerprint: fingerprint([context.event.sourceIp || "unknown", context.event.userAgent || "unknown"].join("|")),
    routeFingerprint: fingerprint(Array.from(context.routeSet).sort().join("|")),
    evidence: safeEvidence({
      findingTypes: findings.map((finding) => finding.findingType).slice(0, 20),
      routeCount: context.routeSet.size,
      detectorCount: relatedDetectorIds.length,
      attackTypes: Array.from(context.attackSet).slice(0, 20),
      windowStart: context.windowStart,
      windowEnd: context.windowEnd,
      storesSensitivePayload: false,
    }),
    windowStart: context.windowStart,
    windowEnd: context.windowEnd,
  };
}

async function upsertDetectionFinding({ database, event, candidate, now }) {
  const dedupeFingerprint = fingerprint([
    event.organizationId,
    event.firewallInstanceId,
    candidate.findingType,
    candidate.detectorId,
    event.sourceIp || "unknown",
    event.requestPath || "unknown",
  ].join("|"));

  const [existing] = await database
    .select()
    .from(detectionFindings)
    .where(
      and(
        eq(detectionFindings.organizationId, event.organizationId),
        eq(detectionFindings.dedupeFingerprint, dedupeFingerprint),
        eq(detectionFindings.status, "open"),
      ),
    )
    .limit(1);

  const values = {
    organizationId: event.organizationId,
    firewallInstanceId: event.firewallInstanceId,
    securityEventId: event.id,
    findingType: candidate.findingType,
    detectorId: candidate.detectorId,
    severity: candidate.severity,
    confidence: clampConfidence(candidate.confidence),
    riskScore: clampScore(candidate.riskScore),
    compositeRisk: candidate.compositeRisk,
    evidence: candidate.evidence,
    firstSeenAt: existing?.firstSeenAt || event.occurredAt || now,
    lastSeenAt: event.occurredAt || now,
    eventCount: existing ? existing.eventCount + 1 : 1,
    dedupeFingerprint,
    updatedAt: now,
  };

  const [row] = existing
    ? await database.update(detectionFindings).set(values).where(eq(detectionFindings.id, existing.id)).returning()
    : await database.insert(detectionFindings).values(values).returning();

  return row;
}

async function upsertCorrelationEvent({ database, event, candidate, now }) {
  const dedupeFingerprint = fingerprint([
    event.organizationId,
    event.firewallInstanceId,
    candidate.correlationType,
    candidate.identityFingerprint || "identity",
    candidate.routeFingerprint || "routes",
  ].join("|"));

  const [existing] = await database
    .select()
    .from(correlationEvents)
    .where(
      and(
        eq(correlationEvents.organizationId, event.organizationId),
        eq(correlationEvents.dedupeFingerprint, dedupeFingerprint),
        eq(correlationEvents.status, "open"),
      ),
    )
    .limit(1);

  const values = {
    organizationId: event.organizationId,
    firewallInstanceId: event.firewallInstanceId,
    correlationType: candidate.correlationType,
    severity: candidate.severity,
    confidence: clampConfidence(candidate.confidence),
    riskScore: clampScore(candidate.riskScore),
    relatedEventIds: candidate.relatedEventIds,
    relatedDetectorIds: candidate.relatedDetectorIds,
    identityFingerprint: candidate.identityFingerprint,
    routeFingerprint: candidate.routeFingerprint,
    evidence: candidate.evidence,
    windowStart: candidate.windowStart,
    windowEnd: candidate.windowEnd,
    dedupeFingerprint,
    updatedAt: now,
  };

  const [row] = existing
    ? await database.update(correlationEvents).set(values).where(eq(correlationEvents.id, existing.id)).returning()
    : await database.insert(correlationEvents).values(values).returning();

  return row;
}

function scopedTimeWhere(table, organizationId, query, timeColumn) {
  return and(
    eq(table.organizationId, organizationId),
    gte(timeColumn, query.since),
    lte(timeColumn, query.until),
    ...(query.firewallInstanceId ? [eq(table.firewallInstanceId, query.firewallInstanceId)] : []),
  );
}

function normalizeDetectorConfigurationInput(input = {}) {
  return {
    firewallInstanceId: cleanString(input.firewallInstanceId, 160),
    detectorId: requiredToken(input.detectorId, 80),
    status: enumValue(input.status || "active", ["active", "observe", "disabled", "deleted"], "detector status"),
    confidenceThreshold: confidenceValue(input.confidenceThreshold ?? DEFAULT_DETECTOR_THRESHOLD),
    severityOverride: input.severityOverride ? enumValue(input.severityOverride, ["low", "medium", "high", "critical"], "severity override") : null,
    tuning: safeJsonObject(input.tuning || {}),
    suppressionRules: Array.isArray(input.suppressionRules) ? input.suppressionRules.slice(0, 50).map(safeSuppressionRule) : [],
  };
}

function normalizeDetectorFeedbackInput(input = {}) {
  return {
    firewallInstanceId: cleanString(input.firewallInstanceId, 160),
    detectorId: requiredToken(input.detectorId, 80),
    securityEventId: cleanString(input.securityEventId, 160),
    findingId: cleanString(input.findingId, 160),
    feedbackType: enumValue(input.feedbackType, ["true_positive", "false_positive", "expected_behavior", "duplicate", "needs_tuning", "customer_exception"], "feedback type"),
    note: cleanString(input.note, 2000),
    expiresAt: parseDate(input.expiresAt),
    metadata: safeJsonObject(input.metadata || {}),
  };
}

function safeSuppressionRule(rule = {}) {
  return {
    scopeType: enumValue(rule.scopeType || "detector", ["detector", "route", "source", "firewall"], "suppression scope"),
    scopeValue: cleanString(rule.scopeValue, 240),
    reason: cleanString(rule.reason, 500) || "Detector tuning exception",
    expiresAt: parseDate(rule.expiresAt)?.toISOString() || null,
  };
}

function presentDetectorConfiguration(row) {
  return {
    id: row.id,
    firewallInstanceId: row.firewallInstanceId,
    detectorId: row.detectorId,
    status: row.status,
    confidenceThreshold: row.confidenceThreshold,
    severityOverride: row.severityOverride,
    tuning: row.tuning || {},
    suppressionRules: row.suppressionRules || [],
    updatedAt: row.updatedAt,
  };
}

function presentBaseline(row) {
  return {
    id: row.id,
    firewallInstanceId: row.firewallInstanceId,
    baselineType: row.baselineType,
    baselineKeyLabel: row.baselineKeyLabel,
    sampleCount: row.sampleCount,
    requestRatePerMinute: row.requestRatePerMinute,
    methodMix: row.methodMix || {},
    routeFrequency: row.routeFrequency || {},
    learnedAt: row.learnedAt,
    expiresAt: row.expiresAt,
  };
}

function summarizeContext(context) {
  return {
    windowStart: context.windowStart,
    windowEnd: context.windowEnd,
    recentEventCount: context.recentEvents.length,
    routeCount: context.routeSet.size,
    detectorCount: context.detectorSet.size,
    storesSensitivePayload: false,
  };
}

function detectorEnabled(configMap, detectorId) {
  const config = configMap.get(detectorId);
  return !config || ["active", "observe"].includes(config.status);
}

function detectorThreshold(configMap, detectorId) {
  return Number(configMap.get(detectorId)?.confidenceThreshold ?? DEFAULT_DETECTOR_THRESHOLD);
}

function detectorForSignal(type) {
  const map = {
    unusual_api_access: ADVANCED_DETECTORS.BEHAVIOR_UNUSUAL_ACCESS,
    endpoint_discovery: ADVANCED_DETECTORS.BEHAVIOR_ENDPOINT_DISCOVERY,
    automated_reconnaissance: ADVANCED_DETECTORS.BEHAVIOR_RECONNAISSANCE,
    abnormal_request_sequence: ADVANCED_DETECTORS.BEHAVIOR_ABNORMAL_SEQUENCE,
    scanner_user_agent: ADVANCED_DETECTORS.ABUSE_SCANNER,
    credential_stuffing_pattern: ADVANCED_DETECTORS.ABUSE_CREDENTIAL_STUFFING,
    object_enumeration_pattern: ADVANCED_DETECTORS.ABUSE_OBJECT_ENUMERATION,
    scraper_velocity: ADVANCED_DETECTORS.ABUSE_SCRAPER,
    token_replay_indicator: ADVANCED_DETECTORS.ABUSE_TOKEN_REPLAY,
  };
  return map[type] || ADVANCED_DETECTORS.BEHAVIOR_UNUSUAL_ACCESS;
}

function signal(type, reasonCode, clientRisk) {
  return { type, reasonCode, clientRisk };
}

function severityWeight(severity) {
  return { low: 20, medium: 45, high: 70, critical: 90 }[severity] || 30;
}

function mapSeverity(score, confidence) {
  if (score >= 75 && confidence >= 0.5) return "critical";
  if (score >= 75) return "high";
  if (score >= 50 && confidence >= 0.6) return "high";
  if (score >= 50) return "medium";
  if (score >= 25 && confidence >= 0.7) return "medium";
  return "low";
}

function numberSummary(row = {}) {
  return {
    total: numberValue(row.total),
    critical: numberValue(row.critical),
    high: numberValue(row.high),
    avgRisk: Math.round(numberValue(row.avgRisk)),
    maxRisk: Math.round(numberValue(row.maxRisk)),
    avgConfidence: roundNumber(numberValue(row.avgConfidence), 2),
  };
}

function frequencyMap(values, maxItems) {
  const counts = new Map();
  values.filter(Boolean).forEach((value) => counts.set(String(value), (counts.get(String(value)) || 0) + 1));
  return Object.fromEntries(Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, maxItems));
}

function safeEvidence(value) {
  return safeJsonObject(value);
}

function safeJsonObject(value) {
  if (!value || Array.isArray(value) || typeof value !== "object") return {};
  return sanitizeObject(value, []);
}

function sanitizeObject(value, path) {
  if (path.length > 8) throw new Error("advanced detection metadata exceeds maximum depth");
  if (value == null || typeof value === "boolean" || typeof value === "number") return value;
  if (typeof value === "string") return value.replace(/[^\x20-\x7E]/g, "").slice(0, 2048);
  if (Array.isArray(value)) return value.slice(0, 50).map((item, index) => sanitizeObject(item, [...path, String(index)]));
  if (typeof value === "object") {
    return Object.entries(value).slice(0, 100).reduce((safe, [key, child]) => {
      const cleanKey = String(key || "").replace(/[^\w.-]/g, "_").slice(0, 120);
      if (!cleanKey) throw new Error("advanced detection metadata contains empty key");
      if (/password|secret|token|cookie|authorization|private[_-]?key|api[_-]?key/i.test(cleanKey)) {
        throw new Error(`advanced detection metadata contains sensitive field: ${[...path, cleanKey].join(".")}`);
      }
      safe[cleanKey] = sanitizeObject(child, [...path, cleanKey]);
      return safe;
    }, {});
  }
  return null;
}

function maskLabel(value) {
  const text = String(value || "unknown").slice(0, 160);
  if (text.length <= 6) return text;
  return `${text.slice(0, 3)}***${text.slice(-3)}`;
}

function fingerprint(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

function cleanString(value, maxLength) {
  if (!value) return null;
  return String(value).replace(/[^\x20-\x7E]/g, "").trim().slice(0, maxLength) || null;
}

function cleanToken(value, maxLength) {
  if (!value) return null;
  const token = String(value).trim().toLowerCase();
  return /^[a-z0-9_.:-]+$/.test(token) ? token.slice(0, maxLength) : null;
}

function requiredToken(value, maxLength) {
  const token = cleanToken(value, maxLength);
  if (!token) throw new Error("detectorId is required");
  return token;
}

function enumValue(value, allowed, label) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!allowed.includes(normalized)) throw new Error(`${label} is invalid`);
  return normalized;
}

function confidenceValue(value) {
  const confidence = Number(value);
  if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
    throw new Error("confidence threshold must be between 0 and 1");
  }
  return confidence;
}

function limitValue(value, fallback) {
  const limit = Number(value || fallback);
  if (!Number.isFinite(limit) || limit < 1) return fallback;
  return Math.min(100, Math.floor(limit));
}

function parseDate(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function clampScore(value) {
  return Math.max(0, Math.min(100, Number.isFinite(Number(value)) ? Number(value) : 0));
}

function clampConfidence(value) {
  return Math.max(0, Math.min(1, Number.isFinite(Number(value)) ? Number(value) : 0));
}

function roundNumber(value, places) {
  const factor = 10 ** places;
  return Math.round(Number(value || 0) * factor) / factor;
}

function numberValue(value) {
  const number = Number(value || 0);
  return Number.isFinite(number) ? number : 0;
}

function isDestructive(method) {
  return ["POST", "PUT", "PATCH", "DELETE"].includes(String(method || "").toUpperCase());
}

async function validateFirewallOwnership(database, organizationId, firewallInstanceId) {
  const [firewall] = await database
    .select({
      id: firewallInstances.id,
      organizationId: firewallInstances.organizationId,
      status: firewallInstances.status,
      deletedAt: firewallInstances.deletedAt,
    })
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
