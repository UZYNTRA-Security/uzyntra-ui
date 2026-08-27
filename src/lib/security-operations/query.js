import "server-only";

import { and, desc, eq, gte, lte, sql } from "drizzle-orm";
import { db } from "../../db/client.js";
import {
  alerts,
  apiInventoryRoutes,
  incidents,
  notificationChannels,
  notificationDeliveries,
  securityEvents,
} from "../../db/schema.js";
import { validateFirewallOwnership } from "../security-events/index.js";

const DEFAULT_HOURS = 24;
const MAX_DAYS = 90;
const DEFAULT_LIMIT = 25;
const MAX_LIMIT = 100;
const SEVERITY_WEIGHT = Object.freeze({ low: 10, medium: 35, high: 70, critical: 100 });

export async function getSecurityDashboard({ database = db(), organizationId, filters = {} } = {}) {
  const query = await normalizeSecurityOperationsQuery({ database, organizationId, filters });
  const [metrics, topThreats, posture, notificationHealth, recentEvents, incidentOverview] =
    await Promise.all([
      getSecurityMetrics({ database, organizationId, filters: query }),
      getTopThreats({ database, organizationId, filters: query }),
      getSecurityPosture({ database, organizationId, filters: query }),
      getNotificationHealth({ database, organizationId, filters: query }),
      getRecentSecurityEvents({ database, organizationId, filters: { ...query, limit: 10 } }),
      getIncidentOverview({ database, organizationId, filters: query }),
    ]);

  const activeIncidents = numberValue(incidentOverview.totals.active);
  const criticalAlerts = numberValue(metrics.alerts.criticalOpen);
  const riskScore = clampScore(
    Math.round(
      (metrics.security.criticalFindings * 10) +
        (criticalAlerts * 12) +
        (activeIncidents * 8) +
        (100 - posture.scores.securityPosture) * 0.35,
    ),
  );

  return {
    window: query.window,
    executive: {
      overallSecurityScore: clampScore(100 - riskScore),
      riskScore,
      activeIncidents,
      criticalAlerts,
      blockedAttacks: metrics.gateway.blockedRequests,
      alertReliabilityScore: notificationHealth.reliability.score,
    },
    analyst: {
      recentEvents,
      topDetectors: topThreats.topDetectors,
      attackCategories: topThreats.attackCategories,
      severityDistribution: metrics.security.severityDistribution,
      detectionConfidence: metrics.security.detectionConfidence,
    },
    posture,
    metrics,
    topThreats,
    notificationHealth,
    incidentOverview,
  };
}

export async function getSecurityMetrics({ database = db(), organizationId, filters = {} } = {}) {
  const query = await normalizeSecurityOperationsQuery({ database, organizationId, filters });
  const eventWhere = securityEventWhere(organizationId, query);
  const alertWhere = scopedWhere(alerts.organizationId, organizationId, query, alerts.firewallInstanceId);
  const incidentWhere = scopedWhere(
    incidents.organizationId,
    organizationId,
    query,
    incidents.firewallInstanceId,
  );

  const [eventSummary] = await database
    .select({
      total: sql`count(*)`,
      blocked: sql`sum(case when ${securityEvents.actionTaken} = 'blocked' then 1 else 0 end)`,
      allowed: sql`sum(case when ${securityEvents.actionTaken} = 'allowed' then 1 else 0 end)`,
      rateLimited: sql`sum(case when ${securityEvents.actionTaken} = 'rate_limited' then 1 else 0 end)`,
      errors: sql`sum(case when ${securityEvents.severity} in ('high', 'critical') then 1 else 0 end)`,
      critical: sql`sum(case when ${securityEvents.severity} = 'critical' then 1 else 0 end)`,
      high: sql`sum(case when ${securityEvents.severity} = 'high' then 1 else 0 end)`,
      avgConfidence: sql`avg(${securityEvents.confidence})`,
      avgScore: sql`avg(${securityEvents.score})`,
      maxScore: sql`max(${securityEvents.score})`,
    })
    .from(securityEvents)
    .where(eventWhere);

  const [alertSummary] = await database
    .select({
      open: sql`sum(case when ${alerts.status} = 'open' then 1 else 0 end)`,
      acknowledged: sql`sum(case when ${alerts.status} = 'acknowledged' then 1 else 0 end)`,
      resolved: sql`sum(case when ${alerts.status} = 'resolved' then 1 else 0 end)`,
      criticalOpen: sql`sum(case when ${alerts.status} = 'open' and ${alerts.severity} = 'critical' then 1 else 0 end)`,
    })
    .from(alerts)
    .where(alertWhere);

  const [incidentSummary] = await database
    .select({
      open: sql`sum(case when ${incidents.status} = 'open' then 1 else 0 end)`,
      investigating: sql`sum(case when ${incidents.status} = 'investigating' then 1 else 0 end)`,
      contained: sql`sum(case when ${incidents.status} = 'contained' then 1 else 0 end)`,
      resolved: sql`sum(case when ${incidents.status} = 'resolved' then 1 else 0 end)`,
      active: sql`sum(case when ${incidents.status} <> 'resolved' then 1 else 0 end)`,
    })
    .from(incidents)
    .where(incidentWhere);

  const [timeline, severityDistribution, detectionConfidence] = await Promise.all([
    eventTimeline(database, eventWhere, query.bucket),
    groupedCount(database, eventWhere, securityEvents.severity, "severity", 10),
    groupedConfidence(database, eventWhere),
  ]);

  const total = numberValue(eventSummary?.total);
  const blocked = numberValue(eventSummary?.blocked);

  return {
    window: query.window,
    gateway: {
      requestVolume: total,
      latency: { p50: null, p95: null, p99: null },
      errors: numberValue(eventSummary?.errors),
      blockedRequests: blocked,
      detectionRate: perThousand(total, total),
    },
    controlPlane: {
      apiAvailability: null,
      ingestionFailures: 0,
      authenticationFailures: 0,
      authorizationFailures: 0,
    },
    security: {
      criticalFindings: numberValue(eventSummary?.critical),
      highFindings: numberValue(eventSummary?.high),
      averageConfidence: roundNumber(eventSummary?.avgConfidence, 3),
      averageScore: roundNumber(eventSummary?.avgScore, 1),
      maxScore: roundNumber(eventSummary?.maxScore, 1),
      severityDistribution,
      detectionConfidence,
      timeline,
    },
    alerts: {
      open: numberValue(alertSummary?.open),
      acknowledged: numberValue(alertSummary?.acknowledged),
      resolved: numberValue(alertSummary?.resolved),
      criticalOpen: numberValue(alertSummary?.criticalOpen),
    },
    incidents: {
      open: numberValue(incidentSummary?.open),
      investigating: numberValue(incidentSummary?.investigating),
      contained: numberValue(incidentSummary?.contained),
      resolved: numberValue(incidentSummary?.resolved),
      active: numberValue(incidentSummary?.active),
    },
  };
}

export async function getSecurityTrends({ database = db(), organizationId, filters = {} } = {}) {
  const query = await normalizeSecurityOperationsQuery({ database, organizationId, filters });
  const eventWhere = securityEventWhere(organizationId, query);
  const incidentWhere = scopedWhere(
    incidents.organizationId,
    organizationId,
    query,
    incidents.firewallInstanceId,
  );

  const [eventTrend, incidentTrend, notificationHealth, posture] = await Promise.all([
    eventTimeline(database, eventWhere, query.bucket),
    incidentTimeline(database, incidentWhere, query.bucket),
    getNotificationHealth({ database, organizationId, filters: query }),
    getSecurityPosture({ database, organizationId, filters: query }),
  ]);

  return {
    window: query.window,
    eventTrend,
    incidentTrend,
    alertReliabilityTrend: notificationHealth.timeline,
    postureTrend: [{ bucket: query.window.until, score: posture.scores.securityPosture }],
  };
}

export async function getSecurityPosture({ database = db(), organizationId, filters = {} } = {}) {
  const query = await normalizeSecurityOperationsQuery({ database, organizationId, filters });
  const inventoryWhere = scopedWhere(
    apiInventoryRoutes.organizationId,
    organizationId,
    query,
    apiInventoryRoutes.firewallInstanceId,
    apiInventoryRoutes.lastSeenAt,
  );
  const eventWhere = securityEventWhere(organizationId, query);
  const alertWhere = scopedWhere(alerts.organizationId, organizationId, query, alerts.firewallInstanceId);

  const [inventory, detectorRows, alertRulesProxy] = await Promise.all([
    groupedCount(database, inventoryWhere, apiInventoryRoutes.status, "status", 10, apiInventoryRoutes),
    groupedCount(database, eventWhere, securityEvents.detectorId, "detectorId", 25),
    database
      .select({
        total: sql`count(*)`,
        openCritical: sql`sum(case when ${alerts.status} = 'open' and ${alerts.severity} = 'critical' then 1 else 0 end)`,
      })
      .from(alerts)
      .where(alertWhere),
  ]);

  const exposure = countByKey(inventory, "status");
  const known = numberValue(exposure.known) + numberValue(exposure.approved);
  const totalRoutes = Object.values(exposure).reduce((sum, value) => sum + numberValue(value), 0);
  const riskyRoutes = numberValue(exposure.new) + numberValue(exposure.unknown);
  const deprecatedRoutes = numberValue(exposure.deprecated);
  const detectorCoverage = detectorRows.length ? Math.min(100, detectorRows.length * 12) : 0;
  const policyCoverage = totalRoutes ? Math.round((known / totalRoutes) * 100) : 100;
  const apiExposureScore = clampScore(100 - Math.round(((riskyRoutes + deprecatedRoutes) / Math.max(totalRoutes, 1)) * 100));
  const openCritical = numberValue(alertRulesProxy?.[0]?.openCritical);
  const responseReadinessScore = clampScore(100 - openCritical * 12);
  const securityPosture = clampScore(
    Math.round(apiExposureScore * 0.35 + policyCoverage * 0.25 + detectorCoverage * 0.2 + responseReadinessScore * 0.2),
  );

  return {
    window: query.window,
    scores: {
      apiExposure: apiExposureScore,
      securityPosture,
      policyCoverage,
      detectorCoverage,
      responseReadiness: responseReadinessScore,
    },
    apiExposure: {
      totalRoutes,
      knownRoutes: known,
      riskyRoutes,
      deprecatedRoutes,
      byStatus: inventory,
    },
    policyCoverage: {
      coveredRoutes: known,
      uncoveredRoutes: Math.max(0, totalRoutes - known),
      percent: policyCoverage,
    },
    detectorCoverage: {
      detectorCount: detectorRows.length,
      topDetectors: detectorRows,
      percent: detectorCoverage,
    },
  };
}

export async function getTopThreats({ database = db(), organizationId, filters = {} } = {}) {
  const query = await normalizeSecurityOperationsQuery({ database, organizationId, filters });
  const eventWhere = securityEventWhere(organizationId, query);
  const [attackCategories, topDetectors, topSources, topRoutes, severityDistribution] =
    await Promise.all([
      groupedCount(database, eventWhere, securityEvents.attackType, "attackType", 10),
      groupedCount(database, eventWhere, securityEvents.detectorId, "detectorId", 10),
      groupedCount(database, eventWhere, securityEvents.sourceIp, "sourceIp", 10),
      groupedCount(database, eventWhere, securityEvents.requestPath, "route", 10),
      groupedCount(database, eventWhere, securityEvents.severity, "severity", 10),
    ]);

  return {
    window: query.window,
    attackCategories,
    topDetectors,
    topSources,
    topRoutes,
    severityDistribution,
  };
}

export async function listNotificationDeliveries({
  database = db(),
  organizationId,
  filters = {},
} = {}) {
  const query = await normalizeSecurityOperationsQuery({ database, organizationId, filters });
  const deliveryQuery = normalizeDeliveryQuery(filters);
  const predicates = [eq(notificationDeliveries.organizationId, organizationId)];

  if (deliveryQuery.status) {
    predicates.push(eq(notificationDeliveries.status, deliveryQuery.status));
  }

  if (deliveryQuery.channelId) {
    predicates.push(eq(notificationDeliveries.channelId, deliveryQuery.channelId));
  }

  predicates.push(gte(notificationDeliveries.createdAt, query.since));
  predicates.push(lte(notificationDeliveries.createdAt, query.until));

  const rows = await database
    .select({
      id: notificationDeliveries.id,
      channelId: notificationDeliveries.channelId,
      channelName: notificationChannels.name,
      providerType: notificationChannels.type,
      eventType: notificationDeliveries.eventType,
      status: notificationDeliveries.status,
      attemptCount: notificationDeliveries.attemptCount,
      maxAttempts: notificationDeliveries.maxAttempts,
      responseStatus: notificationDeliveries.responseStatus,
      lastErrorCode: notificationDeliveries.lastErrorCode,
      nextAttemptAt: notificationDeliveries.nextAttemptAt,
      deliveredAt: notificationDeliveries.deliveredAt,
      createdAt: notificationDeliveries.createdAt,
    })
    .from(notificationDeliveries)
    .leftJoin(notificationChannels, eq(notificationChannels.id, notificationDeliveries.channelId))
    .where(and(...predicates))
    .orderBy(desc(notificationDeliveries.createdAt), desc(notificationDeliveries.id))
    .limit(deliveryQuery.limit + 1)
    .offset(deliveryQuery.offset);

  const items = rows.slice(0, deliveryQuery.limit).map(presentDelivery);
  return {
    items,
    pageInfo: {
      limit: deliveryQuery.limit,
      offset: deliveryQuery.offset,
      hasMore: rows.length > deliveryQuery.limit,
      nextOffset: rows.length > deliveryQuery.limit ? deliveryQuery.offset + deliveryQuery.limit : null,
    },
    filters: deliveryQuery,
  };
}

export async function getNotificationHealth({ database = db(), organizationId, filters = {} } = {}) {
  const query = await normalizeSecurityOperationsQuery({ database, organizationId, filters });
  const deliveryWhere = and(
    eq(notificationDeliveries.organizationId, organizationId),
    gte(notificationDeliveries.createdAt, query.since),
    lte(notificationDeliveries.createdAt, query.until),
  );

  const [summary] = await database
    .select({
      total: sql`count(*)`,
      delivered: sql`sum(case when ${notificationDeliveries.status} = 'delivered' then 1 else 0 end)`,
      pending: sql`sum(case when ${notificationDeliveries.status} = 'pending' then 1 else 0 end)`,
      retrying: sql`sum(case when ${notificationDeliveries.status} in ('claimed', 'retry') then 1 else 0 end)`,
      failed: sql`sum(case when ${notificationDeliveries.status} = 'failed' then 1 else 0 end)`,
      blocked: sql`sum(case when ${notificationDeliveries.status} = 'blocked' then 1 else 0 end)`,
      attemptCount: sql`sum(${notificationDeliveries.attemptCount})`,
      avgLatencyMs: sql`avg(extract(epoch from (${notificationDeliveries.deliveredAt} - ${notificationDeliveries.createdAt})) * 1000)`,
    })
    .from(notificationDeliveries)
    .where(deliveryWhere);

  const [byProvider, timeline] = await Promise.all([
    deliveryByProvider(database, deliveryWhere),
    deliveryTimeline(database, deliveryWhere, query.bucket),
  ]);

  const total = numberValue(summary?.total);
  const delivered = numberValue(summary?.delivered);
  const failed = numberValue(summary?.failed) + numberValue(summary?.blocked);
  const retrying = numberValue(summary?.retrying);
  const deadLetter = numberValue(summary?.blocked) + numberValue(summary?.failed);
  const score = computeAlertReliabilityScore({ delivered, total });

  return {
    window: query.window,
    totals: {
      total,
      delivered,
      pending: numberValue(summary?.pending),
      retrying,
      failed,
      deadLetter,
      attemptCount: numberValue(summary?.attemptCount),
      averageDeliveryLatencyMs: roundNumber(summary?.avgLatencyMs, 0),
    },
    reliability: {
      score,
      successRate: score,
      failureRate: total ? roundNumber((failed / total) * 100, 1) : 0,
      status: score >= 99 ? "healthy" : score >= 95 ? "degraded" : "attention_required",
    },
    byProvider,
    timeline,
  };
}

export async function getIncidentOverview({ database = db(), organizationId, filters = {} } = {}) {
  const query = await normalizeSecurityOperationsQuery({ database, organizationId, filters });
  const whereClause = scopedWhere(
    incidents.organizationId,
    organizationId,
    query,
    incidents.firewallInstanceId,
  );
  const [summary] = await database
    .select({
      open: sql`sum(case when ${incidents.status} = 'open' then 1 else 0 end)`,
      investigating: sql`sum(case when ${incidents.status} = 'investigating' then 1 else 0 end)`,
      contained: sql`sum(case when ${incidents.status} = 'contained' then 1 else 0 end)`,
      resolved: sql`sum(case when ${incidents.status} = 'resolved' then 1 else 0 end)`,
      active: sql`sum(case when ${incidents.status} <> 'resolved' then 1 else 0 end)`,
    })
    .from(incidents)
    .where(whereClause);

  return {
    totals: {
      open: numberValue(summary?.open),
      investigating: numberValue(summary?.investigating),
      contained: numberValue(summary?.contained),
      resolved: numberValue(summary?.resolved),
      active: numberValue(summary?.active),
    },
  };
}

export async function getRecentSecurityEvents({ database = db(), organizationId, filters = {} } = {}) {
  const query = await normalizeSecurityOperationsQuery({ database, organizationId, filters });
  const rows = await database
    .select({
      id: securityEvents.id,
      firewallInstanceId: securityEvents.firewallInstanceId,
      attackType: securityEvents.attackType,
      severity: securityEvents.severity,
      sourceIp: securityEvents.sourceIp,
      requestPath: securityEvents.requestPath,
      httpMethod: securityEvents.httpMethod,
      confidence: securityEvents.confidence,
      detectorId: securityEvents.detectorId,
      score: securityEvents.score,
      actionTaken: securityEvents.actionTaken,
      occurredAt: securityEvents.occurredAt,
    })
    .from(securityEvents)
    .where(securityEventWhere(organizationId, query))
    .orderBy(desc(securityEvents.occurredAt), desc(securityEvents.id))
    .limit(query.limit);

  return rows;
}

export async function normalizeSecurityOperationsQuery({
  database = db(),
  organizationId,
  filters = {},
} = {}) {
  if (!organizationId) {
    throw new Error("organizationId is required");
  }

  const until = nullableDate(filters.until) || new Date();
  const since =
    nullableDate(filters.since) || new Date(until.getTime() - DEFAULT_HOURS * 60 * 60 * 1000);
  const maxSince = new Date(until.getTime() - MAX_DAYS * 24 * 60 * 60 * 1000);
  const boundedSince = since < maxSince ? maxSince : since;
  const firewallInstanceId = nullableBoundedString(filters.firewallInstanceId, 160);

  if (firewallInstanceId) {
    await validateFirewallOwnership(database, organizationId, firewallInstanceId);
  }

  return {
    since: boundedSince,
    until,
    bucket: normalizeBucket(filters.bucket, boundedSince, until),
    firewallInstanceId,
    limit: boundedLimit(filters.limit),
    window: {
      since: boundedSince.toISOString(),
      until: until.toISOString(),
    },
  };
}

export function computeAlertReliabilityScore({ delivered = 0, total = 0 } = {}) {
  const denominator = Number(total || 0);
  if (!denominator) return 100;
  return roundNumber((Number(delivered || 0) / denominator) * 100, 1);
}

export function mapDeliveryStatus(status, attemptCount = 0, maxAttempts = 5) {
  const normalized = String(status || "").toLowerCase();
  if (normalized === "delivered") return "delivered";
  if (normalized === "pending") return "pending";
  if (normalized === "claimed" || normalized === "retry") return "retrying";
  if (normalized === "blocked") return "dead_letter";
  if (normalized === "failed" && Number(attemptCount || 0) >= Number(maxAttempts || 0)) {
    return "dead_letter";
  }
  if (normalized === "failed") return "failed";
  return "pending";
}

export function maskChannelName(name) {
  const clean = String(name || "Integration").replace(/[^\x20-\x7E]/g, "").trim();
  if (clean.length <= 4) return clean || "Integration";
  return `${clean.slice(0, 2)}***${clean.slice(-2)}`;
}

function securityEventWhere(organizationId, query) {
  return scopedWhere(
    securityEvents.organizationId,
    organizationId,
    query,
    securityEvents.firewallInstanceId,
    securityEvents.occurredAt,
  );
}

function scopedWhere(organizationColumn, organizationId, query, firewallColumn, timeColumn) {
  const predicates = [eq(organizationColumn, organizationId)];
  if (query.firewallInstanceId && firewallColumn) {
    predicates.push(eq(firewallColumn, query.firewallInstanceId));
  }
  if (timeColumn) {
    predicates.push(gte(timeColumn, query.since));
    predicates.push(lte(timeColumn, query.until));
  }
  return and(...predicates);
}

async function groupedCount(database, whereClause, column, key, limit, table = securityEvents) {
  const rows = await database
    .select({ [key]: column, count: sql`count(*)` })
    .from(table)
    .where(whereClause)
    .groupBy(column)
    .orderBy(desc(sql`count(*)`))
    .limit(limit);

  return rows
    .filter((row) => row[key])
    .map((row) => ({ [key]: row[key], count: numberValue(row.count) }));
}

async function groupedConfidence(database, whereClause) {
  const bucket = sql`
    case
      when ${securityEvents.confidence} is null then 'unknown'
      when ${securityEvents.confidence} < 0.25 then '0-24'
      when ${securityEvents.confidence} < 0.50 then '25-49'
      when ${securityEvents.confidence} < 0.75 then '50-74'
      else '75-100'
    end
  `;
  const rows = await database
    .select({ bucket, count: sql`count(*)` })
    .from(securityEvents)
    .where(whereClause)
    .groupBy(bucket)
    .orderBy(bucket);

  return rows.map((row) => ({ bucket: row.bucket, count: numberValue(row.count) }));
}

async function eventTimeline(database, whereClause, bucketSize) {
  const bucket = bucketSql(bucketSize, securityEvents.occurredAt);
  const rows = await database
    .select({
      bucket,
      total: sql`count(*)`,
      blocked: sql`sum(case when ${securityEvents.actionTaken} = 'blocked' then 1 else 0 end)`,
      critical: sql`sum(case when ${securityEvents.severity} = 'critical' then 1 else 0 end)`,
      high: sql`sum(case when ${securityEvents.severity} = 'high' then 1 else 0 end)`,
      medium: sql`sum(case when ${securityEvents.severity} = 'medium' then 1 else 0 end)`,
      low: sql`sum(case when ${securityEvents.severity} = 'low' then 1 else 0 end)`,
    })
    .from(securityEvents)
    .where(whereClause)
    .groupBy(bucket)
    .orderBy(bucket)
    .limit(500);

  return rows.map((row) => ({
    bucket: new Date(row.bucket).toISOString(),
    total: numberValue(row.total),
    blocked: numberValue(row.blocked),
    critical: numberValue(row.critical),
    high: numberValue(row.high),
    medium: numberValue(row.medium),
    low: numberValue(row.low),
  }));
}

async function incidentTimeline(database, whereClause, bucketSize) {
  const bucket = bucketSql(bucketSize, incidents.createdAt);
  const rows = await database
    .select({
      bucket,
      open: sql`sum(case when ${incidents.status} <> 'resolved' then 1 else 0 end)`,
      resolved: sql`sum(case when ${incidents.status} = 'resolved' then 1 else 0 end)`,
    })
    .from(incidents)
    .where(whereClause)
    .groupBy(bucket)
    .orderBy(bucket)
    .limit(500);

  return rows.map((row) => ({
    bucket: new Date(row.bucket).toISOString(),
    open: numberValue(row.open),
    resolved: numberValue(row.resolved),
  }));
}

async function deliveryByProvider(database, whereClause) {
  const rows = await database
    .select({
      providerType: notificationChannels.type,
      total: sql`count(*)`,
      delivered: sql`sum(case when ${notificationDeliveries.status} = 'delivered' then 1 else 0 end)`,
      retrying: sql`sum(case when ${notificationDeliveries.status} in ('claimed', 'retry') then 1 else 0 end)`,
      failed: sql`sum(case when ${notificationDeliveries.status} in ('failed', 'blocked') then 1 else 0 end)`,
    })
    .from(notificationDeliveries)
    .leftJoin(notificationChannels, eq(notificationChannels.id, notificationDeliveries.channelId))
    .where(whereClause)
    .groupBy(notificationChannels.type)
    .orderBy(desc(sql`count(*)`))
    .limit(20);

  return rows.map((row) => {
    const total = numberValue(row.total);
    const delivered = numberValue(row.delivered);
    return {
      providerType: row.providerType || "unknown",
      total,
      delivered,
      retrying: numberValue(row.retrying),
      failed: numberValue(row.failed),
      reliabilityScore: computeAlertReliabilityScore({ delivered, total }),
    };
  });
}

async function deliveryTimeline(database, whereClause, bucketSize) {
  const bucket = bucketSql(bucketSize, notificationDeliveries.createdAt);
  const rows = await database
    .select({
      bucket,
      total: sql`count(*)`,
      delivered: sql`sum(case when ${notificationDeliveries.status} = 'delivered' then 1 else 0 end)`,
      failed: sql`sum(case when ${notificationDeliveries.status} in ('failed', 'blocked') then 1 else 0 end)`,
    })
    .from(notificationDeliveries)
    .where(whereClause)
    .groupBy(bucket)
    .orderBy(bucket)
    .limit(500);

  return rows.map((row) => ({
    bucket: new Date(row.bucket).toISOString(),
    total: numberValue(row.total),
    delivered: numberValue(row.delivered),
    failed: numberValue(row.failed),
    reliabilityScore: computeAlertReliabilityScore({
      delivered: row.delivered,
      total: row.total,
    }),
  }));
}

function presentDelivery(row) {
  return {
    id: row.id,
    channelId: row.channelId,
    channelName: maskChannelName(row.channelName),
    providerType: row.providerType || "unknown",
    eventType: row.eventType,
    status: row.status,
    operationalStatus: mapDeliveryStatus(row.status, row.attemptCount, row.maxAttempts),
    attemptCount: numberValue(row.attemptCount),
    maxAttempts: numberValue(row.maxAttempts),
    responseStatus: row.responseStatus,
    lastErrorCode: row.lastErrorCode,
    nextAttemptAt: row.nextAttemptAt,
    deliveredAt: row.deliveredAt,
    createdAt: row.createdAt,
  };
}

function normalizeDeliveryQuery(filters = {}) {
  return {
    limit: boundedLimit(filters.limit),
    offset: boundedOffset(filters.offset),
    status: nullableDeliveryStatus(filters.status || filters.delivery_status),
    channelId: nullableBoundedString(filters.channelId || filters.channel_id, 160),
  };
}

function bucketSql(bucket, column) {
  return bucket === "day" ? sql`date_trunc('day', ${column})` : sql`date_trunc('hour', ${column})`;
}

function normalizeBucket(value, since, until) {
  const normalized = String(value || "").toLowerCase();
  if (normalized === "day") return "day";
  if (normalized === "hour") return "hour";
  const hours = (until.getTime() - since.getTime()) / (60 * 60 * 1000);
  return hours > 72 ? "day" : "hour";
}

function nullableDeliveryStatus(value) {
  if (!value) return null;
  const status = String(value).trim().toLowerCase();
  if (!["pending", "claimed", "delivered", "retry", "failed", "blocked"].includes(status)) {
    throw new Error("delivery status filter is invalid");
  }
  return status;
}

function nullableDate(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error("date filter is invalid");
  return date;
}

function nullableBoundedString(value, maxLength) {
  if (!value) return null;
  return String(value).trim().slice(0, maxLength) || null;
}

function boundedLimit(value) {
  const limit = Number(value || DEFAULT_LIMIT);
  return Number.isFinite(limit) && limit > 0 ? Math.min(Math.trunc(limit), MAX_LIMIT) : DEFAULT_LIMIT;
}

function boundedOffset(value) {
  const offset = Number(value || 0);
  return Number.isFinite(offset) && offset > 0 ? Math.min(Math.trunc(offset), 10_000) : 0;
}

function countByKey(items, key) {
  return Object.fromEntries((items || []).map((item) => [item[key], numberValue(item.count)]));
}

function perThousand(count, total) {
  const denominator = Number(total || 0);
  if (!denominator) return 0;
  return roundNumber((Number(count || 0) / denominator) * 1000, 2);
}

function roundNumber(value, digits = 0) {
  const number = Number(value || 0);
  if (!Number.isFinite(number)) return 0;
  const factor = 10 ** digits;
  return Math.round(number * factor) / factor;
}

function clampScore(value) {
  const number = Number(value || 0);
  if (!Number.isFinite(number)) return 0;
  return Math.max(0, Math.min(100, Math.round(number)));
}

function numberValue(value) {
  return Number(value || 0);
}

export function severityWeight(severity) {
  return SEVERITY_WEIGHT[String(severity || "").toLowerCase()] || 0;
}
