import "server-only";

import { and, desc, eq, gte, ilike, lt, lte, or, sql } from "drizzle-orm";
import { db } from "../../db/client.js";
import { firewallInstances, securityEvents } from "../../db/schema.js";
import {
  SECURITY_EVENT_ACTIONS,
  SECURITY_EVENT_SEVERITIES,
  validateFirewallOwnership,
} from "./index.js";

const DEFAULT_LIMIT = 25;
const MAX_LIMIT = 100;
const DEFAULT_ANALYTICS_HOURS = 24;
const MAX_ANALYTICS_DAYS = 90;

export async function listSecurityEvents({
  database = db(),
  organizationId,
  filters = {},
} = {}) {
  if (!organizationId) {
    throw new Error("organizationId is required");
  }

  const query = normalizeSecurityEventQuery(filters);

  if (query.firewallInstanceId) {
    await validateFirewallOwnership(database, organizationId, query.firewallInstanceId);
  }

  const predicates = buildSecurityEventPredicates({ organizationId, query });
  const rows = await database
    .select(securityEventProjection())
    .from(securityEvents)
    .where(and(...predicates))
    .orderBy(desc(securityEvents.occurredAt), desc(securityEvents.id))
    .limit(query.limit + 1);

  const items = rows.slice(0, query.limit);
  const extra = rows.length > query.limit;
  const last = items.at(-1);

  return {
    items,
    pageInfo: {
      limit: query.limit,
      hasMore: extra,
      nextCursor: extra && last ? encodeSecurityEventCursor(last) : null,
    },
    filters: query,
  };
}

export async function getSecurityEventAnalytics({
  database = db(),
  organizationId,
  filters = {},
} = {}) {
  if (!organizationId) {
    throw new Error("organizationId is required");
  }

  const query = normalizeAnalyticsQuery(filters);

  if (query.firewallInstanceId) {
    await validateFirewallOwnership(database, organizationId, query.firewallInstanceId);
  }

  const predicates = buildSecurityEventPredicates({ organizationId, query });
  const whereClause = and(...predicates);

  const [summary] = await database
    .select({
      total: sql`count(*)`,
      blocked: sql`sum(case when ${securityEvents.actionTaken} = 'blocked' then 1 else 0 end)`,
      allowed: sql`sum(case when ${securityEvents.actionTaken} = 'allowed' then 1 else 0 end)`,
      rateLimited: sql`sum(case when ${securityEvents.actionTaken} = 'rate_limited' then 1 else 0 end)`,
      critical: sql`sum(case when ${securityEvents.severity} = 'critical' then 1 else 0 end)`,
      high: sql`sum(case when ${securityEvents.severity} = 'high' then 1 else 0 end)`,
    })
    .from(securityEvents)
    .where(whereClause);

  const [severityCounts, attackTypes, sourceIps, routes, firewallDistribution, timeline] =
    await Promise.all([
      groupedCount(database, whereClause, securityEvents.severity, "severity", 10),
      groupedCount(database, whereClause, securityEvents.attackType, "attackType", 10),
      groupedCount(database, whereClause, securityEvents.sourceIp, "sourceIp", 10),
      groupedCount(database, whereClause, securityEvents.requestPath, "requestPath", 10),
      groupedCount(database, whereClause, securityEvents.firewallInstanceId, "firewallInstanceId", 10),
      timelineCounts(database, whereClause),
    ]);

  return {
    window: {
      since: query.since.toISOString(),
      until: query.until.toISOString(),
    },
    totals: {
      total: numberValue(summary?.total),
      blocked: numberValue(summary?.blocked),
      allowed: numberValue(summary?.allowed),
      rateLimited: numberValue(summary?.rateLimited),
      critical: numberValue(summary?.critical),
      high: numberValue(summary?.high),
    },
    severityCounts,
    topAttackTypes: attackTypes,
    topSourceIps: sourceIps,
    topRoutes: routes,
    firewallDistribution,
    timeline,
  };
}

export function normalizeSecurityEventQuery(filters = {}) {
  const cursor = decodeSecurityEventCursor(filters.cursor);
  const since = nullableDate(filters.since);
  const until = nullableDate(filters.until);

  return {
    limit: boundedLimit(filters.limit),
    cursor,
    severity: nullableEnum(filters.severity, Object.values(SECURITY_EVENT_SEVERITIES)),
    attackType: nullableToken(filters.attackType || filters.attack_type, 80),
    actionTaken: nullableEnum(
      filters.actionTaken || filters.action_taken,
      Object.values(SECURITY_EVENT_ACTIONS),
    ),
    sourceIp: nullableBoundedString(filters.sourceIp || filters.source_ip, 45),
    requestPath: nullableCleanString(filters.requestPath || filters.path_contains, 2048),
    httpMethod: nullableHttpMethod(filters.httpMethod || filters.method),
    firewallInstanceId: nullableBoundedString(filters.firewallInstanceId, 160),
    detectorId: nullableToken(filters.detectorId || filters.detector_id, 80),
    apiRouteId: nullableCleanString(filters.apiRouteId || filters.api_route_id, 2048),
    anomalyType: nullableToken(filters.anomalyType || filters.anomaly_type, 80),
    since,
    until,
  };
}

export function normalizeAnalyticsQuery(filters = {}) {
  const until = nullableDate(filters.until) || new Date();
  const since =
    nullableDate(filters.since) ||
    new Date(until.getTime() - DEFAULT_ANALYTICS_HOURS * 60 * 60 * 1000);
  const maxSince = new Date(until.getTime() - MAX_ANALYTICS_DAYS * 24 * 60 * 60 * 1000);

  return {
    ...normalizeSecurityEventQuery({ ...filters, limit: MAX_LIMIT }),
    since: since < maxSince ? maxSince : since,
    until,
  };
}

export function encodeSecurityEventCursor(event) {
  if (!event?.id || !event?.occurredAt) {
    return null;
  }

  const payload = JSON.stringify({
    id: event.id,
    occurredAt: new Date(event.occurredAt).toISOString(),
  });

  return Buffer.from(payload, "utf8").toString("base64url");
}

export function decodeSecurityEventCursor(cursor) {
  if (!cursor) {
    return null;
  }

  try {
    const parsed = JSON.parse(Buffer.from(String(cursor), "base64url").toString("utf8"));
    const occurredAt = requiredDate(parsed.occurredAt);
    const id = nullableBoundedString(parsed.id, 160);
    return id ? { id, occurredAt } : null;
  } catch {
    throw new Error("security event cursor is invalid");
  }
}

function securityEventProjection() {
  return {
    id: securityEvents.id,
    organizationId: securityEvents.organizationId,
    firewallInstanceId: securityEvents.firewallInstanceId,
    eventType: securityEvents.eventType,
    attackType: securityEvents.attackType,
    severity: securityEvents.severity,
    sourceIp: securityEvents.sourceIp,
    requestPath: securityEvents.requestPath,
    httpMethod: securityEvents.httpMethod,
    userAgent: securityEvents.userAgent,
    country: securityEvents.country,
    confidence: securityEvents.confidence,
    detectorId: securityEvents.detectorId,
    detectorIds: securityEvents.detectorIds,
    score: securityEvents.score,
    apiRouteId: securityEvents.apiRouteId,
    anomalyType: securityEvents.anomalyType,
    actionTaken: securityEvents.actionTaken,
    requestId: securityEvents.requestId,
    rawMetadata: securityEvents.rawMetadata,
    occurredAt: securityEvents.occurredAt,
    receivedAt: securityEvents.receivedAt,
  };
}

function buildSecurityEventPredicates({ organizationId, query }) {
  const predicates = [eq(securityEvents.organizationId, organizationId)];

  if (query.firewallInstanceId) {
    predicates.push(eq(securityEvents.firewallInstanceId, query.firewallInstanceId));
  }

  if (query.severity) {
    predicates.push(eq(securityEvents.severity, query.severity));
  }

  if (query.attackType) {
    predicates.push(eq(securityEvents.attackType, query.attackType));
  }

  if (query.actionTaken) {
    predicates.push(eq(securityEvents.actionTaken, query.actionTaken));
  }

  if (query.sourceIp) {
    predicates.push(eq(securityEvents.sourceIp, query.sourceIp));
  }

  if (query.requestPath) {
    predicates.push(ilike(securityEvents.requestPath, `%${query.requestPath}%`));
  }

  if (query.httpMethod) {
    predicates.push(eq(securityEvents.httpMethod, query.httpMethod));
  }

  if (query.detectorId) {
    predicates.push(eq(securityEvents.detectorId, query.detectorId));
  }

  if (query.apiRouteId) {
    predicates.push(ilike(securityEvents.apiRouteId, `%${query.apiRouteId}%`));
  }

  if (query.anomalyType) {
    predicates.push(eq(securityEvents.anomalyType, query.anomalyType));
  }

  if (query.since) {
    predicates.push(gte(securityEvents.occurredAt, query.since));
  }

  if (query.until) {
    predicates.push(lte(securityEvents.occurredAt, query.until));
  }

  if (query.cursor) {
    predicates.push(
      or(
        lt(securityEvents.occurredAt, query.cursor.occurredAt),
        and(eq(securityEvents.occurredAt, query.cursor.occurredAt), lt(securityEvents.id, query.cursor.id)),
      ),
    );
  }

  return predicates;
}

async function groupedCount(database, whereClause, column, key, limit) {
  const rows = await database
    .select({
      [key]: column,
      count: sql`count(*)`,
    })
    .from(securityEvents)
    .where(whereClause)
    .groupBy(column)
    .orderBy(desc(sql`count(*)`))
    .limit(limit);

  return rows
    .filter((row) => row[key])
    .map((row) => ({
      [key]: row[key],
      count: numberValue(row.count),
    }));
}

async function timelineCounts(database, whereClause) {
  const bucket = sql`date_trunc('hour', ${securityEvents.occurredAt})`;
  const rows = await database
    .select({
      bucket,
      count: sql`count(*)`,
    })
    .from(securityEvents)
    .where(whereClause)
    .groupBy(bucket)
    .orderBy(bucket)
    .limit(500);

  return rows.map((row) => ({
    bucket: new Date(row.bucket).toISOString(),
    count: numberValue(row.count),
  }));
}

function boundedLimit(value) {
  const limit = Number(value || DEFAULT_LIMIT);
  return Number.isFinite(limit) && limit > 0 ? Math.min(Math.trunc(limit), MAX_LIMIT) : DEFAULT_LIMIT;
}

function nullableEnum(value, allowed) {
  if (!value) {
    return null;
  }

  const normalized = String(value).trim().toLowerCase();
  if (!allowed.includes(normalized)) {
    throw new Error("security event filter is invalid");
  }

  return normalized;
}

function nullableToken(value, maxLength) {
  if (!value) {
    return null;
  }

  const normalized = String(value).trim().toLowerCase();
  if (!/^[a-z0-9_.:-]+$/.test(normalized)) {
    throw new Error("security event token filter is invalid");
  }

  return normalized.slice(0, maxLength);
}

function nullableBoundedString(value, maxLength) {
  if (!value) {
    return null;
  }

  return String(value).trim().slice(0, maxLength) || null;
}

function nullableCleanString(value, maxLength) {
  if (!value) {
    return null;
  }

  return String(value).replace(/[^\x20-\x7E]/g, "").trim().slice(0, maxLength) || null;
}

function nullableHttpMethod(value) {
  if (!value) {
    return null;
  }

  const method = String(value).trim().toUpperCase();
  if (!/^[A-Z]{1,16}$/.test(method)) {
    throw new Error("http method filter is invalid");
  }

  return method;
}

function nullableDate(value) {
  if (!value) {
    return null;
  }

  return requiredDate(value);
}

function requiredDate(value) {
  const date = value instanceof Date ? value : new Date(value || "");
  if (Number.isNaN(date.getTime())) {
    throw new Error("security event date filter is invalid");
  }

  return date;
}

function numberValue(value) {
  return Number(value || 0);
}
