import "server-only";

import { and, desc, eq, ilike, sql } from "drizzle-orm";
import { db } from "../../db/client.js";
import { apiInventoryRoutes } from "../../db/schema.js";

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;
const STATUS_VALUES = new Set(["new", "known", "approved", "deprecated", "unknown"]);

export async function upsertApiInventoryFromSecurityEvent({ database = db(), event } = {}) {
  const routeTemplate = cleanRouteTemplate(event?.apiRouteId || event?.requestPath);
  if (!event?.organizationId || !event?.firewallInstanceId || !routeTemplate) {
    return null;
  }

  const method = cleanMethod(event.httpMethod);
  const contentTypes = extractContentTypes(event.rawMetadata);
  const statusCodes = extractStatusCodes(event.rawMetadata);
  const schemaSummary = extractSchemaSummary(event.rawMetadata);
  const seenAt = event.occurredAt instanceof Date ? event.occurredAt : new Date(event.occurredAt);

  const values = {
    organizationId: event.organizationId,
    firewallInstanceId: event.firewallInstanceId,
    routeTemplate,
    methods: method ? [method] : [],
    firstSeenAt: seenAt,
    lastSeenAt: seenAt,
    status: statusFromEvent(event),
    observedRequestCount: 1,
    observedStatusCodes: statusCodes,
    contentTypes,
    learnedSchemaSummary: schemaSummary,
  };

  const insert = database.insert(apiInventoryRoutes).values(values);
  if (typeof insert.onConflictDoUpdate !== "function") {
    await insert.returning?.();
    return values;
  }

  const [route] = await insert
    .onConflictDoUpdate({
      target: [
        apiInventoryRoutes.organizationId,
        apiInventoryRoutes.firewallInstanceId,
        apiInventoryRoutes.routeTemplate,
      ],
      set: {
        methods: sql`(
          select array_agg(distinct item order by item)
          from unnest(${apiInventoryRoutes.methods} || excluded.methods) as item
        )`,
        lastSeenAt: sql`greatest(${apiInventoryRoutes.lastSeenAt}, excluded.last_seen_at)`,
        observedRequestCount: sql`${apiInventoryRoutes.observedRequestCount} + 1`,
        observedStatusCodes: sql`(
          select array_agg(distinct item order by item)
          from unnest(${apiInventoryRoutes.observedStatusCodes} || excluded.observed_status_codes) as item
        )`,
        contentTypes: sql`(
          select array_agg(distinct item order by item)
          from unnest(${apiInventoryRoutes.contentTypes} || excluded.content_types) as item
        )`,
        learnedSchemaSummary: sql`${apiInventoryRoutes.learnedSchemaSummary} || excluded.learned_schema_summary`,
        updatedAt: sql`now()`,
      },
    })
    .returning();

  return route || values;
}

export async function listApiInventoryRoutes({
  database = db(),
  organizationId,
  filters = {},
} = {}) {
  if (!organizationId) {
    throw new Error("organizationId is required");
  }

  const query = normalizeInventoryQuery(filters);
  const predicates = [eq(apiInventoryRoutes.organizationId, organizationId)];

  if (query.firewallInstanceId) {
    predicates.push(eq(apiInventoryRoutes.firewallInstanceId, query.firewallInstanceId));
  }

  if (query.status) {
    predicates.push(eq(apiInventoryRoutes.status, query.status));
  }

  if (query.route) {
    predicates.push(ilike(apiInventoryRoutes.routeTemplate, `%${query.route}%`));
  }

  const rows = await database
    .select({
      id: apiInventoryRoutes.id,
      firewallInstanceId: apiInventoryRoutes.firewallInstanceId,
      routeTemplate: apiInventoryRoutes.routeTemplate,
      methods: apiInventoryRoutes.methods,
      firstSeenAt: apiInventoryRoutes.firstSeenAt,
      lastSeenAt: apiInventoryRoutes.lastSeenAt,
      status: apiInventoryRoutes.status,
      observedRequestCount: apiInventoryRoutes.observedRequestCount,
      observedStatusCodes: apiInventoryRoutes.observedStatusCodes,
      contentTypes: apiInventoryRoutes.contentTypes,
      learnedSchemaSummary: apiInventoryRoutes.learnedSchemaSummary,
      updatedAt: apiInventoryRoutes.updatedAt,
    })
    .from(apiInventoryRoutes)
    .where(and(...predicates))
    .orderBy(desc(apiInventoryRoutes.lastSeenAt), desc(apiInventoryRoutes.id))
    .limit(query.limit);

  return { items: rows, filters: query };
}

export function normalizeInventoryQuery(filters = {}) {
  return {
    limit: boundedLimit(filters.limit),
    firewallInstanceId: nullableString(filters.firewallInstanceId, 160),
    status: nullableStatus(filters.status),
    route: nullableRouteSearch(filters.route || filters.path_contains),
  };
}

function statusFromEvent(event) {
  if (event.attackType === "shadow_api" || event.attackType === "api_inventory") {
    return "new";
  }
  if (event.rawMetadata?.inventoryStatus && STATUS_VALUES.has(event.rawMetadata.inventoryStatus)) {
    return event.rawMetadata.inventoryStatus;
  }
  return "known";
}

function extractContentTypes(metadata = {}) {
  const values = [
    metadata.requestContentType,
    metadata.responseContentType,
    ...(metadata.request_content_types || []),
    ...(metadata.response_content_types || []),
  ];
  return uniq(values.map((value) => cleanContentType(value)).filter(Boolean)).slice(0, 12);
}

function extractStatusCodes(metadata = {}) {
  const values = [
    metadata.statusCode,
    metadata.responseStatus,
    ...(metadata.observedStatusCodes || []),
    ...(metadata.observed_status_codes || []),
  ];
  return uniq(
    values
      .map((value) => Number(value))
      .filter((value) => Number.isInteger(value) && value >= 100 && value <= 599),
  ).slice(0, 32);
}

function extractSchemaSummary(metadata = {}) {
  const detectorIds = metadata.detector_ids || metadata.detectorIds || metadata.rule_ids || [];
  return {
    detectorIds: Array.isArray(detectorIds) ? detectorIds.slice(0, 20) : [],
    categories: Array.isArray(metadata.categories) ? metadata.categories.slice(0, 20) : [],
    findingCount: Number(metadata.finding_count || metadata.findingCount || 0),
  };
}

function cleanRouteTemplate(value) {
  if (!value) return null;
  const path = String(value).split("?")[0].replace(/[^\x20-\x7E]/g, "").trim();
  if (!path.startsWith("/")) return null;
  return path.replace(/\/+/g, "/").slice(0, 2048);
}

function cleanMethod(value) {
  if (!value) return null;
  const method = String(value).trim().toUpperCase();
  return /^[A-Z]{1,16}$/.test(method) ? method : null;
}

function cleanContentType(value) {
  if (!value) return null;
  return String(value).toLowerCase().replace(/[^\w.+/-]/g, "").slice(0, 120) || null;
}

function boundedLimit(value) {
  const limit = Number(value || DEFAULT_LIMIT);
  return Number.isFinite(limit) && limit > 0 ? Math.min(Math.trunc(limit), MAX_LIMIT) : DEFAULT_LIMIT;
}

function nullableString(value, maxLength) {
  return value ? String(value).trim().slice(0, maxLength) || null : null;
}

function nullableStatus(value) {
  if (!value) return null;
  const status = String(value).trim().toLowerCase();
  if (!STATUS_VALUES.has(status)) {
    throw new Error("api inventory status filter is invalid");
  }
  return status;
}

function nullableRouteSearch(value) {
  return value ? String(value).replace(/[^\x20-\x7E]/g, "").trim().slice(0, 512) || null : null;
}

function uniq(values) {
  return Array.from(new Set(values));
}
