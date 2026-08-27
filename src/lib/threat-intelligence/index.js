import "server-only";

import { createHash } from "node:crypto";
import { and, desc, eq, gte, isNull, lte, or, sql } from "drizzle-orm";
import { db } from "../../db/client.js";
import {
  reputationCache,
  threatFeedStatus,
  threatIndicators,
  threatMatches,
  threatSources,
} from "../../db/schema.js";
import { createAuditEvent } from "../audit/index.js";

export const INDICATOR_TYPES = Object.freeze({
  IP: "ip",
  CIDR: "cidr",
  DOMAIN: "domain",
  URL: "url",
  HASH: "hash",
  ASN: "asn",
  USER_AGENT: "user_agent",
});

export const PROVIDER_CAPABILITIES = Object.freeze({
  IP_REPUTATION: "ip_reputation",
  ASN_CONTEXT: "asn_context",
  DOMAIN_REPUTATION: "domain_reputation",
  URL_REPUTATION: "url_reputation",
  HASH_REPUTATION: "hash_reputation",
  SCANNER_SIGNATURES: "scanner_signatures",
  CAMPAIGN_CONTEXT: "campaign_context",
});

const DEFAULT_CACHE_TTL_MS = 30 * 60 * 1000;
const MAX_CACHE_ENTRIES = 5000;
const hotCache = new Map();

export class ThreatIntelligenceProvider {
  constructor({ id, displayName, capabilities = [] } = {}) {
    this.id = id;
    this.displayName = displayName;
    this.capabilities = capabilities;
  }

  async fetchIndicators() {
    return { indicators: [], cursor: null };
  }

  async lookup() {
    return null;
  }

  async health() {
    return { status: "unknown", latencyMs: null };
  }

  normalize(rawIndicator) {
    return normalizeIndicatorInput(rawIndicator);
  }
}

export const providerRegistry = Object.freeze({
  abuseipdb: new ThreatIntelligenceProvider({
    id: "abuseipdb",
    displayName: "AbuseIPDB",
    capabilities: [PROVIDER_CAPABILITIES.IP_REPUTATION],
  }),
  greynoise: new ThreatIntelligenceProvider({
    id: "greynoise",
    displayName: "GreyNoise",
    capabilities: [PROVIDER_CAPABILITIES.IP_REPUTATION, PROVIDER_CAPABILITIES.SCANNER_SIGNATURES],
  }),
  spamhaus: new ThreatIntelligenceProvider({
    id: "spamhaus",
    displayName: "Spamhaus",
    capabilities: [PROVIDER_CAPABILITIES.IP_REPUTATION, PROVIDER_CAPABILITIES.DOMAIN_REPUTATION],
  }),
  misp: new ThreatIntelligenceProvider({
    id: "misp",
    displayName: "MISP",
    capabilities: Object.values(PROVIDER_CAPABILITIES),
  }),
  stix_taxii: new ThreatIntelligenceProvider({
    id: "stix_taxii",
    displayName: "STIX/TAXII",
    capabilities: Object.values(PROVIDER_CAPABILITIES),
  }),
  local: new ThreatIntelligenceProvider({
    id: "local",
    displayName: "Local Curated Indicators",
    capabilities: Object.values(PROVIDER_CAPABILITIES),
  }),
});

export async function createThreatSource({
  database = db(),
  organizationId = null,
  userId = null,
  input = {},
  auditContext = {},
} = {}) {
  const values = normalizeThreatSourceInput(input);
  const [created] = await database
    .insert(threatSources)
    .values({
      ...values,
      organizationId,
      createdByUserId: userId,
    })
    .returning();

  await createAuditEvent({
    database,
    organizationId,
    userId,
    eventType: "threat_source.created",
    action: "threat_source.create",
    resourceType: "threat_source",
    resourceId: created.id,
    result: "success",
    severity: "info",
    requestId: auditContext.requestId,
    metadata: {
      providerType: created.providerType,
      status: created.status,
      capabilities: created.capabilities || [],
    },
  });

  return presentThreatSource(created);
}

export async function listThreatSources({ database = db(), organizationId, filters = {} } = {}) {
  const predicates = [
    isNull(threatSources.deletedAt),
    or(isNull(threatSources.organizationId), eq(threatSources.organizationId, organizationId)),
  ];
  if (filters.status) predicates.push(eq(threatSources.status, enumValue(filters.status, ["active", "observe", "disabled", "deleted"], "source status")));
  if (filters.providerType) predicates.push(eq(threatSources.providerType, cleanToken(filters.providerType, 80)));

  const rows = await database
    .select()
    .from(threatSources)
    .where(and(...predicates))
    .orderBy(desc(threatSources.updatedAt))
    .limit(limitValue(filters.limit, 100));

  return { items: rows.map(presentThreatSource) };
}

export async function upsertThreatIndicator({
  database = db(),
  organizationId = null,
  userId = null,
  input = {},
  auditContext = {},
} = {}) {
  const normalized = normalizeIndicatorInput(input);
  const scope = input.global === true ? null : organizationId;
  const sourceId = cleanString(input.sourceId, 160);
  const now = new Date();
  const lookup = normalizeLookupValue(normalized.indicatorType, normalized.value);
  const indicatorValueHash = lookup.hash;

  const [existing] = await database
    .select()
    .from(threatIndicators)
    .where(
      and(
        scope ? eq(threatIndicators.organizationId, scope) : isNull(threatIndicators.organizationId),
        eq(threatIndicators.indicatorType, normalized.indicatorType),
        eq(threatIndicators.indicatorValueHash, indicatorValueHash),
        isNull(threatIndicators.deletedAt),
      ),
    )
    .limit(1);

  const values = {
    organizationId: scope,
    sourceId,
    indicatorType: normalized.indicatorType,
    indicatorValueHash,
    indicatorValueDisplay: lookup.display,
    category: normalized.category,
    reputationScore: normalized.reputationScore,
    confidence: normalized.confidence,
    severity: normalized.severity,
    tags: normalized.tags,
    reviewStatus: normalized.reviewStatus,
    firstSeenAt: existing?.firstSeenAt || now,
    lastSeenAt: now,
    expiresAt: normalized.expiresAt,
    sourceMetadata: normalized.sourceMetadata,
    updatedAt: now,
  };

  const [row] = existing
    ? await database.update(threatIndicators).set(values).where(eq(threatIndicators.id, existing.id)).returning()
    : await database.insert(threatIndicators).values(values).returning();

  await refreshReputationCache({ database, organizationId: scope, indicatorType: normalized.indicatorType, lookup });

  await createAuditEvent({
    database,
    organizationId: scope,
    userId,
    eventType: "threat_indicator.upserted",
    action: "threat_indicator.upsert",
    resourceType: "threat_indicator",
    resourceId: row.id,
    result: "success",
    severity: "info",
    requestId: auditContext.requestId,
    metadata: {
      indicatorType: row.indicatorType,
      category: row.category,
      reputationScore: row.reputationScore,
      confidence: row.confidence,
      scope: scope ? "tenant" : "global",
    },
  });

  return presentThreatIndicator(row);
}

export async function reviewThreatIndicator({
  database = db(),
  organizationId,
  userId,
  input = {},
  auditContext = {},
} = {}) {
  const indicatorId = requiredString(input.indicatorId, "indicatorId", 160);
  const reviewStatus = enumValue(input.reviewStatus, ["confirmed", "false_positive", "trusted", "expired"], "review status");
  const analystNote = cleanString(input.analystNote, 2000);
  const expiresAt = parseDate(input.expiresAt);

  const [indicator] = await database
    .select()
    .from(threatIndicators)
    .where(
      and(
        eq(threatIndicators.id, indicatorId),
        or(isNull(threatIndicators.organizationId), eq(threatIndicators.organizationId, organizationId)),
        isNull(threatIndicators.deletedAt),
      ),
    )
    .limit(1);

  if (!indicator) throw new Error("threat indicator not found");

  const [updated] = await database
    .update(threatIndicators)
    .set({
      reviewStatus,
      analystNote,
      expiresAt: expiresAt || indicator.expiresAt,
      reviewedByUserId: userId,
      reviewedAt: new Date(),
      updatedAt: new Date(),
    })
    .where(eq(threatIndicators.id, indicator.id))
    .returning();

  await refreshReputationCache({
    database,
    organizationId: updated.organizationId,
    indicatorType: updated.indicatorType,
    lookup: {
      hash: updated.indicatorValueHash,
      display: updated.indicatorValueDisplay,
      value: updated.indicatorValueDisplay,
    },
  });

  await createAuditEvent({
    database,
    organizationId: updated.organizationId || organizationId,
    userId,
    eventType: "threat_indicator.reviewed",
    action: "threat_indicator.review",
    resourceType: "threat_indicator",
    resourceId: updated.id,
    result: "success",
    severity: reviewStatus === "false_positive" ? "medium" : "info",
    requestId: auditContext.requestId,
    metadata: {
      indicatorType: updated.indicatorType,
      reviewStatus,
      scope: updated.organizationId ? "tenant" : "global",
    },
  });

  return presentThreatIndicator(updated);
}

export async function listThreatIndicators({ database = db(), organizationId, filters = {} } = {}) {
  const predicates = [
    isNull(threatIndicators.deletedAt),
    or(isNull(threatIndicators.organizationId), eq(threatIndicators.organizationId, organizationId)),
  ];
  if (filters.indicatorType) predicates.push(eq(threatIndicators.indicatorType, enumValue(filters.indicatorType, Object.values(INDICATOR_TYPES), "indicator type")));
  if (filters.category) predicates.push(eq(threatIndicators.category, cleanToken(filters.category, 80)));
  if (filters.reviewStatus) predicates.push(eq(threatIndicators.reviewStatus, enumValue(filters.reviewStatus, ["unreviewed", "confirmed", "false_positive", "trusted", "expired"], "review status")));

  const rows = await database
    .select()
    .from(threatIndicators)
    .where(and(...predicates))
    .orderBy(desc(threatIndicators.lastSeenAt), desc(threatIndicators.reputationScore))
    .limit(limitValue(filters.limit, 100));

  return { items: rows.map(presentThreatIndicator) };
}

export async function lookupThreatReputation({
  database = db(),
  organizationId,
  indicatorType,
  value,
  now = new Date(),
} = {}) {
  const lookup = normalizeLookupValue(indicatorType, value);
  const cacheKey = `${organizationId || "global"}:${indicatorType}:${lookup.hash}`;
  const hot = hotCache.get(cacheKey);
  if (hot && hot.expiresAt > now.getTime()) return hot.value;

  const cached = await readReputationCache({ database, organizationId, indicatorType, lookup, now });
  if (cached) {
    setHotCache(cacheKey, cached, new Date(cached.expiresAt).getTime());
    return cached;
  }

  const refreshed = await refreshReputationCache({ database, organizationId, indicatorType, lookup, now });
  setHotCache(cacheKey, refreshed, new Date(refreshed.expiresAt).getTime());
  return refreshed;
}

export async function matchThreatIndicatorsForEvent({ database = db(), event, findingId = null } = {}) {
  if (!event?.organizationId) throw new Error("security event is required for threat matching");
  const lookups = extractEventLookups(event);
  const matches = [];

  for (const lookup of lookups) {
    const reputation = await lookupThreatReputation({
      database,
      organizationId: event.organizationId,
      indicatorType: lookup.indicatorType,
      value: lookup.value,
    });
    if (!reputation || reputation.reputationScore <= 0 || reputation.reviewStatus === "false_positive") continue;
    const match = await recordThreatMatch({
      database,
      event,
      findingId,
      lookup,
      reputation,
    });
    matches.push(match);
  }

  return matches;
}

export async function enrichEventWithThreatIntelligence({ database = db(), event } = {}) {
  const matches = await matchThreatIndicatorsForEvent({ database, event });
  const context = classifyThreatContext(event);
  const riskDelta = Math.min(70, matches.reduce((sum, match) => sum + Number(match.riskDelta || 0), 0));
  const confidenceDelta = Math.min(0.4, matches.reduce((sum, match) => sum + Number(match.confidenceDelta || 0), 0));

  return {
    matches,
    riskDelta,
    confidenceDelta,
    threatContext: {
      ...context,
      indicatorMatches: matches.length,
      sourceIds: Array.from(new Set(matches.map((match) => match.sourceId).filter(Boolean))).slice(0, 20),
      categories: Array.from(new Set(matches.map((match) => match.metadata?.category).filter(Boolean))).slice(0, 20),
    },
  };
}

export async function listThreatMatches({ database = db(), organizationId, filters = {} } = {}) {
  const query = normalizeThreatQuery(filters);
  const predicates = [
    eq(threatMatches.organizationId, organizationId),
    gte(threatMatches.matchedAt, query.since),
    lte(threatMatches.matchedAt, query.until),
  ];
  if (query.indicatorType) predicates.push(eq(threatMatches.indicatorType, query.indicatorType));
  if (query.firewallInstanceId) predicates.push(eq(threatMatches.firewallInstanceId, query.firewallInstanceId));

  const rows = await database
    .select()
    .from(threatMatches)
    .where(and(...predicates))
    .orderBy(desc(threatMatches.matchedAt))
    .limit(query.limit);

  return { items: rows.map(presentThreatMatch), filters: query };
}

export async function getThreatIntelligenceOverview({ database = db(), organizationId, filters = {} } = {}) {
  const query = normalizeThreatQuery(filters);
  const indicatorWhere = and(
    isNull(threatIndicators.deletedAt),
    or(isNull(threatIndicators.organizationId), eq(threatIndicators.organizationId, organizationId)),
  );
  const matchWhere = and(
    eq(threatMatches.organizationId, organizationId),
    gte(threatMatches.matchedAt, query.since),
    lte(threatMatches.matchedAt, query.until),
  );

  const [indicatorSummary] = await database
    .select({
      total: sql`count(*)`,
      malicious: sql`sum(case when ${threatIndicators.reputationScore} >= 70 then 1 else 0 end)`,
      trusted: sql`sum(case when ${threatIndicators.reviewStatus} = 'trusted' then 1 else 0 end)`,
      falsePositive: sql`sum(case when ${threatIndicators.reviewStatus} = 'false_positive' then 1 else 0 end)`,
    })
    .from(threatIndicators)
    .where(indicatorWhere);

  const [matchSummary] = await database
    .select({
      total: sql`count(*)`,
      avgRiskDelta: sql`avg(${threatMatches.riskDelta})`,
      maxRiskDelta: sql`max(${threatMatches.riskDelta})`,
    })
    .from(threatMatches)
    .where(matchWhere);

  const sourceRows = await database
    .select()
    .from(threatSources)
    .where(
      and(
        isNull(threatSources.deletedAt),
        or(isNull(threatSources.organizationId), eq(threatSources.organizationId, organizationId)),
      ),
    )
    .orderBy(desc(threatSources.updatedAt))
    .limit(20);

  const categoryRows = await database
    .select({ category: threatIndicators.category, count: sql`count(*)` })
    .from(threatIndicators)
    .where(indicatorWhere)
    .groupBy(threatIndicators.category)
    .orderBy(sql`count(*) desc`)
    .limit(10);

  return {
    summary: {
      indicators: {
        total: numberValue(indicatorSummary?.total),
        malicious: numberValue(indicatorSummary?.malicious),
        trusted: numberValue(indicatorSummary?.trusted),
        falsePositive: numberValue(indicatorSummary?.falsePositive),
      },
      matches: {
        total: numberValue(matchSummary?.total),
        avgRiskDelta: Math.round(numberValue(matchSummary?.avgRiskDelta)),
        maxRiskDelta: Math.round(numberValue(matchSummary?.maxRiskDelta)),
      },
      sourceHealth: summarizeSourceHealth(sourceRows),
    },
    categories: categoryRows.map((row) => ({ category: row.category, count: numberValue(row.count) })),
    sources: sourceRows.map(presentThreatSource),
    filters: query,
  };
}

export function normalizeIndicatorInput(input = {}) {
  const indicatorType = enumValue(input.indicatorType || input.type, Object.values(INDICATOR_TYPES), "indicator type");
  const value = requiredString(input.value || input.indicatorValue || input.indicatorValueDisplay, "indicator value", 2048);
  return {
    indicatorType,
    value,
    category: cleanToken(input.category || "unknown", 80) || "unknown",
    reputationScore: scoreValue(input.reputationScore ?? input.score ?? 50),
    confidence: confidenceValue(input.confidence ?? 0.5),
    severity: enumValue(input.severity || "medium", ["low", "medium", "high", "critical"], "severity"),
    tags: normalizeTags(input.tags),
    reviewStatus: enumValue(input.reviewStatus || "unreviewed", ["unreviewed", "confirmed", "false_positive", "trusted", "expired"], "review status"),
    expiresAt: parseDate(input.expiresAt) || new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    sourceMetadata: safeMetadata(input.sourceMetadata || input.metadata || {}),
  };
}

export function normalizeLookupValue(indicatorType, value) {
  const type = enumValue(indicatorType, Object.values(INDICATOR_TYPES), "indicator type");
  const raw = requiredString(value, "lookup value", 2048);
  const normalized =
    type === INDICATOR_TYPES.DOMAIN
      ? raw.toLowerCase().replace(/^https?:\/\//, "").split("/")[0]
      : type === INDICATOR_TYPES.URL
        ? normalizeUrl(raw)
        : type === INDICATOR_TYPES.USER_AGENT
          ? raw.toLowerCase().slice(0, 512)
          : raw.trim().toLowerCase();
  return {
    type,
    value: normalized,
    hash: hashValue(`${type}:${normalized}`),
    display: displayValue(type, normalized),
  };
}

export function extractEventLookups(event = {}) {
  const lookups = [];
  if (event.sourceIp) lookups.push({ indicatorType: INDICATOR_TYPES.IP, value: event.sourceIp, context: "source_ip" });
  if (event.rawMetadata?.asn) lookups.push({ indicatorType: INDICATOR_TYPES.ASN, value: String(event.rawMetadata.asn), context: "asn" });
  if (event.userAgent) lookups.push({ indicatorType: INDICATOR_TYPES.USER_AGENT, value: event.userAgent, context: "user_agent" });
  if (event.rawMetadata?.domain) lookups.push({ indicatorType: INDICATOR_TYPES.DOMAIN, value: String(event.rawMetadata.domain), context: "domain" });
  if (event.rawMetadata?.url) lookups.push({ indicatorType: INDICATOR_TYPES.URL, value: String(event.rawMetadata.url), context: "url" });
  if (event.rawMetadata?.fileHash) lookups.push({ indicatorType: INDICATOR_TYPES.HASH, value: String(event.rawMetadata.fileHash), context: "hash" });
  return lookups.slice(0, 12);
}

export function clearThreatIntelHotCache() {
  hotCache.clear();
}

export function hotCacheStats() {
  return { size: hotCache.size, maxEntries: MAX_CACHE_ENTRIES };
}

async function readReputationCache({ database, organizationId, indicatorType, lookup, now }) {
  const rows = await database
    .select()
    .from(reputationCache)
    .where(
      and(
        eq(reputationCache.indicatorType, indicatorType),
        eq(reputationCache.lookupHash, lookup.hash),
        gte(reputationCache.expiresAt, now),
        or(
          organizationId ? eq(reputationCache.organizationId, organizationId) : sql`false`,
          isNull(reputationCache.organizationId),
        ),
      ),
    )
    .orderBy(desc(reputationCache.organizationId), desc(reputationCache.reputationScore))
    .limit(1);

  return rows[0] ? presentReputation(rows[0]) : null;
}

async function refreshReputationCache({ database, organizationId, indicatorType, lookup, now = new Date() }) {
  const indicatorRows = await database
    .select()
    .from(threatIndicators)
    .where(
      and(
        eq(threatIndicators.indicatorType, indicatorType),
        eq(threatIndicators.indicatorValueHash, lookup.hash),
        isNull(threatIndicators.deletedAt),
        or(isNull(threatIndicators.expiresAt), gte(threatIndicators.expiresAt, now)),
        or(
          organizationId ? eq(threatIndicators.organizationId, organizationId) : sql`false`,
          isNull(threatIndicators.organizationId),
        ),
      ),
    )
    .limit(50);

  const activeRows = indicatorRows.filter((row) => row.reviewStatus !== "false_positive" && row.reviewStatus !== "expired");
  const score = Math.max(0, ...activeRows.map((row) => Number(row.reputationScore || 0)));
  const confidence = Math.max(0, ...activeRows.map((row) => Number(row.confidence || 0)));
  const categories = Array.from(new Set(activeRows.map((row) => row.category).filter(Boolean))).slice(0, 20);
  const sourceIds = Array.from(new Set(activeRows.map((row) => row.sourceId).filter(Boolean))).slice(0, 20);
  const indicatorIds = activeRows.map((row) => row.id).slice(0, 50);
  const expiresAt = soonestExpiration(activeRows) || new Date(now.getTime() + DEFAULT_CACHE_TTL_MS);
  const payload = safeMetadata({
    providerMode: "local_cache",
    indicatorCount: activeRows.length,
    reviewStatus: activeRows[0]?.reviewStatus || null,
  });

  const [existing] = await database
    .select()
    .from(reputationCache)
    .where(
      and(
        organizationId ? eq(reputationCache.organizationId, organizationId) : isNull(reputationCache.organizationId),
        eq(reputationCache.indicatorType, indicatorType),
        eq(reputationCache.lookupHash, lookup.hash),
      ),
    )
    .limit(1);

  const values = {
    organizationId,
    indicatorType,
    lookupHash: lookup.hash,
    lookupLabel: lookup.display,
    reputationScore: score,
    confidence,
    categories,
    sourceIds,
    indicatorIds,
    payload,
    expiresAt,
    lastRefreshedAt: now,
    updatedAt: now,
  };

  const [row] = existing
    ? await database.update(reputationCache).set(values).where(eq(reputationCache.id, existing.id)).returning()
    : await database.insert(reputationCache).values(values).returning();

  return presentReputation(row);
}

async function recordThreatMatch({ database, event, findingId, lookup, reputation }) {
  const indicatorId = reputation.indicatorIds?.[0] || null;
  const sourceId = reputation.sourceIds?.[0] || null;
  const riskDelta = riskDeltaForReputation(reputation.reputationScore, reputation.confidence);
  const confidenceDelta = Math.min(0.35, Number(reputation.confidence || 0) * 0.25);

  const [row] = await database
    .insert(threatMatches)
    .values({
      organizationId: event.organizationId,
      firewallInstanceId: event.firewallInstanceId,
      securityEventId: event.id || null,
      detectionFindingId: findingId,
      indicatorId,
      indicatorType: lookup.indicatorType,
      matchValueHash: reputation.lookupHash || normalizeLookupValue(lookup.indicatorType, lookup.value).hash,
      matchLabel: reputation.lookupLabel || displayValue(lookup.indicatorType, lookup.value),
      matchContext: lookup.context || "event",
      riskDelta,
      confidenceDelta,
      sourceId,
      metadata: safeMetadata({
        category: reputation.categories?.[0] || "unknown",
        sourceCount: reputation.sourceIds?.length || 0,
        cacheExpiresAt: reputation.expiresAt,
        storesSensitivePayload: false,
      }),
    })
    .returning();

  return presentThreatMatch(row);
}

function normalizeThreatSourceInput(input = {}) {
  const providerType = cleanToken(input.providerType || "local", 80) || "local";
  const provider = providerRegistry[providerType] || providerRegistry.local;
  return {
    name: requiredString(input.name || provider.displayName, "source name", 160),
    providerType,
    status: enumValue(input.status || "active", ["active", "observe", "disabled", "deleted"], "source status"),
    healthStatus: enumValue(input.healthStatus || "unknown", ["healthy", "degraded", "failed", "unknown"], "source health"),
    capabilities: normalizeTags(input.capabilities?.length ? input.capabilities : provider.capabilities),
    configuration: safeMetadata(input.configuration || {}),
    secretReference: safeMetadata(input.secretReference || {}),
    rateLimitPerMinute: integerRange(input.rateLimitPerMinute ?? 60, 1, 10000, "rate limit"),
    timeoutMs: integerRange(input.timeoutMs ?? 2500, 100, 30000, "timeout"),
  };
}

function normalizeThreatQuery(filters = {}) {
  const now = new Date();
  const until = parseDate(filters.until) || now;
  const since = parseDate(filters.since) || new Date(until.getTime() - 24 * 60 * 60 * 1000);
  if (since > until) throw new Error("since must be before until");
  return {
    since,
    until,
    indicatorType: filters.indicatorType ? enumValue(filters.indicatorType, Object.values(INDICATOR_TYPES), "indicator type") : null,
    firewallInstanceId: cleanString(filters.firewallInstanceId, 160),
    limit: limitValue(filters.limit, 100),
  };
}

function setHotCache(cacheKey, value, expiresAt) {
  if (hotCache.size >= MAX_CACHE_ENTRIES) {
    const oldestKey = hotCache.keys().next().value;
    if (oldestKey) hotCache.delete(oldestKey);
  }
  hotCache.set(cacheKey, { value, expiresAt });
}

function presentThreatSource(row) {
  return {
    id: row.id,
    organizationId: row.organizationId,
    name: row.name,
    providerType: row.providerType,
    status: row.status,
    healthStatus: row.healthStatus,
    capabilities: row.capabilities || [],
    rateLimitPerMinute: row.rateLimitPerMinute,
    timeoutMs: row.timeoutMs,
    lastSyncAt: row.lastSyncAt,
    lastSuccessAt: row.lastSuccessAt,
    lastFailureAt: row.lastFailureAt,
    lastFailureCode: row.lastFailureCode,
    updatedAt: row.updatedAt,
  };
}

function presentThreatIndicator(row) {
  return {
    id: row.id,
    organizationId: row.organizationId,
    sourceId: row.sourceId,
    indicatorType: row.indicatorType,
    indicatorValueDisplay: row.indicatorValueDisplay,
    category: row.category,
    reputationScore: row.reputationScore,
    confidence: row.confidence,
    severity: row.severity,
    tags: row.tags || [],
    reviewStatus: row.reviewStatus,
    firstSeenAt: row.firstSeenAt,
    lastSeenAt: row.lastSeenAt,
    expiresAt: row.expiresAt,
    reviewedAt: row.reviewedAt,
    analystNote: row.analystNote,
  };
}

function presentReputation(row) {
  return {
    id: row.id,
    organizationId: row.organizationId,
    indicatorType: row.indicatorType,
    lookupHash: row.lookupHash,
    lookupLabel: row.lookupLabel,
    reputationScore: row.reputationScore,
    confidence: row.confidence,
    categories: row.categories || [],
    sourceIds: row.sourceIds || [],
    indicatorIds: row.indicatorIds || [],
    payload: row.payload || {},
    expiresAt: row.expiresAt,
    lastRefreshedAt: row.lastRefreshedAt,
    reviewStatus: row.payload?.reviewStatus || null,
  };
}

function presentThreatMatch(row) {
  return {
    id: row.id,
    firewallInstanceId: row.firewallInstanceId,
    securityEventId: row.securityEventId,
    detectionFindingId: row.detectionFindingId,
    correlationEventId: row.correlationEventId,
    indicatorId: row.indicatorId,
    indicatorType: row.indicatorType,
    matchLabel: row.matchLabel,
    matchContext: row.matchContext,
    riskDelta: row.riskDelta,
    confidenceDelta: row.confidenceDelta,
    sourceId: row.sourceId,
    metadata: row.metadata || {},
    matchedAt: row.matchedAt,
  };
}

function summarizeSourceHealth(rows) {
  return rows.reduce(
    (summary, row) => {
      summary.total += 1;
      summary[row.healthStatus] = (summary[row.healthStatus] || 0) + 1;
      return summary;
    },
    { total: 0, healthy: 0, degraded: 0, failed: 0, unknown: 0 },
  );
}

function soonestExpiration(rows) {
  const expirations = rows
    .map((row) => row.expiresAt)
    .filter(Boolean)
    .map((value) => new Date(value))
    .filter((date) => !Number.isNaN(date.getTime()))
    .sort((a, b) => a.getTime() - b.getTime());
  return expirations[0] || null;
}

function riskDeltaForReputation(score, confidence) {
  return Math.round(Math.min(70, Math.max(0, Number(score || 0) * 0.65 * Number(confidence || 0.5))));
}

function classifyThreatContext(event = {}) {
  const userAgent = String(event.userAgent || "").toLowerCase();
  const scanner = /sqlmap|nuclei|nikto|masscan|zgrab|acunetix|burp|zap|dirbuster/.test(userAgent);
  const automation = /curl|python-requests|go-http-client|httpclient|wget|axios/.test(userAgent);
  return {
    ipReputation: scanner ? "suspicious" : "unknown",
    asn: event.rawMetadata?.asn || null,
    geo: event.country ? { country: event.country } : null,
    userAgentFamily: scanner ? "scanner" : automation ? "automation" : "browser_or_unknown",
    scannerSignature: scanner ? userAgent.slice(0, 120) : null,
    confidence: scanner ? 0.86 : automation ? 0.55 : 0.35,
  };
}

function displayValue(type, value) {
  const text = String(value || "").slice(0, 240);
  if (type === INDICATOR_TYPES.USER_AGENT && text.length > 48) return `${text.slice(0, 24)}...${text.slice(-16)}`;
  return text;
}

function normalizeUrl(value) {
  try {
    const url = new URL(value);
    return `${url.protocol}//${url.hostname.toLowerCase()}${url.pathname}`.slice(0, 2048);
  } catch {
    return String(value).trim().toLowerCase().slice(0, 2048);
  }
}

function safeMetadata(value) {
  if (!value || Array.isArray(value) || typeof value !== "object") return {};
  return sanitizeValue(value, []);
}

function sanitizeValue(value, path) {
  if (path.length > 8) throw new Error("threat intelligence metadata exceeds maximum depth");
  if (value == null || typeof value === "boolean" || typeof value === "number") return value;
  if (typeof value === "string") return value.replace(/[^\x20-\x7E]/g, "").slice(0, 2048);
  if (Array.isArray(value)) return value.slice(0, 50).map((item, index) => sanitizeValue(item, [...path, String(index)]));
  if (typeof value === "object") {
    return Object.entries(value).slice(0, 100).reduce((safe, [key, child]) => {
      const cleanKey = String(key || "").replace(/[^\w.-]/g, "_").slice(0, 120);
      if (!cleanKey) throw new Error("threat intelligence metadata contains empty key");
      if (/password|secret|token|cookie|authorization|private[_-]?key|api[_-]?key/i.test(cleanKey)) {
        throw new Error(`threat intelligence metadata contains sensitive field: ${[...path, cleanKey].join(".")}`);
      }
      safe[cleanKey] = sanitizeValue(child, [...path, cleanKey]);
      return safe;
    }, {});
  }
  return null;
}

function hashValue(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}

function requiredString(value, label, maxLength) {
  const text = String(value || "").replace(/[^\x20-\x7E]/g, "").trim().slice(0, maxLength);
  if (!text) throw new Error(`${label} is required`);
  return text;
}

function cleanString(value, maxLength) {
  if (!value) return null;
  return String(value).replace(/[^\x20-\x7E]/g, "").trim().slice(0, maxLength) || null;
}

function cleanToken(value, maxLength) {
  if (!value) return null;
  const token = String(value).trim().toLowerCase().replace(/[^a-z0-9_.:-]/g, "_").slice(0, maxLength);
  return token || null;
}

function enumValue(value, allowed, label) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!allowed.includes(normalized)) throw new Error(`${label} is invalid`);
  return normalized;
}

function normalizeTags(tags) {
  const values = Array.isArray(tags) ? tags : [];
  return Array.from(new Set(values.map((tag) => cleanToken(tag, 80)).filter(Boolean))).slice(0, 40);
}

function scoreValue(value) {
  const score = Number(value);
  if (!Number.isFinite(score) || score < 0 || score > 100) throw new Error("reputation score must be between 0 and 100");
  return score;
}

function confidenceValue(value) {
  const confidence = Number(value);
  if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) throw new Error("confidence must be between 0 and 1");
  return confidence;
}

function integerRange(value, min, max, label) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < min || number > max) throw new Error(`${label} is invalid`);
  return number;
}

function limitValue(value, fallback) {
  const limit = Number(value || fallback);
  return Number.isFinite(limit) ? Math.max(1, Math.min(100, Math.floor(limit))) : fallback;
}

function parseDate(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function numberValue(value) {
  const number = Number(value || 0);
  return Number.isFinite(number) ? number : 0;
}
