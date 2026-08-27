import "server-only";

import { and, count, desc, eq, inArray, isNull, or } from "drizzle-orm";
import { db } from "../../db/client.js";
import {
  backupJobs,
  developerApps,
  integrationCatalog,
  marketplaceListings,
  platformHealthRecords,
  platformRegions,
  recoveryEvents,
  regionalServices,
  residencyPolicies,
  restoreOperations,
  tenantRegionAssignments,
  webhookSubscriptions,
} from "../../db/schema.js";
import {
  AUDIT_EVENT_TYPES,
  AUDIT_RESULTS,
  AUDIT_SEVERITIES,
  createAuditEvent,
} from "../audit/index.js";

export const PLATFORM_REGION_STATUSES = Object.freeze({
  PLANNED: "planned",
  ACTIVE: "active",
  DEGRADED: "degraded",
  MAINTENANCE: "maintenance",
  RETIRED: "retired",
});

export const REGIONAL_SERVICE_TYPES = Object.freeze({
  CONTROL_PLANE: "control_plane",
  GATEWAY: "gateway",
  DATABASE: "database",
  INGESTION: "ingestion",
  NOTIFICATION: "notification",
  AI: "ai",
  MARKETPLACE: "marketplace",
  DEVELOPER_API: "developer_api",
});

export const PLATFORM_HEALTH_STATUSES = Object.freeze({
  HEALTHY: "healthy",
  DEGRADED: "degraded",
  DOWN: "down",
  MAINTENANCE: "maintenance",
  UNKNOWN: "unknown",
});

export const INTEGRATION_CATEGORIES = Object.freeze({
  SIEM: "siem",
  SOAR: "soar",
  TICKETING: "ticketing",
  IDENTITY: "identity",
  CLOUD: "cloud",
  NOTIFICATION: "notification",
  THREAT_INTELLIGENCE: "threat_intelligence",
  COMPLIANCE: "compliance",
  DEVELOPER: "developer",
});

const REGION_STATUSES = Object.values(PLATFORM_REGION_STATUSES);
const SERVICE_TYPES = Object.values(REGIONAL_SERVICE_TYPES);
const SERVICE_STATUSES = ["planned", "active", "degraded", "maintenance", "failed", "retired"];
const HEALTH_STATUSES = Object.values(PLATFORM_HEALTH_STATUSES);
const ASSIGNMENT_TYPES = ["home", "failover", "processing", "archive"];
const RESIDENCY_STATUSES = ["active", "draft", "disabled", "retired"];
const BACKUP_STATUSES = ["scheduled", "running", "completed", "failed", "cancelled"];
const RESTORE_STATUSES = ["requested", "approved", "running", "completed", "failed", "cancelled"];
const RECOVERY_EVENT_TYPES = [
  "backup_completed",
  "backup_failed",
  "restore_requested",
  "restore_completed",
  "failover_started",
  "failover_completed",
  "region_degraded",
  "region_recovered",
];
const DEVELOPER_APP_STATUSES = ["active", "disabled", "deleted"];
const APP_TYPES = ["api_consumer", "webhook_app", "partner_integration", "internal_tool"];
const CATALOG_STATUSES = ["draft", "review", "active", "deprecated", "disabled"];
const MARKETPLACE_STATUSES = ["draft", "review", "published", "suspended", "retired"];
const REVIEW_STATUSES = ["not_started", "in_review", "approved", "rejected", "expired"];

export async function getPlatformOverview({ database = db(), organizationId } = {}) {
  const [
    activeRegions,
    degradedHealth,
    tenantAssignments,
    developerAppCount,
    marketplacePublished,
    backupFailures,
    health,
  ] = await Promise.all([
    scalarCount(database, platformRegions, eq(platformRegions.status, "active")),
    scalarCount(database, platformHealthRecords, and(eq(platformHealthRecords.organizationId, organizationId), or(eq(platformHealthRecords.status, "degraded"), eq(platformHealthRecords.status, "down")))),
    scalarCount(database, tenantRegionAssignments, and(eq(tenantRegionAssignments.organizationId, organizationId), eq(tenantRegionAssignments.status, "active"))),
    scalarCount(database, developerApps, and(eq(developerApps.organizationId, organizationId), eq(developerApps.status, "active"), isNull(developerApps.deletedAt))),
    scalarCount(database, marketplaceListings, eq(marketplaceListings.status, "published")),
    scalarCount(database, backupJobs, and(eq(backupJobs.organizationId, organizationId), eq(backupJobs.status, "failed"))),
    listPlatformHealth({ database, organizationId, filters: { limit: 50 } }),
  ]);

  return {
    summary: {
      activeRegions,
      degradedHealth,
      tenantAssignments,
      developerApps: developerAppCount,
      marketplaceListings: marketplacePublished,
      backupFailures,
    },
    health: health.rollup,
    governance: {
      productionDnsManagedHere: false,
      crossRegionFailoverRequiresApproval: true,
      residencyBypassAllowed: false,
      hiddenProviderCredentialsExposed: false,
    },
  };
}

export async function listRegions({ database = db(), organizationId, filters = {} } = {}) {
  const regions = await database
    .select()
    .from(platformRegions)
    .where(filters.status ? eq(platformRegions.status, safeString(filters.status, 32)) : undefined)
    .orderBy(desc(platformRegions.updatedAt))
    .limit(boundedLimit(filters.limit, 100, 200));

  const assignments = await database
    .select()
    .from(tenantRegionAssignments)
    .where(eq(tenantRegionAssignments.organizationId, organizationId))
    .orderBy(desc(tenantRegionAssignments.updatedAt))
    .limit(200);

  const assignmentMap = new Map(assignments.map((row) => [row.regionId, row]));
  return {
    items: regions.map((region) => ({
      ...region,
      tenantAssignment: assignmentMap.get(region.id) || null,
    })),
  };
}

export async function createRegion({ database = db(), organizationId, userId, input = {}, auditContext } = {}) {
  const regionKey = normalizeSlug(input.regionKey || input.name);
  const name = safeString(input.name, 160);
  if (!regionKey || !name) throw new Error("region key and name are required");

  const [row] = await database
    .insert(platformRegions)
    .values({
      regionKey,
      name,
      geography: safeString(input.geography || "global", 120),
      provider: safeString(input.provider || "multi_provider", 80),
      status: enumValue(input.status || "planned", REGION_STATUSES, "region status"),
      dataResidencyClass: safeString(input.dataResidencyClass || "standard", 80),
      primaryControlPlane: Boolean(input.primaryControlPlane),
      failoverAllowed: Boolean(input.failoverAllowed),
      metadata: safeMetadata(input.metadata),
    })
    .onConflictDoUpdate({
      target: platformRegions.regionKey,
      set: {
        name,
        geography: safeString(input.geography || "global", 120),
        provider: safeString(input.provider || "multi_provider", 80),
        status: enumValue(input.status || "planned", REGION_STATUSES, "region status"),
        dataResidencyClass: safeString(input.dataResidencyClass || "standard", 80),
        primaryControlPlane: Boolean(input.primaryControlPlane),
        failoverAllowed: Boolean(input.failoverAllowed),
        metadata: safeMetadata(input.metadata),
        updatedAt: new Date(),
      },
    })
    .returning();

  await auditGlobalScale({
    database,
    organizationId,
    userId,
    eventType: AUDIT_EVENT_TYPES.PLATFORM_REGION_CREATED,
    action: "platform.region.upsert",
    resourceType: "platform_region",
    resourceId: row.id,
    requestId: auditContext?.requestId,
    metadata: { regionKey, status: row.status },
  });

  return row;
}

export async function assignTenantRegion({ database = db(), organizationId, userId, input = {}, auditContext } = {}) {
  const regionId = requiredString(input.regionId, "region");
  await requireRegionExists(database, regionId);
  const assignmentType = enumValue(input.assignmentType || "home", ASSIGNMENT_TYPES, "assignment type");

  const [row] = await database
    .insert(tenantRegionAssignments)
    .values({
      organizationId,
      regionId,
      assignmentType,
      status: enumValue(input.status || "active", ["active", "disabled", "deleted"], "assignment status"),
      routingPriority: boundedNumber(input.routingPriority, 1, 1000, 100),
      residencyLocked: input.residencyLocked !== false,
      failoverRegionIds: normalizeStringArray(input.failoverRegionIds, 20),
      assignedByUserId: userId,
      metadata: safeMetadata(input.metadata),
    })
    .onConflictDoUpdate({
      target: [tenantRegionAssignments.organizationId, tenantRegionAssignments.regionId, tenantRegionAssignments.assignmentType],
      set: {
        status: enumValue(input.status || "active", ["active", "disabled", "deleted"], "assignment status"),
        routingPriority: boundedNumber(input.routingPriority, 1, 1000, 100),
        residencyLocked: input.residencyLocked !== false,
        failoverRegionIds: normalizeStringArray(input.failoverRegionIds, 20),
        assignedByUserId: userId,
        metadata: safeMetadata(input.metadata),
        updatedAt: new Date(),
      },
    })
    .returning();

  await auditGlobalScale({
    database,
    organizationId,
    userId,
    eventType: AUDIT_EVENT_TYPES.TENANT_REGION_ASSIGNED,
    action: "platform.tenant_region.assign",
    resourceType: "tenant_region_assignment",
    resourceId: row.id,
    requestId: auditContext?.requestId,
    metadata: { regionId, assignmentType, status: row.status },
  });

  return row;
}

export async function listPlatformHealth({ database = db(), organizationId, filters = {} } = {}) {
  const predicates = [or(isNull(platformHealthRecords.organizationId), eq(platformHealthRecords.organizationId, organizationId))];
  if (filters.status) predicates.push(eq(platformHealthRecords.status, safeString(filters.status, 32)));
  if (filters.serviceType) predicates.push(eq(platformHealthRecords.serviceType, safeString(filters.serviceType, 48)));

  const rows = await database
    .select()
    .from(platformHealthRecords)
    .where(and(...predicates))
    .orderBy(desc(platformHealthRecords.checkedAt))
    .limit(boundedLimit(filters.limit, 100, 500));

  return { items: rows, rollup: calculateHealthRollup(rows) };
}

export async function recordPlatformHealth({ database = db(), organizationId, userId, input = {}, auditContext } = {}) {
  const [row] = await database
    .insert(platformHealthRecords)
    .values({
      organizationId: input.global === true ? null : organizationId,
      regionId: nullableString(input.regionId, 80),
      serviceId: nullableString(input.serviceId, 80),
      serviceType: enumValue(input.serviceType || "control_plane", SERVICE_TYPES, "service type"),
      status: enumValue(input.status || "unknown", HEALTH_STATUSES, "health status"),
      availabilityPercent: boundedFloat(input.availabilityPercent, 0, 100, 100),
      latencyP95Ms: boundedNumber(input.latencyP95Ms, 0, 3_600_000, 0),
      errorRatePercent: boundedFloat(input.errorRatePercent, 0, 100, 0),
      checkedAt: optionalDate(input.checkedAt) || new Date(),
      details: safeMetadata(input.details),
    })
    .returning();

  await auditGlobalScale({
    database,
    organizationId,
    userId,
    eventType: AUDIT_EVENT_TYPES.PLATFORM_HEALTH_RECORDED,
    action: "platform.health.record",
    resourceType: "platform_health_record",
    resourceId: row.id,
    requestId: auditContext?.requestId,
    metadata: { serviceType: row.serviceType, status: row.status },
  });

  return row;
}

export async function createRegionalService({ database = db(), organizationId, userId, input = {}, auditContext } = {}) {
  const regionId = requiredString(input.regionId, "region");
  await requireRegionExists(database, regionId);

  const [row] = await database
    .insert(regionalServices)
    .values({
      regionId,
      organizationId: input.global === true ? null : organizationId,
      serviceType: enumValue(input.serviceType || "gateway", SERVICE_TYPES, "service type"),
      name: requiredString(input.name, "service name"),
      provider: safeString(input.provider || "unknown", 80),
      status: enumValue(input.status || "planned", SERVICE_STATUSES, "service status"),
      endpointHost: nullableHost(input.endpointHost),
      healthCheckPath: safePath(input.healthCheckPath || "/healthz"),
      lastHealthyAt: optionalDate(input.lastHealthyAt),
      metadata: safeMetadata(input.metadata),
    })
    .returning();

  await auditGlobalScale({
    database,
    organizationId,
    userId,
    eventType: AUDIT_EVENT_TYPES.REGIONAL_SERVICE_REGISTERED,
    action: "platform.regional_service.register",
    resourceType: "regional_service",
    resourceId: row.id,
    requestId: auditContext?.requestId,
    metadata: { regionId, serviceType: row.serviceType, status: row.status },
  });

  return row;
}

export async function listDeveloperApps({ database = db(), organizationId, filters = {} } = {}) {
  const predicates = [eq(developerApps.organizationId, organizationId), isNull(developerApps.deletedAt)];
  if (filters.status) predicates.push(eq(developerApps.status, safeString(filters.status, 32)));
  return {
    items: await database
      .select()
      .from(developerApps)
      .where(and(...predicates))
      .orderBy(desc(developerApps.updatedAt))
      .limit(boundedLimit(filters.limit, 100, 200)),
  };
}

export async function createDeveloperApp({ database = db(), organizationId, userId, input = {}, auditContext } = {}) {
  const name = requiredString(input.name, "app name");
  const slug = normalizeSlug(input.slug || name);
  if (!slug) throw new Error("app slug is required");

  const [row] = await database
    .insert(developerApps)
    .values({
      organizationId,
      ownerUserId: userId,
      name,
      slug,
      status: enumValue(input.status || "active", DEVELOPER_APP_STATUSES, "app status"),
      appType: enumValue(input.appType || "api_consumer", APP_TYPES, "app type"),
      callbackUrls: normalizeUrls(input.callbackUrls, 20),
      allowedScopes: normalizeStringArray(input.allowedScopes, 100),
      rateLimitPerMinute: boundedNumber(input.rateLimitPerMinute, 1, 100000, 60),
      metadata: safeMetadata(input.metadata),
    })
    .onConflictDoUpdate({
      target: [developerApps.organizationId, developerApps.slug],
      set: {
        name,
        status: enumValue(input.status || "active", DEVELOPER_APP_STATUSES, "app status"),
        appType: enumValue(input.appType || "api_consumer", APP_TYPES, "app type"),
        callbackUrls: normalizeUrls(input.callbackUrls, 20),
        allowedScopes: normalizeStringArray(input.allowedScopes, 100),
        rateLimitPerMinute: boundedNumber(input.rateLimitPerMinute, 1, 100000, 60),
        metadata: safeMetadata(input.metadata),
        updatedAt: new Date(),
      },
    })
    .returning();

  await auditGlobalScale({
    database,
    organizationId,
    userId,
    eventType: AUDIT_EVENT_TYPES.DEVELOPER_APP_CREATED,
    action: "developer.app.upsert",
    resourceType: "developer_app",
    resourceId: row.id,
    requestId: auditContext?.requestId,
    metadata: { slug, appType: row.appType, status: row.status },
  });

  return row;
}

export async function listIntegrationCatalog({ database = db(), organizationId, filters = {} } = {}) {
  const predicates = [or(isNull(integrationCatalog.organizationId), eq(integrationCatalog.organizationId, organizationId))];
  if (filters.category) predicates.push(eq(integrationCatalog.category, safeString(filters.category, 48)));
  if (filters.status) predicates.push(eq(integrationCatalog.status, safeString(filters.status, 32)));

  return {
    items: await database
      .select()
      .from(integrationCatalog)
      .where(and(...predicates))
      .orderBy(desc(integrationCatalog.updatedAt))
      .limit(boundedLimit(filters.limit, 100, 200)),
  };
}

export async function createIntegrationCatalogEntry({ database = db(), organizationId, userId, input = {}, auditContext } = {}) {
  const name = requiredString(input.name, "integration name");
  const slug = normalizeSlug(input.slug || `${organizationId}-${name}`);
  if (!slug) throw new Error("integration slug is required");

  const [row] = await database
    .insert(integrationCatalog)
    .values({
      organizationId: input.global === true ? null : organizationId,
      publisherOrganizationId: organizationId,
      name,
      slug,
      category: enumValue(input.category || "developer", Object.values(INTEGRATION_CATEGORIES), "integration category"),
      status: enumValue(input.status || "draft", CATALOG_STATUSES, "integration status"),
      capabilityManifest: safeMetadata(input.capabilityManifest),
      permissionManifest: normalizeStringArray(input.permissionManifest, 100),
      securityReviewStatus: enumValue(input.securityReviewStatus || "not_started", REVIEW_STATUSES, "security review status"),
      version: safeString(input.version || "0.1.0", 40),
      metadata: safeMetadata(input.metadata),
    })
    .onConflictDoUpdate({
      target: integrationCatalog.slug,
      set: {
        name,
        category: enumValue(input.category || "developer", Object.values(INTEGRATION_CATEGORIES), "integration category"),
        status: enumValue(input.status || "draft", CATALOG_STATUSES, "integration status"),
        capabilityManifest: safeMetadata(input.capabilityManifest),
        permissionManifest: normalizeStringArray(input.permissionManifest, 100),
        securityReviewStatus: enumValue(input.securityReviewStatus || "not_started", REVIEW_STATUSES, "security review status"),
        version: safeString(input.version || "0.1.0", 40),
        metadata: safeMetadata(input.metadata),
        updatedAt: new Date(),
      },
    })
    .returning();

  await auditGlobalScale({
    database,
    organizationId,
    userId,
    eventType: AUDIT_EVENT_TYPES.INTEGRATION_CATALOG_CREATED,
    action: "integration.catalog.upsert",
    resourceType: "integration_catalog",
    resourceId: row.id,
    requestId: auditContext?.requestId,
    metadata: { slug, category: row.category, status: row.status },
  });

  return row;
}

export async function listMarketplace({ database = db(), organizationId, filters = {} } = {}) {
  const predicates = [];
  if (filters.category) predicates.push(eq(marketplaceListings.category, safeString(filters.category, 48)));
  if (filters.status) predicates.push(eq(marketplaceListings.status, safeString(filters.status, 32)));

  const rows = await database
    .select()
    .from(marketplaceListings)
    .where(predicates.length ? and(...predicates) : undefined)
    .orderBy(desc(marketplaceListings.updatedAt))
    .limit(boundedLimit(filters.limit, 100, 200));

  const integrationIds = rows.map((row) => row.integrationId);
  const integrations = integrationIds.length
    ? await database
        .select()
        .from(integrationCatalog)
        .where(
          and(
            inArray(integrationCatalog.id, integrationIds),
            or(isNull(integrationCatalog.organizationId), eq(integrationCatalog.organizationId, organizationId)),
          ),
        )
    : [];
  const integrationMap = new Map(integrations.map((row) => [row.id, row]));

  return {
    items: rows
      .map((row) => ({ ...row, integration: integrationMap.get(row.integrationId) || null }))
      .filter((row) => row.integration),
  };
}

export async function createMarketplaceListing({ database = db(), organizationId, userId, input = {}, auditContext } = {}) {
  const integrationId = requiredString(input.integrationId, "integration");
  const [integration] = await database
    .select()
    .from(integrationCatalog)
    .where(
      and(
        eq(integrationCatalog.id, integrationId),
        or(isNull(integrationCatalog.organizationId), eq(integrationCatalog.organizationId, organizationId)),
      ),
    )
    .limit(1);
  if (!integration) throw new Error("integration not found");

  const [row] = await database
    .insert(marketplaceListings)
    .values({
      integrationId,
      publisherOrganizationId: organizationId,
      name: requiredString(input.name || integration.name, "listing name"),
      category: enumValue(input.category || integration.category, Object.values(INTEGRATION_CATEGORIES), "listing category"),
      status: enumValue(input.status || "draft", MARKETPLACE_STATUSES, "listing status"),
      summary: safeString(input.summary || "Marketplace integration listing", 4000),
      capabilities: normalizeStringArray(input.capabilities, 100),
      pricingModel: safeString(input.pricingModel || "bring_your_own_license", 48),
      securityReviewStatus: enumValue(input.securityReviewStatus || "not_started", REVIEW_STATUSES, "security review status"),
      metadata: safeMetadata(input.metadata),
    })
    .returning();

  await auditGlobalScale({
    database,
    organizationId,
    userId,
    eventType: AUDIT_EVENT_TYPES.MARKETPLACE_LISTING_CREATED,
    action: "marketplace.listing.create",
    resourceType: "marketplace_listing",
    resourceId: row.id,
    requestId: auditContext?.requestId,
    metadata: { integrationId, category: row.category, status: row.status },
  });

  return row;
}

export async function createBackupJob({ database = db(), organizationId, userId, input = {}, auditContext } = {}) {
  const [row] = await database
    .insert(backupJobs)
    .values({
      organizationId,
      regionId: nullableString(input.regionId, 80),
      backupType: enumValue(input.backupType || "database", ["database", "event_archive", "configuration", "evidence_bundle"], "backup type"),
      status: enumValue(input.status || "scheduled", BACKUP_STATUSES, "backup status"),
      startedAt: optionalDate(input.startedAt),
      completedAt: optionalDate(input.completedAt),
      rpoMinutes: boundedNumber(input.rpoMinutes, 0, 525600, 1440),
      retentionDays: boundedNumber(input.retentionDays, 1, 3650, 30),
      storageLocationRef: nullableString(input.storageLocationRef, 160),
      metadata: safeMetadata(input.metadata),
    })
    .returning();

  await auditGlobalScale({
    database,
    organizationId,
    userId,
    eventType: AUDIT_EVENT_TYPES.BACKUP_JOB_RECORDED,
    action: "platform.backup.record",
    resourceType: "backup_job",
    resourceId: row.id,
    requestId: auditContext?.requestId,
    metadata: { backupType: row.backupType, status: row.status },
  });

  return row;
}

export async function createRestoreOperation({ database = db(), organizationId, userId, input = {}, auditContext } = {}) {
  const [row] = await database
    .insert(restoreOperations)
    .values({
      organizationId,
      backupJobId: nullableString(input.backupJobId, 80),
      targetRegionId: nullableString(input.targetRegionId, 80),
      status: enumValue(input.status || "requested", RESTORE_STATUSES, "restore status"),
      requestedByUserId: userId,
      approvedByUserId: nullableString(input.approvedByUserId, 80),
      startedAt: optionalDate(input.startedAt),
      completedAt: optionalDate(input.completedAt),
      validationResult: safeMetadata(input.validationResult),
      metadata: safeMetadata(input.metadata),
    })
    .returning();

  await auditGlobalScale({
    database,
    organizationId,
    userId,
    eventType: AUDIT_EVENT_TYPES.RESTORE_OPERATION_RECORDED,
    action: "platform.restore.record",
    resourceType: "restore_operation",
    resourceId: row.id,
    requestId: auditContext?.requestId,
    metadata: { status: row.status, backupJobId: row.backupJobId },
  });

  return row;
}

export async function createRecoveryEvent({ database = db(), organizationId, input = {} } = {}) {
  const [row] = await database
    .insert(recoveryEvents)
    .values({
      organizationId,
      regionId: nullableString(input.regionId, 80),
      backupJobId: nullableString(input.backupJobId, 80),
      restoreOperationId: nullableString(input.restoreOperationId, 80),
      eventType: enumValue(input.eventType || "backup_completed", RECOVERY_EVENT_TYPES, "recovery event type"),
      severity: enumValue(input.severity || "info", ["info", "low", "medium", "high", "critical"], "severity"),
      summary: safeString(input.summary || "Recovery event recorded", 4000),
      metadata: safeMetadata(input.metadata),
    })
    .returning();
  return row;
}

export function isTenantRegionAllowed({ assignment, targetRegionId } = {}) {
  if (!assignment || assignment.status !== "active" || !targetRegionId) return false;
  if (assignment.regionId === targetRegionId) return true;
  if (assignment.residencyLocked) return false;
  const failoverRegionIds = Array.isArray(assignment.failoverRegionIds) ? assignment.failoverRegionIds : [];
  return failoverRegionIds.includes(targetRegionId);
}

export function calculateHealthRollup(records = []) {
  const total = records.length;
  const byStatus = records.reduce((acc, row) => {
    acc[row.status] = (acc[row.status] || 0) + 1;
    return acc;
  }, {});
  const degraded = (byStatus.degraded || 0) + (byStatus.down || 0);
  const averageLatencyP95Ms = total
    ? Math.round(records.reduce((sum, row) => sum + Number(row.latencyP95Ms || 0), 0) / total)
    : 0;
  const averageAvailabilityPercent = total
    ? Number((records.reduce((sum, row) => sum + Number(row.availabilityPercent || 0), 0) / total).toFixed(2))
    : 100;
  return {
    total,
    byStatus,
    degraded,
    healthy: total - degraded,
    averageLatencyP95Ms,
    averageAvailabilityPercent,
  };
}

async function requireRegionExists(database, regionId) {
  const [row] = await database.select({ id: platformRegions.id }).from(platformRegions).where(eq(platformRegions.id, regionId)).limit(1);
  if (!row) throw new Error("region not found");
  return row;
}

async function scalarCount(database, table, where) {
  const query = database.select({ value: count() }).from(table);
  const [row] = await (where ? query.where(where) : query);
  return Number(row?.value || 0);
}

async function auditGlobalScale({
  database,
  organizationId,
  userId,
  eventType,
  action,
  resourceType,
  resourceId,
  requestId,
  metadata,
}) {
  await createAuditEvent({
    database,
    eventType,
    action,
    result: AUDIT_RESULTS.SUCCESS,
    severity: AUDIT_SEVERITIES.INFO,
    organizationId,
    userId,
    resourceType,
    resourceId,
    requestId,
    metadata,
  });
}

function boundedLimit(value, fallback, max) {
  const number = Number(value || fallback);
  if (!Number.isFinite(number)) return fallback;
  return Math.min(Math.max(Math.trunc(number), 1), max);
}

function boundedNumber(value, min, max, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  const number = Number(value);
  if (!Number.isFinite(number)) throw new Error("numeric value is invalid");
  return Math.min(Math.max(Math.trunc(number), min), max);
}

function boundedFloat(value, min, max, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  const number = Number(value);
  if (!Number.isFinite(number)) throw new Error("numeric value is invalid");
  return Math.min(Math.max(number, min), max);
}

function enumValue(value, allowed, label) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!allowed.includes(normalized)) throw new Error(`${label} is invalid`);
  return normalized;
}

function optionalDate(value) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error("date is invalid");
  return date;
}

function requiredString(value, label) {
  const text = safeString(value, 160);
  if (!text) throw new Error(`${label} is required`);
  return text;
}

function safeString(value, maxLength) {
  return String(value || "").replace(/[^\x20-\x7E]/g, "").trim().slice(0, maxLength);
}

function nullableString(value, maxLength) {
  const text = safeString(value, maxLength);
  return text || null;
}

function nullableHost(value) {
  const host = nullableString(value, 255);
  if (!host) return null;
  return host.replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
}

function safePath(value) {
  const path = safeString(value, 160);
  if (!path.startsWith("/")) throw new Error("health check path is invalid");
  return path;
}

function normalizeSlug(value) {
  return (
    String(value || "")
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 120) || null
  );
}

function normalizeStringArray(value, max) {
  if (!Array.isArray(value)) return [];
  return value.map((item) => safeString(item, 160)).filter(Boolean).slice(0, max);
}

function normalizeUrls(value, max) {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => safeString(item, 500))
    .filter((item) => /^https:\/\//i.test(item))
    .slice(0, max);
}

function safeMetadata(metadata) {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return {};
  return scrub(metadata);
}

function scrub(value) {
  if (Array.isArray(value)) return value.slice(0, 50).map(scrub);
  if (!value || typeof value !== "object") return value;
  const output = {};
  for (const [key, child] of Object.entries(value)) {
    if (/password|secret|token|credential|authorization|cookie|private[_-]?key|api[_-]?key/i.test(key)) continue;
    output[safeString(key, 80)] = scrub(child);
  }
  return output;
}
