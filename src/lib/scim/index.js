import "server-only";

import crypto from "node:crypto";
import { and, eq, gt, isNull, or } from "drizzle-orm";
import { db } from "../../db/client.js";
import {
  organizationMemberships,
  roles,
  scimEvents,
  scimGroupMappings,
  scimProviders,
  scimSyncJobs,
  scimTokens,
  userRoles,
  users,
} from "../../db/schema.js";
import {
  AUDIT_RESULTS,
} from "../audit/index.js";
import {
  IDENTITY_AUDIT_EVENT_TYPES,
  hashIdentityValue,
  recordIdentityAuditEvent,
  sanitizeIdentityMetadata,
} from "../identity/index.js";
import { normalizeEmail, safeString } from "../management/tokens.js";

export const SCIM_AUDIT_EVENTS = Object.freeze({
  USER_CREATED: "scim.user.created",
  USER_UPDATED: "scim.user.updated",
  USER_DEACTIVATED: "scim.user.deactivated",
  GROUP_SYNCED: "scim.group.synced",
  SYNC_STARTED: "scim.sync.started",
  SYNC_COMPLETED: "scim.sync.completed",
  SYNC_FAILED: "scim.sync.failed",
});

export const SCIM_PROVIDER_STATUSES = Object.freeze({
  ACTIVE: "active",
  DISABLED: "disabled",
  DELETED: "deleted",
});

export const SCIM_TOKEN_STATUSES = Object.freeze({
  ACTIVE: "active",
  REVOKED: "revoked",
  EXPIRED: "expired",
});

export const SCIM_SYNC_STATUSES = Object.freeze({
  QUEUED: "queued",
  RUNNING: "running",
  COMPLETED: "completed",
  FAILED: "failed",
  CANCELLED: "cancelled",
});

export const SCIM_GROUP_MAPPING_STATUSES = Object.freeze({
  PENDING: "pending",
  APPROVED: "approved",
  DISABLED: "disabled",
  DELETED: "deleted",
});

const SCIM_TOKEN_BYTES = 32;

export async function listScimProviders({ database = db(), organizationId } = {}) {
  if (!organizationId) throw new Error("organizationId is required");
  const providers = await database
    .select()
    .from(scimProviders)
    .where(and(eq(scimProviders.organizationId, organizationId), isNull(scimProviders.deletedAt)))
    .limit(50);
  return providers.map(publicScimProvider);
}

export async function createScimProvider({
  database = db(),
  organizationId,
  name = "Enterprise SCIM",
  status = SCIM_PROVIDER_STATUSES.DISABLED,
  endpointConfigurationRef = null,
  baseUrl = null,
  createdByUserId = null,
  metadata = {},
  auditContext = {},
} = {}) {
  if (!organizationId) throw new Error("organizationId is required");
  const normalizedStatus = normalizeEnum(status, Object.values(SCIM_PROVIDER_STATUSES), "scim provider status");
  const normalizedName = requiredString(name, "provider name", 160);

  const [provider] = await database
    .insert(scimProviders)
    .values({
      organizationId,
      name: normalizedName,
      status: normalizedStatus,
      endpointConfigurationRef: safeString(endpointConfigurationRef, 160),
      baseUrl: safeUrl(baseUrl),
      createdByUserId,
      metadata: sanitizeIdentityMetadata(metadata),
    })
    .onConflictDoUpdate({
      target: [scimProviders.organizationId, scimProviders.name],
      set: {
        status: normalizedStatus,
        endpointConfigurationRef: safeString(endpointConfigurationRef, 160),
        baseUrl: safeUrl(baseUrl),
        metadata: sanitizeIdentityMetadata(metadata),
        updatedAt: new Date(),
        deletedAt: null,
      },
    })
    .returning();

  await recordScimAudit({
    database,
    organizationId,
    providerId: provider.id,
    eventType: SCIM_AUDIT_EVENTS.SYNC_COMPLETED,
    result: AUDIT_RESULTS.SUCCESS,
    auditContext,
    metadata: { operation: "provider.saved", status: provider.status },
  });

  return publicScimProvider(provider);
}

export async function createScimToken({
  database = db(),
  organizationId,
  providerId,
  name = "SCIM token",
  expiresAt = null,
  createdByUserId = null,
  auditContext = {},
} = {}) {
  if (!organizationId || !providerId) throw new Error("organizationId and providerId are required");
  const [provider] = await database
    .select()
    .from(scimProviders)
    .where(
      and(
        eq(scimProviders.id, providerId),
        eq(scimProviders.organizationId, organizationId),
        isNull(scimProviders.deletedAt),
      ),
    )
    .limit(1);
  if (!provider) throw new Error("scim provider is not available");

  const plaintextToken = generateScimToken();
  const tokenHash = hashScimToken(plaintextToken);
  const [token] = await database
    .insert(scimTokens)
    .values({
      organizationId,
      providerId,
      tokenHash,
      name: safeString(name, 160) || "SCIM token",
      status: SCIM_TOKEN_STATUSES.ACTIVE,
      expiresAt,
      createdByUserId,
    })
    .returning();

  await recordScimAudit({
    database,
    organizationId,
    providerId,
    eventType: SCIM_AUDIT_EVENTS.SYNC_COMPLETED,
    result: AUDIT_RESULTS.SUCCESS,
    auditContext,
    metadata: { operation: "access_credential_created" },
  });

  return {
    token: publicScimToken(token),
    plaintextToken,
  };
}

export async function authenticateScimRequest(request, { database = db(), now = new Date() } = {}) {
  const authorization = request?.headers?.get?.("authorization") || "";
  const match = /^Bearer\s+(.+)$/i.exec(authorization);
  if (!match) return null;

  const tokenHash = hashScimToken(match[1]);
  const [token] = await database
    .select()
    .from(scimTokens)
    .where(
      and(
        eq(scimTokens.tokenHash, tokenHash),
        eq(scimTokens.status, SCIM_TOKEN_STATUSES.ACTIVE),
        or(isNull(scimTokens.expiresAt), gt(scimTokens.expiresAt, now)),
      ),
    )
    .limit(1);
  if (!token) return null;

  const [provider] = await database
    .select()
    .from(scimProviders)
    .where(
      and(
        eq(scimProviders.id, token.providerId),
        eq(scimProviders.organizationId, token.organizationId),
        eq(scimProviders.status, SCIM_PROVIDER_STATUSES.ACTIVE),
        isNull(scimProviders.deletedAt),
      ),
    )
    .limit(1);
  if (!provider) return null;

  await database
    .update(scimTokens)
    .set({ lastUsedAt: now, updatedAt: now })
    .where(eq(scimTokens.id, token.id));

  return {
    organizationId: token.organizationId,
    provider,
    token: publicScimToken(token),
  };
}

export async function listScimUsers({ database = db(), organizationId, startIndex = 1, count = 100 } = {}) {
  const limit = boundedScimCount(count);
  const rows = await database
    .select({
      membership: organizationMemberships,
      user: users,
    })
    .from(organizationMemberships)
    .innerJoin(users, eq(users.id, organizationMemberships.userId))
    .where(eq(organizationMemberships.organizationId, organizationId))
    .limit(limit);

  const resources = rows.map((row) => scimUserResource(row.user, row.membership));
  return scimListResponse({ resources, startIndex, itemsPerPage: resources.length });
}

export async function getScimUser({ database = db(), organizationId, userId } = {}) {
  const [row] = await database
    .select({
      membership: organizationMemberships,
      user: users,
    })
    .from(organizationMemberships)
    .innerJoin(users, eq(users.id, organizationMemberships.userId))
    .where(and(eq(organizationMemberships.organizationId, organizationId), eq(users.id, userId)))
    .limit(1);
  return row ? scimUserResource(row.user, row.membership) : null;
}

export async function provisionScimUser({
  database = db(),
  organizationId,
  providerId,
  payload,
  auditContext = {},
  now = new Date(),
} = {}) {
  const input = normalizeScimUserPayload(payload);
  return database.transaction(async (tx) => {
    const job = await createSyncJob({
      database: tx,
      organizationId,
      providerId,
      operationType: "user_create",
      resourceType: "User",
      resourceId: input.externalIdHash,
      now,
    });
    await recordScimAudit({ database: tx, organizationId, providerId, syncJobId: job.id, eventType: SCIM_AUDIT_EVENTS.SYNC_STARTED, result: AUDIT_RESULTS.SUCCESS, auditContext, metadata: { operationType: "user_create" } });

    const [user] = await tx
      .insert(users)
      .values({
        email: input.email,
        status: input.active ? "active" : "disabled",
        emailVerifiedAt: now,
        lastLoginAt: null,
      })
      .onConflictDoUpdate({
        target: users.email,
        set: {
          status: input.active ? "active" : "disabled",
          updatedAt: now,
        },
      })
      .returning();

    const [membership] = await tx
      .insert(organizationMemberships)
      .values({
        organizationId,
        userId: user.id,
        status: input.active ? "active" : "disabled",
      })
      .onConflictDoUpdate({
        target: [organizationMemberships.organizationId, organizationMemberships.userId],
        set: { status: input.active ? "active" : "disabled" },
      })
      .returning();

    await completeSyncJob({ database: tx, jobId: job.id, now });
    await recordScimEvent({
      database: tx,
      organizationId,
      providerId,
      syncJobId: job.id,
      userId: user.id,
      membershipId: membership.id,
      eventType: SCIM_AUDIT_EVENTS.USER_CREATED,
      result: AUDIT_RESULTS.SUCCESS,
      externalIdHash: input.externalIdHash,
      resourceType: "User",
      resourceId: user.id,
      summary: "SCIM user provisioned",
      metadata: { active: input.active },
    });
    await recordScimAudit({ database: tx, organizationId, providerId, syncJobId: job.id, userId: user.id, eventType: SCIM_AUDIT_EVENTS.USER_CREATED, result: AUDIT_RESULTS.SUCCESS, auditContext, metadata: { active: input.active } });
    await recordScimAudit({ database: tx, organizationId, providerId, syncJobId: job.id, eventType: SCIM_AUDIT_EVENTS.SYNC_COMPLETED, result: AUDIT_RESULTS.SUCCESS, auditContext, metadata: { operationType: "user_create" } });

    return scimUserResource(user, membership);
  });
}

export async function updateScimUser({
  database = db(),
  organizationId,
  providerId,
  userId,
  payload,
  auditContext = {},
  now = new Date(),
} = {}) {
  const input = normalizeScimUserPayload(payload, { partial: true });
  return database.transaction(async (tx) => {
    const current = await getScimUserRecord({ database: tx, organizationId, userId });
    if (!current) return null;
    const job = await createSyncJob({
      database: tx,
      organizationId,
      providerId,
      operationType: input.active === false ? "user_deactivate" : "user_update",
      resourceType: "User",
      resourceId: userId,
      now,
    });

    const userChanges = { updatedAt: now };
    if (input.email) userChanges.email = input.email;
    if (typeof input.active === "boolean") userChanges.status = input.active ? "active" : "disabled";

    const [user] = await tx.update(users).set(userChanges).where(eq(users.id, userId)).returning();
    const membershipStatus = input.active === false ? "disabled" : "active";
    const [membership] = await tx
      .update(organizationMemberships)
      .set({ status: membershipStatus })
      .where(and(eq(organizationMemberships.organizationId, organizationId), eq(organizationMemberships.userId, userId)))
      .returning();

    await completeSyncJob({ database: tx, jobId: job.id, now });
    const eventType = input.active === false ? SCIM_AUDIT_EVENTS.USER_DEACTIVATED : SCIM_AUDIT_EVENTS.USER_UPDATED;
    await recordScimEvent({
      database: tx,
      organizationId,
      providerId,
      syncJobId: job.id,
      userId,
      membershipId: membership?.id || current.membership.id,
      eventType,
      result: AUDIT_RESULTS.SUCCESS,
      externalIdHash: input.externalIdHash || null,
      resourceType: "User",
      resourceId: userId,
      summary: input.active === false ? "SCIM user deactivated" : "SCIM user updated",
      metadata: { active: input.active },
    });
    await recordScimAudit({ database: tx, organizationId, providerId, syncJobId: job.id, userId, eventType, result: AUDIT_RESULTS.SUCCESS, auditContext, metadata: { active: input.active } });

    return scimUserResource(user || current.user, membership || current.membership);
  });
}

export async function patchScimUser({ payload, ...context } = {}) {
  const patch = normalizeScimPatch(payload);
  return updateScimUser({ ...context, payload: patch });
}

export async function listScimGroups({ database = db(), organizationId, startIndex = 1, count = 100 } = {}) {
  const mappings = await database
    .select()
    .from(scimGroupMappings)
    .where(eq(scimGroupMappings.organizationId, organizationId))
    .limit(boundedScimCount(count));
  const resources = mappings.map(scimGroupResource);
  return scimListResponse({ resources, startIndex, itemsPerPage: resources.length });
}

export async function getScimGroup({ database = db(), organizationId, groupId } = {}) {
  const [mapping] = await database
    .select()
    .from(scimGroupMappings)
    .where(and(eq(scimGroupMappings.id, groupId), eq(scimGroupMappings.organizationId, organizationId)))
    .limit(1);
  return mapping ? scimGroupResource(mapping) : null;
}

export async function syncScimGroup({
  database = db(),
  organizationId,
  providerId,
  payload,
  auditContext = {},
  now = new Date(),
} = {}) {
  const input = normalizeScimGroupPayload(payload);
  return database.transaction(async (tx) => {
    const job = await createSyncJob({
      database: tx,
      organizationId,
      providerId,
      operationType: "group_sync",
      resourceType: "Group",
      resourceId: input.externalIdHash,
      now,
    });

    const [mapping] = await tx
      .insert(scimGroupMappings)
      .values({
        organizationId,
        providerId,
        externalGroupIdHash: input.externalIdHash,
        externalDisplayName: input.displayName,
        status: SCIM_GROUP_MAPPING_STATUSES.PENDING,
        metadata: { memberCount: input.members.length },
      })
      .onConflictDoUpdate({
        target: [scimGroupMappings.providerId, scimGroupMappings.externalGroupIdHash],
        set: {
          externalDisplayName: input.displayName,
          metadata: { memberCount: input.members.length },
          updatedAt: now,
        },
      })
      .returning();

    if (mapping.roleId && mapping.status === SCIM_GROUP_MAPPING_STATUSES.APPROVED) {
      await applyApprovedGroupRoleMapping({
        database: tx,
        organizationId,
        roleId: mapping.roleId,
        members: input.members,
      });
    }

    await completeSyncJob({ database: tx, jobId: job.id, now });
    await recordScimEvent({
      database: tx,
      organizationId,
      providerId,
      syncJobId: job.id,
      eventType: SCIM_AUDIT_EVENTS.GROUP_SYNCED,
      result: AUDIT_RESULTS.SUCCESS,
      externalIdHash: input.externalIdHash,
      resourceType: "Group",
      resourceId: mapping.id,
      summary: "SCIM group synchronized",
      metadata: { memberCount: input.members.length, mappingStatus: mapping.status },
    });
    await recordScimAudit({ database: tx, organizationId, providerId, syncJobId: job.id, eventType: SCIM_AUDIT_EVENTS.GROUP_SYNCED, result: AUDIT_RESULTS.SUCCESS, auditContext, metadata: { mappingStatus: mapping.status } });

    return scimGroupResource(mapping);
  });
}

export function scimJson(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "cache-control": "no-store",
      "content-type": "application/scim+json",
      "x-content-type-options": "nosniff",
    },
  });
}

export function scimError(detail, status = 400) {
  return scimJson(
    {
      schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
      detail,
      status: String(status),
    },
    status,
  );
}

export function generateScimToken() {
  return `scim_${crypto.randomBytes(SCIM_TOKEN_BYTES).toString("base64url")}`;
}

export function hashScimToken(token) {
  return crypto.createHmac("sha256", scimHashSecret()).update(requiredString(token, "scim token"), "utf8").digest("base64url");
}

function normalizeScimUserPayload(payload = {}, { partial = false } = {}) {
  if (!payload || typeof payload !== "object") throw new Error("SCIM user payload is required");
  const email = normalizeEmail(payload.userName || payload.emails?.[0]?.value || payload.email);
  if (!partial && !email) throw new Error("SCIM userName email is required");
  if (email && !email.includes("@")) throw new Error("SCIM userName email is invalid");
  const externalId = safeString(payload.externalId || payload.id || email, 255);
  return {
    externalId,
    externalIdHash: externalId ? hashIdentityValue(externalId) : null,
    email,
    active: payload.active !== false,
    displayName: safeString(payload.displayName || payload.name?.formatted, 160),
  };
}

function normalizeScimPatch(payload = {}) {
  const output = {};
  const operations = Array.isArray(payload.Operations) ? payload.Operations : [];
  for (const operation of operations) {
    const path = String(operation.path || "").toLowerCase();
    if (!path || path === "active") output.active = operation.value === true || operation.value === "true";
    if (!path || path === "username") output.userName = operation.value;
    if (!path || path === "displayname") output.displayName = operation.value;
  }
  return output;
}

function normalizeScimGroupPayload(payload = {}) {
  const displayName = requiredString(payload.displayName, "SCIM group displayName", 160);
  const externalId = safeString(payload.externalId || payload.id || displayName, 255);
  return {
    displayName,
    externalId,
    externalIdHash: hashIdentityValue(externalId),
    members: Array.isArray(payload.members) ? payload.members.slice(0, 500) : [],
  };
}

async function getScimUserRecord({ database, organizationId, userId } = {}) {
  const [row] = await database
    .select({
      membership: organizationMemberships,
      user: users,
    })
    .from(organizationMemberships)
    .innerJoin(users, eq(users.id, organizationMemberships.userId))
    .where(and(eq(organizationMemberships.organizationId, organizationId), eq(users.id, userId)))
    .limit(1);
  return row || null;
}

async function createSyncJob({ database, organizationId, providerId, operationType, resourceType, resourceId, now }) {
  const [job] = await database
    .insert(scimSyncJobs)
    .values({
      organizationId,
      providerId,
      operationType,
      status: SCIM_SYNC_STATUSES.RUNNING,
      startedAt: now,
      resourceType,
      resourceId,
    })
    .returning();
  return job;
}

async function completeSyncJob({ database, jobId, now }) {
  await database
    .update(scimSyncJobs)
    .set({ status: SCIM_SYNC_STATUSES.COMPLETED, completedAt: now, updatedAt: now })
    .where(eq(scimSyncJobs.id, jobId));
}

async function applyApprovedGroupRoleMapping({ database, organizationId, roleId, members }) {
  const ids = members.map((member) => safeString(member.value, 255)).filter(Boolean).slice(0, 500);
  for (const userId of ids) {
    const [membership] = await database
      .select({ id: organizationMemberships.id })
      .from(organizationMemberships)
      .where(and(eq(organizationMemberships.organizationId, organizationId), eq(organizationMemberships.userId, userId)))
      .limit(1);
    if (membership) {
      await database.insert(userRoles).values({ membershipId: membership.id, roleId }).onConflictDoNothing();
    }
  }
}

async function recordScimEvent({
  database,
  organizationId,
  providerId,
  syncJobId = null,
  userId = null,
  membershipId = null,
  eventType,
  result,
  externalIdHash = null,
  resourceType = null,
  resourceId = null,
  summary = null,
  metadata = {},
} = {}) {
  const [event] = await database
    .insert(scimEvents)
    .values({
      organizationId,
      providerId,
      syncJobId,
      userId,
      membershipId,
      eventType,
      result,
      externalIdHash,
      resourceType,
      resourceId,
      summary,
      metadata: sanitizeIdentityMetadata(metadata),
    })
    .returning();
  return event;
}

async function recordScimAudit({
  database,
  organizationId,
  providerId,
  syncJobId = null,
  userId = null,
  eventType,
  result,
  auditContext = {},
  metadata = {},
} = {}) {
  return recordIdentityAuditEvent({
    database,
    organizationId,
    userId,
    actorUserId: auditContext.userId || null,
    eventType,
    action: eventType,
    result,
    requestId: auditContext.requestId,
    ipAddress: auditContext.ipAddress,
    userAgent: auditContext.userAgent,
    metadata: {
      providerId,
      syncJobId,
      ...sanitizeIdentityMetadata(metadata),
    },
  });
}

function scimUserResource(user, membership) {
  return {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:User"],
    id: user.id,
    userName: user.email,
    active: membership?.status !== "disabled" && user.status === "active",
    emails: [{ value: user.email, primary: true }],
    meta: {
      resourceType: "User",
      created: user.createdAt,
      lastModified: user.updatedAt,
    },
  };
}

function scimGroupResource(mapping) {
  return {
    schemas: ["urn:ietf:params:scim:schemas:core:2.0:Group"],
    id: mapping.id,
    displayName: mapping.externalDisplayName,
    externalId: mapping.externalDisplayName,
    members: [],
    meta: {
      resourceType: "Group",
      created: mapping.createdAt,
      lastModified: mapping.updatedAt,
    },
  };
}

function scimListResponse({ resources, startIndex = 1, itemsPerPage = resources.length }) {
  return {
    schemas: ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
    totalResults: resources.length,
    startIndex: Number(startIndex) || 1,
    itemsPerPage,
    Resources: resources,
  };
}

function publicScimProvider(provider = {}) {
  return {
    id: provider.id,
    organizationId: provider.organizationId,
    name: provider.name,
    status: provider.status,
    endpointConfigurationRef: provider.endpointConfigurationRef || null,
    baseUrl: provider.baseUrl || null,
    lastSyncAt: provider.lastSyncAt || null,
    createdAt: provider.createdAt || null,
    updatedAt: provider.updatedAt || null,
  };
}

function publicScimToken(token = {}) {
  return {
    id: token.id,
    organizationId: token.organizationId,
    providerId: token.providerId,
    name: token.name,
    status: token.status,
    lastUsedAt: token.lastUsedAt || null,
    expiresAt: token.expiresAt || null,
    createdAt: token.createdAt || null,
  };
}

function boundedScimCount(value) {
  const count = Number(value);
  if (!Number.isFinite(count)) return 100;
  return Math.min(Math.max(Math.trunc(count), 1), 200);
}

function normalizeEnum(value, allowed, label) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!allowed.includes(normalized)) throw new Error(`${label} is invalid`);
  return normalized;
}

function safeUrl(value) {
  const text = safeString(value, 2048);
  if (!text) return null;
  const url = new URL(text);
  if (!["https:", "http:"].includes(url.protocol)) throw new Error("SCIM base url is invalid");
  return url.toString();
}

function requiredString(value, label, length = 512) {
  const text = safeString(value, length);
  if (!text) throw new Error(`${label} is required`);
  return text;
}

function scimHashSecret() {
  const secret = process.env.AUTH_API_KEY_SECRET || process.env.AUTH_SESSION_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("AUTH_API_KEY_SECRET or AUTH_SESSION_SECRET must be at least 32 characters");
  }
  return secret;
}
