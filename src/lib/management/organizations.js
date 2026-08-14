import "server-only";

import { and, count, eq, isNull, ne, or, sql } from "drizzle-orm";
import { db } from "../../db/client.js";
import {
  organizationMemberships,
  organizationSettings,
  organizations,
  permissions,
  rolePermissions,
  roles,
  userRoles,
} from "../../db/schema.js";
import {
  AUDIT_EVENT_TYPES,
  AUDIT_RESULTS,
  AUDIT_SEVERITIES,
  createAuditEvent,
} from "../audit/index.js";
import { updateSessionOrganization } from "../auth/session.js";
import { boundedLimit, safeString } from "./tokens.js";

export async function listOrganizationsForUser({ database = db(), userId } = {}) {
  if (!userId) {
    throw new Error("userId is required");
  }

  return database
    .select({
      id: organizations.id,
      name: organizations.name,
      slug: organizations.slug,
      status: organizations.status,
      membershipId: organizationMemberships.id,
      membershipStatus: organizationMemberships.status,
    })
    .from(organizationMemberships)
    .innerJoin(organizations, eq(organizations.id, organizationMemberships.organizationId))
    .where(
      and(
        eq(organizationMemberships.userId, userId),
        eq(organizationMemberships.status, "active"),
        eq(organizations.status, "active"),
        isNull(organizations.deletedAt),
      ),
    )
    .limit(100);
}

export async function createOrganizationForUser({
  database = db(),
  userId,
  name,
  slug,
  auditContext,
} = {}) {
  if (!userId) {
    throw new Error("userId is required");
  }

  const orgName = safeString(name, 255);
  const orgSlug = normalizeSlug(slug || name);
  if (!orgName || !orgSlug) {
    throw new Error("organization name and slug are required");
  }

  const created = await database.transaction(async (tx) => {
    const [organization] = await tx
      .insert(organizations)
      .values({ name: orgName, slug: orgSlug })
      .returning();

    await tx.insert(organizationSettings).values({ organizationId: organization.id });

    const [membership] = await tx
      .insert(organizationMemberships)
      .values({ organizationId: organization.id, userId, status: "active" })
      .returning();

    const ownerRole = await ensureOwnerRole(tx, organization.id);
    await tx
      .insert(userRoles)
      .values({ membershipId: membership.id, roleId: ownerRole.id })
      .onConflictDoNothing();

    await createAuditEvent({
      database: tx,
      eventType: AUDIT_EVENT_TYPES.ORGANIZATION_CREATED,
      action: AUDIT_EVENT_TYPES.ORGANIZATION_CREATED,
      result: AUDIT_RESULTS.SUCCESS,
      severity: AUDIT_SEVERITIES.INFO,
      organizationId: organization.id,
      userId,
      resourceType: "organization",
      resourceId: organization.id,
      requestId: auditContext?.requestId,
      ipAddress: auditContext?.ipAddress,
      userAgent: auditContext?.userAgent,
      metadata: { slug: organization.slug },
    });

    return { organization, membership, ownerRole };
  });

  return created;
}

export async function updateOrganization({
  database = db(),
  organizationId,
  name,
  slug,
  auditContext,
} = {}) {
  const changes = {};
  const orgName = safeString(name, 255);
  const orgSlug = slug ? normalizeSlug(slug) : null;
  if (orgName) changes.name = orgName;
  if (orgSlug) changes.slug = orgSlug;
  if (Object.keys(changes).length === 0) {
    throw new Error("no organization changes provided");
  }

  const [updated] = await database
    .update(organizations)
    .set({ ...changes, updatedAt: new Date() })
    .where(and(eq(organizations.id, organizationId), isNull(organizations.deletedAt)))
    .returning();

  if (updated) {
    await createAuditEvent({
      database,
      eventType: AUDIT_EVENT_TYPES.ORGANIZATION_UPDATED,
      action: AUDIT_EVENT_TYPES.ORGANIZATION_UPDATED,
      result: AUDIT_RESULTS.SUCCESS,
      severity: AUDIT_SEVERITIES.INFO,
      organizationId,
      userId: auditContext?.userId,
      resourceType: "organization",
      resourceId: organizationId,
      requestId: auditContext?.requestId,
      ipAddress: auditContext?.ipAddress,
      userAgent: auditContext?.userAgent,
      metadata: changes,
    });
  }

  return updated || null;
}

export async function switchActiveOrganization({
  database = db(),
  userId,
  sessionId,
  organizationId,
  auditContext,
} = {}) {
  const [membership] = await database
    .select({ id: organizationMemberships.id })
    .from(organizationMemberships)
    .innerJoin(organizations, eq(organizations.id, organizationMemberships.organizationId))
    .where(
      and(
        eq(organizationMemberships.userId, userId),
        eq(organizationMemberships.organizationId, organizationId),
        eq(organizationMemberships.status, "active"),
        eq(organizations.status, "active"),
        isNull(organizations.deletedAt),
      ),
    )
    .limit(1);

  if (!membership) {
    return null;
  }

  const session = await updateSessionOrganization({ database, sessionId, organizationId });
  if (session) {
    await createAuditEvent({
      database,
      eventType: AUDIT_EVENT_TYPES.ORGANIZATION_SWITCHED,
      action: AUDIT_EVENT_TYPES.ORGANIZATION_SWITCHED,
      result: AUDIT_RESULTS.SUCCESS,
      severity: AUDIT_SEVERITIES.INFO,
      organizationId,
      userId,
      resourceType: "organization",
      resourceId: organizationId,
      requestId: auditContext?.requestId,
      ipAddress: auditContext?.ipAddress,
      userAgent: auditContext?.userAgent,
    });
  }

  return session;
}

export async function listOrganizationSettings({ database = db(), organizationId } = {}) {
  const [settings] = await database
    .select()
    .from(organizationSettings)
    .where(eq(organizationSettings.organizationId, organizationId))
    .limit(1);

  return settings || null;
}

export async function updateOrganizationSettings({
  database = db(),
  organizationId,
  mfaRequired,
  sessionTimeoutSeconds,
  allowedEmailDomains,
  securityLevel,
  auditContext,
} = {}) {
  const changes = {};
  if (typeof mfaRequired === "boolean") changes.mfaRequired = mfaRequired;
  if (sessionTimeoutSeconds !== undefined) {
    const seconds = Number(sessionTimeoutSeconds);
    if (!Number.isFinite(seconds) || seconds < 300 || seconds > 2_592_000) {
      throw new Error("session timeout is invalid");
    }
    changes.sessionTimeoutSeconds = Math.trunc(seconds);
  }
  if (allowedEmailDomains !== undefined) {
    changes.allowedEmailDomains = normalizeDomains(allowedEmailDomains);
  }
  if (securityLevel !== undefined) {
    const normalized = safeString(securityLevel, 32);
    if (!["standard", "strict", "enterprise"].includes(normalized)) {
      throw new Error("security level is invalid");
    }
    changes.securityLevel = normalized;
  }

  if (Object.keys(changes).length === 0) {
    throw new Error("no settings changes provided");
  }

  const [updated] = await database
    .update(organizationSettings)
    .set({ ...changes, updatedAt: new Date() })
    .where(eq(organizationSettings.organizationId, organizationId))
    .returning();

  if (updated) {
    await createAuditEvent({
      database,
      eventType: AUDIT_EVENT_TYPES.ORGANIZATION_SETTINGS_UPDATED,
      action: AUDIT_EVENT_TYPES.ORGANIZATION_SETTINGS_UPDATED,
      result: AUDIT_RESULTS.SUCCESS,
      severity: AUDIT_SEVERITIES.INFO,
      organizationId,
      userId: auditContext?.userId,
      resourceType: "organization_settings",
      resourceId: updated.id,
      requestId: auditContext?.requestId,
      ipAddress: auditContext?.ipAddress,
      userAgent: auditContext?.userAgent,
      metadata: changes,
    });
  }

  return updated || null;
}

export async function activeOwnerCount(database, organizationId, excludeMembershipId) {
  const predicates = [
    eq(organizationMemberships.organizationId, organizationId),
    eq(organizationMemberships.status, "active"),
    eq(roles.name, "Owner"),
  ];
  if (excludeMembershipId) {
    predicates.push(ne(organizationMemberships.id, excludeMembershipId));
  }

  const [row] = await database
    .select({ value: count() })
    .from(organizationMemberships)
    .innerJoin(userRoles, eq(userRoles.membershipId, organizationMemberships.id))
    .innerJoin(roles, eq(roles.id, userRoles.roleId))
    .where(and(...predicates));

  return Number(row?.value || 0);
}

export async function lockOrganizationOwnerSet(database, organizationId) {
  if (!database?.execute) {
    return;
  }

  await database.execute(sql`select pg_advisory_xact_lock(hashtext(${organizationId}))`);
}

export async function ensureOwnerRole(database, organizationId) {
  const [existing] = await database
    .select()
    .from(roles)
    .where(and(eq(roles.organizationId, organizationId), eq(roles.name, "Owner")))
    .limit(1);
  if (existing) {
    return existing;
  }

  const [created] = await database
    .insert(roles)
    .values({
      organizationId,
      name: "Owner",
      description: "Full organization control",
    })
    .returning();

  const permissionRows = await database.select().from(permissions).limit(200);
  if (permissionRows.length > 0) {
    await database
      .insert(rolePermissions)
      .values(permissionRows.map((permission) => ({ roleId: created.id, permissionId: permission.id })))
      .onConflictDoNothing();
  }

  return created;
}

export async function listRoles({ database = db(), organizationId, limit } = {}) {
  return database
    .select({
      id: roles.id,
      organizationId: roles.organizationId,
      name: roles.name,
      description: roles.description,
    })
    .from(roles)
    .where(or(isNull(roles.organizationId), eq(roles.organizationId, organizationId)))
    .limit(boundedLimit(limit, 100, 200));
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

function normalizeDomains(value) {
  const domains = Array.isArray(value)
    ? value
    : String(value || "")
        .split(",")
        .map((item) => item.trim());

  return [...new Set(domains.map((domain) => domain.toLowerCase()).filter(isDomain))].slice(0, 50);
}

function isDomain(value) {
  return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value);
}
