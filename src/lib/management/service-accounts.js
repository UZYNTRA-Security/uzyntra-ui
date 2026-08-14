import "server-only";

import { and, eq, isNull, or } from "drizzle-orm";
import { db } from "../../db/client.js";
import { roles, serviceAccountRoles, serviceAccounts } from "../../db/schema.js";
import {
  AUDIT_EVENT_TYPES,
  AUDIT_RESULTS,
  AUDIT_SEVERITIES,
  createAuditEvent,
} from "../audit/index.js";
import { boundedLimit, safeString } from "./tokens.js";

export async function listServiceAccounts({ database = db(), organizationId, limit } = {}) {
  return database
    .select({
      id: serviceAccounts.id,
      organizationId: serviceAccounts.organizationId,
      name: serviceAccounts.name,
      status: serviceAccounts.status,
      createdAt: serviceAccounts.createdAt,
      deletedAt: serviceAccounts.deletedAt,
      roleId: roles.id,
      roleName: roles.name,
    })
    .from(serviceAccounts)
    .leftJoin(serviceAccountRoles, eq(serviceAccountRoles.serviceAccountId, serviceAccounts.id))
    .leftJoin(roles, eq(roles.id, serviceAccountRoles.roleId))
    .where(and(eq(serviceAccounts.organizationId, organizationId), isNull(serviceAccounts.deletedAt)))
    .limit(boundedLimit(limit, 100, 200));
}

export async function createServiceAccount({
  database = db(),
  organizationId,
  name,
  roleId,
  auditContext,
} = {}) {
  const accountName = safeString(name, 160);
  if (!organizationId || !accountName) {
    throw new Error("organizationId and service account name are required");
  }

  const created = await database.transaction(async (tx) => {
    const [serviceAccount] = await tx
      .insert(serviceAccounts)
      .values({ organizationId, name: accountName, status: "active" })
      .returning();

    if (roleId) {
      await assertRoleBelongsToOrganization(tx, organizationId, roleId);
      await tx
        .insert(serviceAccountRoles)
        .values({ serviceAccountId: serviceAccount.id, roleId })
        .onConflictDoNothing();
    }

    await recordServiceAccountAudit(
      tx,
      AUDIT_EVENT_TYPES.SERVICE_ACCOUNT_CREATED,
      serviceAccount,
      auditContext,
      { roleId: roleId || null },
    );

    return serviceAccount;
  });

  return created;
}

export async function updateServiceAccountStatus({
  database = db(),
  organizationId,
  serviceAccountId,
  status,
  auditContext,
} = {}) {
  if (!["active", "disabled"].includes(status)) {
    throw new Error("service account status is invalid");
  }

  const [updated] = await database
    .update(serviceAccounts)
    .set({ status })
    .where(
      and(
        eq(serviceAccounts.id, serviceAccountId),
        eq(serviceAccounts.organizationId, organizationId),
        isNull(serviceAccounts.deletedAt),
      ),
    )
    .returning();

  if (updated) {
    await recordServiceAccountAudit(
      database,
      status === "active"
        ? AUDIT_EVENT_TYPES.SERVICE_ACCOUNT_REACTIVATED
        : AUDIT_EVENT_TYPES.SERVICE_ACCOUNT_DISABLED,
      updated,
      auditContext,
    );
  }

  return updated || null;
}

export async function softDeleteServiceAccount({
  database = db(),
  organizationId,
  serviceAccountId,
  auditContext,
  now = new Date(),
} = {}) {
  const [updated] = await database
    .update(serviceAccounts)
    .set({ status: "deleted", deletedAt: now })
    .where(
      and(
        eq(serviceAccounts.id, serviceAccountId),
        eq(serviceAccounts.organizationId, organizationId),
        isNull(serviceAccounts.deletedAt),
      ),
    )
    .returning();

  if (updated) {
    await recordServiceAccountAudit(
      database,
      AUDIT_EVENT_TYPES.SERVICE_ACCOUNT_DELETED,
      updated,
      auditContext,
    );
  }

  return updated || null;
}

async function recordServiceAccountAudit(database, eventType, serviceAccount, auditContext, metadata = {}) {
  await createAuditEvent({
    database,
    eventType,
    action: eventType,
    result: AUDIT_RESULTS.SUCCESS,
    severity: AUDIT_SEVERITIES.INFO,
    organizationId: serviceAccount.organizationId,
    serviceAccountId: serviceAccount.id,
    userId: auditContext?.userId,
    resourceType: "service_account",
    resourceId: serviceAccount.id,
    requestId: auditContext?.requestId,
    ipAddress: auditContext?.ipAddress,
    userAgent: auditContext?.userAgent,
    metadata,
  });
}

async function assertRoleBelongsToOrganization(database, organizationId, roleId) {
  const [role] = await database
    .select({ id: roles.id })
    .from(roles)
    .where(and(eq(roles.id, roleId), or(isNull(roles.organizationId), eq(roles.organizationId, organizationId))))
    .limit(1);
  if (!role) {
    throw new Error("role is not available in this organization");
  }
}
