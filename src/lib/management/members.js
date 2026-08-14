import "server-only";

import { and, eq, isNull, or } from "drizzle-orm";
import { db } from "../../db/client.js";
import {
  organizationInvitations,
  organizationMemberships,
  organizations,
  roles,
  userRoles,
  users,
} from "../../db/schema.js";
import {
  AUDIT_EVENT_TYPES,
  AUDIT_RESULTS,
  AUDIT_SEVERITIES,
  createAuditEvent,
} from "../audit/index.js";
import { activeOwnerCount, lockOrganizationOwnerSet } from "./organizations.js";
import { boundedLimit, generateOneTimeToken, hashOneTimeToken, normalizeEmail } from "./tokens.js";

export const INVITATION_TTL_SECONDS = 7 * 24 * 60 * 60;

export async function listMembers({ database = db(), organizationId, limit } = {}) {
  return database
    .select({
      membershipId: organizationMemberships.id,
      userId: users.id,
      email: users.email,
      status: organizationMemberships.status,
      roleId: roles.id,
      roleName: roles.name,
      createdAt: organizationMemberships.createdAt,
    })
    .from(organizationMemberships)
    .innerJoin(users, eq(users.id, organizationMemberships.userId))
    .leftJoin(userRoles, eq(userRoles.membershipId, organizationMemberships.id))
    .leftJoin(roles, eq(roles.id, userRoles.roleId))
    .where(eq(organizationMemberships.organizationId, organizationId))
    .limit(boundedLimit(limit, 100, 200));
}

export async function createInvitation({
  database = db(),
  organizationId,
  invitedByUserId,
  email,
  roleId,
  auditContext,
  now = new Date(),
} = {}) {
  const normalizedEmail = normalizeEmail(email);
  if (!organizationId || !invitedByUserId || !normalizedEmail) {
    throw new Error("organizationId, inviter, and email are required");
  }

  if (roleId) {
    await assertRoleBelongsToOrganization(database, organizationId, roleId);
  }

  const plaintextToken = generateOneTimeToken("invite");
  const tokenHash = hashOneTimeToken(plaintextToken);
  const expiresAt = new Date(now.getTime() + INVITATION_TTL_SECONDS * 1000);

  const [invitation] = await database
    .insert(organizationInvitations)
    .values({
      organizationId,
      email: normalizedEmail,
      invitedByUserId,
      roleId: roleId || null,
      tokenHash,
      status: "pending",
      expiresAt,
    })
    .returning();

  await createAuditEvent({
    database,
    eventType: AUDIT_EVENT_TYPES.MEMBER_INVITED,
    action: AUDIT_EVENT_TYPES.MEMBER_INVITED,
    result: AUDIT_RESULTS.SUCCESS,
    severity: AUDIT_SEVERITIES.INFO,
    organizationId,
    userId: invitedByUserId,
    resourceType: "organization_invitation",
    resourceId: invitation.id,
    requestId: auditContext?.requestId,
    ipAddress: auditContext?.ipAddress,
    userAgent: auditContext?.userAgent,
    metadata: { email: normalizedEmail, roleId: roleId || null, expiresAt: expiresAt.toISOString() },
  });

  return { invitation: publicInvitation(invitation), plaintextToken };
}

export async function listInvitations({ database = db(), organizationId, limit } = {}) {
  const rows = await database
    .select()
    .from(organizationInvitations)
    .where(eq(organizationInvitations.organizationId, organizationId))
    .limit(boundedLimit(limit, 100, 200));

  return rows.map(publicInvitation);
}

export async function revokeInvitation({
  database = db(),
  organizationId,
  invitationId,
  auditContext,
  now = new Date(),
} = {}) {
  const [revoked] = await database
    .update(organizationInvitations)
    .set({ status: "revoked", revokedAt: now })
    .where(
      and(
        eq(organizationInvitations.id, invitationId),
        eq(organizationInvitations.organizationId, organizationId),
        eq(organizationInvitations.status, "pending"),
      ),
    )
    .returning();

  if (revoked) {
    await createAuditEvent({
      database,
      eventType: AUDIT_EVENT_TYPES.INVITATION_REVOKED,
      action: AUDIT_EVENT_TYPES.INVITATION_REVOKED,
      result: AUDIT_RESULTS.SUCCESS,
      severity: AUDIT_SEVERITIES.INFO,
      organizationId,
      userId: auditContext?.userId,
      resourceType: "organization_invitation",
      resourceId: invitationId,
      requestId: auditContext?.requestId,
      ipAddress: auditContext?.ipAddress,
      userAgent: auditContext?.userAgent,
      metadata: { email: revoked.email },
    });
  }

  return revoked ? publicInvitation(revoked) : null;
}

export async function acceptInvitation({
  database = db(),
  plaintextToken,
  userId,
  auditContext,
  now = new Date(),
} = {}) {
  const tokenHash = hashOneTimeToken(plaintextToken);
  return database.transaction(async (tx) => {
    const [user] = await tx
      .select({ email: users.email })
      .from(users)
      .where(eq(users.id, userId))
      .limit(1);

    const [invitation] = await tx
      .select()
      .from(organizationInvitations)
      .where(and(eq(organizationInvitations.tokenHash, tokenHash), eq(organizationInvitations.status, "pending")))
      .limit(1);

    if (!invitation || new Date(invitation.expiresAt).getTime() <= now.getTime()) {
      return null;
    }

    if (!user || normalizeEmail(user.email) !== invitation.email) {
      return null;
    }

    const [accepted] = await tx
      .update(organizationInvitations)
      .set({ status: "accepted", acceptedAt: now })
      .where(and(eq(organizationInvitations.id, invitation.id), eq(organizationInvitations.status, "pending")))
      .returning();

    if (!accepted) {
      return null;
    }

    const [membership] = await tx
      .insert(organizationMemberships)
      .values({ organizationId: invitation.organizationId, userId, status: "active" })
      .onConflictDoUpdate({
        target: [organizationMemberships.organizationId, organizationMemberships.userId],
        set: { status: "active" },
      })
      .returning();

    if (invitation.roleId) {
      await tx
        .insert(userRoles)
        .values({ membershipId: membership.id, roleId: invitation.roleId })
        .onConflictDoNothing();
    }

    await createAuditEvent({
      database: tx,
      eventType: AUDIT_EVENT_TYPES.MEMBER_JOINED,
      action: AUDIT_EVENT_TYPES.MEMBER_JOINED,
      result: AUDIT_RESULTS.SUCCESS,
      severity: AUDIT_SEVERITIES.INFO,
      organizationId: invitation.organizationId,
      userId,
      resourceType: "organization_membership",
      resourceId: membership.id,
      requestId: auditContext?.requestId,
      ipAddress: auditContext?.ipAddress,
      userAgent: auditContext?.userAgent,
      metadata: { invitationId: invitation.id },
    });

    return { invitation: publicInvitation(accepted), membership };
  });
}

export async function updateMembershipStatus({
  database = db(),
  organizationId,
  membershipId,
  status,
  auditContext,
  now = new Date(),
} = {}) {
  if (!["active", "disabled"].includes(status)) {
    throw new Error("membership status is invalid");
  }

  const updated = await database.transaction(async (tx) => {
    const [membership] = await tx
      .select({ id: organizationMemberships.id })
      .from(organizationMemberships)
      .where(
        and(
          eq(organizationMemberships.id, membershipId),
          eq(organizationMemberships.organizationId, organizationId),
        ),
      )
      .limit(1);
    if (!membership) {
      return null;
    }

    if (status === "disabled") {
      await lockOrganizationOwnerSet(tx, organizationId);
      if (await isLastOwner(tx, organizationId, membershipId)) {
        throw new Error("last owner cannot be disabled");
      }
    }

    const [changed] = await tx
      .update(organizationMemberships)
      .set({ status })
      .where(
        and(
          eq(organizationMemberships.id, membershipId),
          eq(organizationMemberships.organizationId, organizationId),
        ),
      )
      .returning();

    return changed || null;
  });

  if (updated) {
    const eventType =
      status === "active"
        ? AUDIT_EVENT_TYPES.MEMBER_REACTIVATED
        : AUDIT_EVENT_TYPES.MEMBER_DISABLED;
    await createAuditEvent({
      database,
      eventType,
      action: eventType,
      result: AUDIT_RESULTS.SUCCESS,
      severity: AUDIT_SEVERITIES.INFO,
      organizationId,
      userId: auditContext?.userId,
      resourceType: "organization_membership",
      resourceId: membershipId,
      requestId: auditContext?.requestId,
      ipAddress: auditContext?.ipAddress,
      userAgent: auditContext?.userAgent,
      metadata: { status },
    });
  }

  return updated || null;
}

export async function assignMembershipRole({
  database = db(),
  organizationId,
  membershipId,
  roleId,
  auditContext,
} = {}) {
  await assertRoleBelongsToOrganization(database, organizationId, roleId);

  const [membership] = await database
    .select()
    .from(organizationMemberships)
    .where(
      and(
        eq(organizationMemberships.id, membershipId),
        eq(organizationMemberships.organizationId, organizationId),
      ),
    )
    .limit(1);
  if (!membership) {
    return null;
  }

  await database.insert(userRoles).values({ membershipId, roleId }).onConflictDoNothing();
  await createAuditEvent({
    database,
    eventType: AUDIT_EVENT_TYPES.MEMBER_ROLE_CHANGED,
    action: AUDIT_EVENT_TYPES.MEMBER_ROLE_CHANGED,
    result: AUDIT_RESULTS.SUCCESS,
    severity: AUDIT_SEVERITIES.INFO,
    organizationId,
    userId: auditContext?.userId,
    resourceType: "organization_membership",
    resourceId: membershipId,
    requestId: auditContext?.requestId,
    ipAddress: auditContext?.ipAddress,
    userAgent: auditContext?.userAgent,
    metadata: { roleId, operation: "assigned" },
  });

  return { membershipId, roleId };
}

export async function removeMembershipRole({
  database = db(),
  organizationId,
  membershipId,
  roleId,
  auditContext,
} = {}) {
  const removed = await database.transaction(async (tx) => {
    const [membership] = await tx
      .select({ id: organizationMemberships.id })
      .from(organizationMemberships)
      .where(
        and(
          eq(organizationMemberships.id, membershipId),
          eq(organizationMemberships.organizationId, organizationId),
        ),
      )
      .limit(1);
    if (!membership) {
      return null;
    }

    const [role] = await tx.select().from(roles).where(eq(roles.id, roleId)).limit(1);
    if (role?.name === "Owner") {
      await lockOrganizationOwnerSet(tx, organizationId);
      if (await isLastOwner(tx, organizationId, membershipId)) {
        throw new Error("last owner role cannot be removed");
      }
    }

    await tx
      .delete(userRoles)
      .where(and(eq(userRoles.membershipId, membershipId), eq(userRoles.roleId, roleId)));

    return { membershipId, roleId };
  });

  if (!removed) {
    return null;
  }

  await createAuditEvent({
    database,
    eventType: AUDIT_EVENT_TYPES.MEMBER_ROLE_CHANGED,
    action: AUDIT_EVENT_TYPES.MEMBER_ROLE_CHANGED,
    result: AUDIT_RESULTS.SUCCESS,
    severity: AUDIT_SEVERITIES.INFO,
    organizationId,
    userId: auditContext?.userId,
    resourceType: "organization_membership",
    resourceId: membershipId,
    requestId: auditContext?.requestId,
    ipAddress: auditContext?.ipAddress,
    userAgent: auditContext?.userAgent,
    metadata: { roleId, operation: "removed" },
  });

  return { membershipId, roleId };
}

export function publicInvitation(invitation) {
  if (!invitation) return null;
  const { tokenHash, ...safeInvitation } = invitation;
  return safeInvitation;
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

async function isLastOwner(database, organizationId, membershipId) {
  return (await activeOwnerCount(database, organizationId, membershipId)) === 0;
}
