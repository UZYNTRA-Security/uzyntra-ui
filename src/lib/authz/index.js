import "server-only";

import { and, eq, isNull, or } from "drizzle-orm";
import { db } from "../../db/client.js";
import {
  firewallInstanceRoleAssignments,
  firewallInstances,
  organizationMemberships,
  organizations,
  permissions,
  rolePermissions,
  roles,
  userRoles,
  users,
} from "../../db/schema.js";

export async function getAuthorizationContext({ database = db(), userId, organizationId } = {}) {
  if (!userId || !organizationId) {
    throw new Error("userId and organizationId are required");
  }

  const rows = await database
    .select({
      userId: users.id,
      userStatus: users.status,
      userDeletedAt: users.deletedAt,
      organizationId: organizations.id,
      organizationStatus: organizations.status,
      organizationDeletedAt: organizations.deletedAt,
      membershipId: organizationMemberships.id,
      membershipStatus: organizationMemberships.status,
      roleId: roles.id,
      roleName: roles.name,
      roleOrganizationId: roles.organizationId,
      permissionKey: permissions.key,
    })
    .from(users)
    .innerJoin(
      organizationMemberships,
      and(
        eq(organizationMemberships.userId, users.id),
        eq(organizationMemberships.organizationId, organizationId),
      ),
    )
    .innerJoin(organizations, eq(organizations.id, organizationMemberships.organizationId))
    .leftJoin(userRoles, eq(userRoles.membershipId, organizationMemberships.id))
    .leftJoin(
      roles,
      and(
        eq(roles.id, userRoles.roleId),
        or(isNull(roles.organizationId), eq(roles.organizationId, organizationId)),
      ),
    )
    .leftJoin(rolePermissions, eq(rolePermissions.roleId, roles.id))
    .leftJoin(permissions, eq(permissions.id, rolePermissions.permissionId))
    .where(eq(users.id, userId));

  return buildAuthorizationContext(rows);
}

export async function getFirewallAuthorizationContext({
  database = db(),
  userId,
  organizationId,
  firewallInstanceId,
} = {}) {
  if (!userId || !organizationId || !firewallInstanceId) {
    throw new Error("userId, organizationId, and firewallInstanceId are required");
  }

  const rows = await database
    .select({
      userId: users.id,
      userStatus: users.status,
      userDeletedAt: users.deletedAt,
      organizationId: organizations.id,
      organizationStatus: organizations.status,
      organizationDeletedAt: organizations.deletedAt,
      membershipId: organizationMemberships.id,
      membershipStatus: organizationMemberships.status,
      firewallInstanceId: firewallInstances.id,
      firewallInstanceStatus: firewallInstances.status,
      firewallInstanceDeletedAt: firewallInstances.deletedAt,
      roleId: roles.id,
      roleName: roles.name,
      roleOrganizationId: roles.organizationId,
      permissionKey: permissions.key,
    })
    .from(users)
    .innerJoin(
      organizationMemberships,
      and(
        eq(organizationMemberships.userId, users.id),
        eq(organizationMemberships.organizationId, organizationId),
      ),
    )
    .innerJoin(organizations, eq(organizations.id, organizationMemberships.organizationId))
    .innerJoin(
      firewallInstances,
      and(
        eq(firewallInstances.id, firewallInstanceId),
        eq(firewallInstances.organizationId, organizations.id),
      ),
    )
    .leftJoin(
      firewallInstanceRoleAssignments,
      and(
        eq(firewallInstanceRoleAssignments.membershipId, organizationMemberships.id),
        eq(firewallInstanceRoleAssignments.firewallInstanceId, firewallInstances.id),
      ),
    )
    .leftJoin(
      roles,
      and(
        eq(roles.id, firewallInstanceRoleAssignments.roleId),
        or(isNull(roles.organizationId), eq(roles.organizationId, organizationId)),
      ),
    )
    .leftJoin(rolePermissions, eq(rolePermissions.roleId, roles.id))
    .leftJoin(permissions, eq(permissions.id, rolePermissions.permissionId))
    .where(eq(users.id, userId));

  return buildFirewallAuthorizationContext(rows);
}

export function buildAuthorizationContext(rows) {
  if (!Array.isArray(rows) || rows.length === 0) {
    return null;
  }

  const base = rows[0];
  if (!isActiveAuthorizationSubject(base)) {
    return null;
  }

  const roleMap = new Map();
  const permissionSet = new Set();

  rows.forEach((row) => {
    if (row.roleId) {
      roleMap.set(row.roleId, {
        id: row.roleId,
        name: row.roleName,
        organizationId: row.roleOrganizationId || null,
      });
    }

    if (row.permissionKey) {
      permissionSet.add(row.permissionKey);
    }
  });

  return {
    userId: base.userId,
    organizationId: base.organizationId,
    membershipId: base.membershipId,
    roles: [...roleMap.values()],
    permissions: [...permissionSet].sort(),
  };
}

export function buildFirewallAuthorizationContext(rows) {
  if (!Array.isArray(rows) || rows.length === 0) {
    return null;
  }

  const base = rows[0];
  if (!isActiveAuthorizationSubject(base) || !isActiveFirewallSubject(base)) {
    return null;
  }

  const roleMap = new Map();
  const permissionSet = new Set();

  rows.forEach((row) => {
    if (row.roleId) {
      roleMap.set(row.roleId, {
        id: row.roleId,
        name: row.roleName,
        organizationId: row.roleOrganizationId || null,
      });
    }

    if (row.permissionKey) {
      permissionSet.add(row.permissionKey);
    }
  });

  return {
    userId: base.userId,
    organizationId: base.organizationId,
    membershipId: base.membershipId,
    firewallInstanceId: base.firewallInstanceId,
    roles: [...roleMap.values()],
    permissions: [...permissionSet].sort(),
  };
}

export function hasPermission(context, permission) {
  if (!context || typeof permission !== "string" || !permission) {
    return false;
  }

  return new Set(context.permissions || []).has(permission);
}

export function hasAnyPermission(context, requiredPermissions) {
  const permissionsToCheck = normalizePermissionList(requiredPermissions);
  if (permissionsToCheck.length === 0) {
    return false;
  }

  return permissionsToCheck.some((permission) => hasPermission(context, permission));
}

export function hasAllPermissions(context, requiredPermissions) {
  const permissionsToCheck = normalizePermissionList(requiredPermissions);
  if (permissionsToCheck.length === 0) {
    return false;
  }

  return permissionsToCheck.every((permission) => hasPermission(context, permission));
}

export function hasFirewallPermission(context, firewallInstanceId, permission) {
  if (!context || context.firewallInstanceId !== firewallInstanceId) {
    return false;
  }

  return hasPermission(context, permission);
}

export function recordAuthorizationDecision({
  result,
  userId,
  organizationId,
  route,
  method,
  permission,
  requestId,
}) {
  console.info(
    JSON.stringify({
      source: "uzyntra-bff-authz",
      result,
      userId: userId || null,
      organizationId: organizationId || null,
      route: route || null,
      method: method || null,
      permission: permission || null,
      requestId: requestId || null,
      timestamp: new Date().toISOString(),
    }),
  );
}

function isActiveAuthorizationSubject(row) {
  return (
    row.userStatus === "active" &&
    !row.userDeletedAt &&
    row.organizationStatus === "active" &&
    !row.organizationDeletedAt &&
    row.membershipStatus === "active"
  );
}

function isActiveFirewallSubject(row) {
  return (
    row.firewallInstanceId &&
    row.firewallInstanceStatus === "active" &&
    !row.firewallInstanceDeletedAt
  );
}

function normalizePermissionList(requiredPermissions) {
  if (typeof requiredPermissions === "string") {
    return [requiredPermissions];
  }

  if (!Array.isArray(requiredPermissions)) {
    return [];
  }

  return requiredPermissions.filter((permission) => typeof permission === "string" && permission);
}
