import assert from "node:assert/strict";
import {
  buildAuthorizationContext,
  buildFirewallAuthorizationContext,
  hasAllPermissions,
  hasAnyPermission,
  hasFirewallPermission,
  hasPermission,
} from "../src/lib/authz/index.js";
import { requiredPermissionForAdminRoute } from "../src/lib/authz/routes.js";
import { PERMISSIONS } from "../src/lib/rbac/catalog.js";

const activeBase = {
  userId: "user-1",
  userStatus: "active",
  userDeletedAt: null,
  organizationId: "org-1",
  organizationStatus: "active",
  organizationDeletedAt: null,
  membershipId: "membership-1",
  membershipStatus: "active",
};

const owner = buildAuthorizationContext([
  authzRow("role-owner", "Owner", null, PERMISSIONS.POLICY_UPDATE),
  authzRow("role-owner", "Owner", null, PERMISSIONS.EVENTS_READ),
]);
assert.equal(hasPermission(owner, PERMISSIONS.POLICY_UPDATE), true);
assert.equal(hasAllPermissions(owner, [PERMISSIONS.POLICY_UPDATE, PERMISSIONS.EVENTS_READ]), true);

const viewer = buildAuthorizationContext([
  authzRow("role-viewer", "Viewer", null, PERMISSIONS.EVENTS_READ),
  authzRow("role-viewer", "Viewer", null, PERMISSIONS.METRICS_READ),
]);
assert.equal(hasPermission(viewer, PERMISSIONS.POLICY_UPDATE), false);
assert.equal(hasAnyPermission(viewer, [PERMISSIONS.POLICY_UPDATE, PERMISSIONS.METRICS_READ]), true);

const multiRole = buildAuthorizationContext([
  authzRow("role-viewer", "Viewer", null, PERMISSIONS.EVENTS_READ),
  authzRow("role-analyst", "Analyst", null, PERMISSIONS.AUDITS_READ),
  authzRow("role-analyst", "Analyst", null, PERMISSIONS.REPUTATION_READ),
]);
assert.deepEqual(
  multiRole.permissions,
  [PERMISSIONS.AUDITS_READ, PERMISSIONS.EVENTS_READ, PERMISSIONS.REPUTATION_READ].sort(),
);
assert.equal(multiRole.roles.length, 2);

const disabledUser = buildAuthorizationContext([
  { ...authzRow("role-owner", "Owner", null, PERMISSIONS.POLICY_UPDATE), userStatus: "disabled" },
]);
assert.equal(disabledUser, null);

assert.equal(requiredPermissionForAdminRoute("GET", "metrics"), PERMISSIONS.METRICS_READ);
assert.equal(requiredPermissionForAdminRoute("GET", "events/recent"), PERMISSIONS.EVENTS_READ);
assert.equal(requiredPermissionForAdminRoute("POST", "policy/rules/set"), PERMISSIONS.POLICY_UPDATE);
assert.equal(requiredPermissionForAdminRoute("GET", "policy/export"), PERMISSIONS.POLICY_READ);
assert.equal(requiredPermissionForAdminRoute("POST", "policy/import"), PERMISSIONS.POLICY_UPDATE);
assert.equal(
  requiredPermissionForAdminRoute("POST", "policy/bundles/restore"),
  PERMISSIONS.POLICY_UPDATE,
);
assert.equal(
  requiredPermissionForAdminRoute("POST", "mitigations/unblock/127.0.0.1"),
  PERMISSIONS.MITIGATION_DELETE,
);
assert.equal(requiredPermissionForAdminRoute("GET", "unsupported"), null);

const securityAdmin = buildAuthorizationContext([
  authzRow("role-security-admin", "Security Admin", null, PERMISSIONS.POLICY_UPDATE),
]);
assert.equal(
  hasPermission(securityAdmin, requiredPermissionForAdminRoute("POST", "policy/routes/upsert")),
  true,
);
assert.equal(
  hasPermission(viewer, requiredPermissionForAdminRoute("POST", "policy/routes/upsert")),
  false,
);

const productionFirewall = buildFirewallAuthorizationContext([
  firewallAuthzRow(
    "firewall-production",
    "role-prod-policy",
    "Security Admin",
    null,
    PERMISSIONS.POLICY_UPDATE,
  ),
]);
assert.equal(
  hasFirewallPermission(productionFirewall, "firewall-production", PERMISSIONS.POLICY_UPDATE),
  true,
);

const stagingFirewall = buildFirewallAuthorizationContext([
  firewallAuthzRow("firewall-staging", null, null, null, null),
]);
assert.equal(
  hasFirewallPermission(stagingFirewall, "firewall-staging", PERMISSIONS.POLICY_UPDATE),
  false,
);

const crossTenantFirewall = buildFirewallAuthorizationContext([]);
assert.equal(crossTenantFirewall, null);

assert.equal(hasPermission(owner, PERMISSIONS.POLICY_UPDATE), true);
assert.equal(
  hasFirewallPermission(stagingFirewall, "firewall-staging", PERMISSIONS.POLICY_UPDATE),
  false,
);
assert.equal(
  hasFirewallPermission(productionFirewall, "firewall-other", PERMISSIONS.POLICY_UPDATE),
  false,
);

console.log("authz tests passed");

function authzRow(roleId, roleName, roleOrganizationId, permissionKey) {
  return {
    ...activeBase,
    roleId,
    roleName,
    roleOrganizationId,
    permissionKey,
  };
}

function firewallAuthzRow(
  firewallInstanceId,
  roleId,
  roleName,
  roleOrganizationId,
  permissionKey,
) {
  return {
    ...activeBase,
    firewallInstanceId,
    firewallInstanceStatus: "active",
    firewallInstanceDeletedAt: null,
    roleId,
    roleName,
    roleOrganizationId,
    permissionKey,
  };
}
