import assert from "node:assert/strict";
import { DEFAULT_ROLES, PERMISSIONS } from "../src/lib/rbac/catalog.js";

const roles = new Map(DEFAULT_ROLES.map((role) => [role.name, role.permissions]));
assert.ok(roles.get("Owner").includes(PERMISSIONS.ALERTS_MANAGE));
assert.ok(roles.get("Security Admin").includes(PERMISSIONS.INTEGRATIONS_MANAGE));
assert.ok(roles.get("Analyst").includes(PERMISSIONS.INCIDENTS_MANAGE));
assert.ok(roles.get("Viewer").includes(PERMISSIONS.ALERTS_READ));
assert.equal(roles.get("Viewer").includes(PERMISSIONS.ALERTS_MANAGE), false);
assert.equal(roles.get("Analyst").includes(PERMISSIONS.INTEGRATIONS_MANAGE), false);

console.log("phase 6 RBAC catalog tests passed");
