import assert from "node:assert/strict";
import {
  INTEGRATION_CATEGORIES,
  PLATFORM_HEALTH_STATUSES,
  PLATFORM_REGION_STATUSES,
  REGIONAL_SERVICE_TYPES,
  calculateHealthRollup,
  isTenantRegionAllowed,
} from "../src/lib/global-scale/index.js";
import { AUDIT_EVENT_TYPES } from "../src/lib/audit/index.js";
import { DEFAULT_ROLES, PERMISSIONS } from "../src/lib/rbac/catalog.js";

function run() {
  testCatalogExports();
  testTenantRegionPlacement();
  testHealthRollup();
  testRbacCatalog();
  testDefaultRoleBoundaries();
  testAuditCatalog();
  testNoPhase9Scope();
  console.log("test-global-scale passed");
}

function testCatalogExports() {
  assert.equal(PLATFORM_REGION_STATUSES.ACTIVE, "active");
  assert.equal(REGIONAL_SERVICE_TYPES.GATEWAY, "gateway");
  assert.equal(PLATFORM_HEALTH_STATUSES.DEGRADED, "degraded");
  assert.equal(INTEGRATION_CATEGORIES.THREAT_INTELLIGENCE, "threat_intelligence");
}

function testTenantRegionPlacement() {
  const locked = {
    regionId: "region-us",
    status: "active",
    residencyLocked: true,
    failoverRegionIds: ["region-eu"],
  };
  const unlocked = {
    ...locked,
    residencyLocked: false,
  };

  assert.equal(isTenantRegionAllowed({ assignment: locked, targetRegionId: "region-us" }), true);
  assert.equal(isTenantRegionAllowed({ assignment: locked, targetRegionId: "region-eu" }), false);
  assert.equal(isTenantRegionAllowed({ assignment: unlocked, targetRegionId: "region-eu" }), true);
  assert.equal(isTenantRegionAllowed({ assignment: { ...unlocked, status: "disabled" }, targetRegionId: "region-eu" }), false);
}

function testHealthRollup() {
  const rollup = calculateHealthRollup([
    { status: "healthy", latencyP95Ms: 40, availabilityPercent: 100 },
    { status: "degraded", latencyP95Ms: 120, availabilityPercent: 99 },
    { status: "down", latencyP95Ms: 300, availabilityPercent: 97 },
  ]);

  assert.equal(rollup.total, 3);
  assert.equal(rollup.healthy, 1);
  assert.equal(rollup.degraded, 2);
  assert.equal(rollup.averageLatencyP95Ms, 153);
  assert.equal(rollup.averageAvailabilityPercent, 98.67);
}

function testRbacCatalog() {
  for (const permission of [
    "platform.read",
    "platform.manage",
    "regions.read",
    "regions.manage",
    "developer.read",
    "developer.manage",
    "integrations.read",
    "integrations.manage",
    "marketplace.read",
  ]) {
    assert.ok(Object.values(PERMISSIONS).includes(permission), `${permission} missing`);
  }
}

function testDefaultRoleBoundaries() {
  const roles = new Map(DEFAULT_ROLES.map((role) => [role.name, role]));
  assert.ok(roles.get("Owner").permissions.includes(PERMISSIONS.PLATFORM_MANAGE));
  assert.ok(roles.get("Security Admin").permissions.includes(PERMISSIONS.REGIONS_MANAGE));
  assert.ok(roles.get("Security Admin").permissions.includes(PERMISSIONS.DEVELOPER_MANAGE));
  assert.ok(roles.get("MSSP Operator").permissions.includes(PERMISSIONS.PLATFORM_READ));
  assert.equal(roles.get("MSSP Operator").permissions.includes(PERMISSIONS.PLATFORM_MANAGE), false);
  assert.ok(roles.get("Auditor").permissions.includes(PERMISSIONS.MARKETPLACE_READ));
  assert.equal(roles.get("Auditor").permissions.includes(PERMISSIONS.REGIONS_MANAGE), false);
}

function testAuditCatalog() {
  for (const eventType of [
    "platform.region.created",
    "platform.tenant_region.assigned",
    "platform.regional_service.registered",
    "platform.health.recorded",
    "platform.backup.recorded",
    "platform.restore.recorded",
    "developer.app.created",
    "integration.catalog.created",
    "marketplace.listing.created",
  ]) {
    assert.ok(Object.values(AUDIT_EVENT_TYPES).includes(eventType), `${eventType} missing`);
  }
}

function testNoPhase9Scope() {
  assert.equal(Object.values(PERMISSIONS).includes("identity.sso.configure"), false);
  assert.equal(Object.values(PERMISSIONS).includes("oauth.providers.manage"), false);
}

run();
