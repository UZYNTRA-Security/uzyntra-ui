import assert from "node:assert/strict";
import {
  DELEGATED_ACCESS_LEVELS,
  ENTERPRISE_RELATIONSHIP_TYPES,
  TENANT_PLANS,
  isDelegatedAccessActive,
} from "../src/lib/enterprise/index.js";
import { AUDIT_EVENT_TYPES } from "../src/lib/audit/index.js";
import { PERMISSIONS, DEFAULT_ROLES } from "../src/lib/rbac/catalog.js";

function run() {
  testCatalogExports();
  testRbacCatalog();
  testDefaultRoles();
  testAuditCatalog();
  testDelegationLifecycle();
  testEnterpriseBoundaries();
  console.log("test-enterprise passed");
}

function testCatalogExports() {
  assert.equal(ENTERPRISE_RELATIONSHIP_TYPES.MSSP_CUSTOMER, "mssp_customer");
  assert.equal(DELEGATED_ACCESS_LEVELS.ANALYST, "analyst");
  assert.equal(TENANT_PLANS.ENTERPRISE, "enterprise");
}

function testRbacCatalog() {
  for (const permission of [
    "enterprise.read",
    "enterprise.manage",
    "tenant.read",
    "tenant.manage",
    "delegated_access.read",
    "delegated_access.manage",
    "compliance_reports.read",
    "compliance_reports.generate",
    "usage.read",
  ]) {
    assert.ok(Object.values(PERMISSIONS).includes(permission));
  }
}

function testDefaultRoles() {
  const roles = new Map(DEFAULT_ROLES.map((role) => [role.name, role]));
  assert.ok(roles.get("Owner").permissions.includes(PERMISSIONS.ENTERPRISE_MANAGE));
  assert.ok(roles.get("Security Admin").permissions.includes(PERMISSIONS.DELEGATED_ACCESS_MANAGE));
  assert.ok(roles.get("MSSP Operator").permissions.includes(PERMISSIONS.TENANT_READ));
  assert.equal(roles.get("MSSP Operator").permissions.includes(PERMISSIONS.TENANT_MANAGE), false);
  assert.ok(roles.get("Auditor").permissions.includes(PERMISSIONS.COMPLIANCE_REPORTS_READ));
  assert.equal(roles.get("Auditor").permissions.includes(PERMISSIONS.DELEGATED_ACCESS_MANAGE), false);
}

function testAuditCatalog() {
  for (const eventType of [
    "enterprise.hierarchy.updated",
    "enterprise.customer.created",
    "enterprise.delegated_access.granted",
    "enterprise.compliance_report.created",
    "enterprise.usage.record_created",
  ]) {
    assert.ok(Object.values(AUDIT_EVENT_TYPES).includes(eventType));
  }
}

function testDelegationLifecycle() {
  const future = new Date(Date.now() + 60_000);
  const past = new Date(Date.now() - 60_000);
  assert.equal(
    isDelegatedAccessActive({
      status: "active",
      approvalState: "approved",
      expiresAt: future,
    }),
    true,
  );
  assert.equal(
    isDelegatedAccessActive({
      status: "active",
      approvalState: "pending_customer_approval",
      expiresAt: future,
    }),
    false,
  );
  assert.equal(
    isDelegatedAccessActive({
      status: "active",
      approvalState: "approved",
      expiresAt: past,
    }),
    false,
  );
  assert.equal(
    isDelegatedAccessActive({
      status: "revoked",
      approvalState: "approved",
      expiresAt: future,
    }),
    false,
  );
}

function testEnterpriseBoundaries() {
  const msspRole = DEFAULT_ROLES.find((role) => role.name === "MSSP Operator");
  assert.ok(msspRole.permissions.includes(PERMISSIONS.AI_ANALYZE));
  assert.equal(msspRole.permissions.includes(PERMISSIONS.AI_MANAGE), false);
  assert.equal(msspRole.permissions.includes(PERMISSIONS.ENTERPRISE_MANAGE), false);
  assert.equal(msspRole.permissions.includes(PERMISSIONS.POLICY_APPROVALS_MANAGE), false);
}

run();
