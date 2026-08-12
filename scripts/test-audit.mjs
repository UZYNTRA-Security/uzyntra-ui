import assert from "node:assert/strict";
import {
  AUDIT_RESULTS,
  AUDIT_EVENT_TYPES,
  AUDIT_SEVERITIES,
  assertAuditEventSafe,
  createAuditEvent,
  normalizeAuditEvent,
} from "../src/lib/audit/index.js";

const normalized = normalizeAuditEvent({
  organizationId: "org-1",
  userId: "user-1",
  eventType: AUDIT_EVENT_TYPES.AUTH_LOGIN_SUCCESS,
  action: "login",
  result: AUDIT_RESULTS.SUCCESS,
  severity: AUDIT_SEVERITIES.INFO,
  ipAddress: "127.0.0.1",
  userAgent: "test-agent\nwith-control-char",
  requestId: "request-1",
  metadata: { method: "password" },
});

assert.equal(normalized.eventType, "auth.login.success");
assert.equal(normalized.result, "success");
assert.equal(normalized.severity, "info");
assert.equal(normalized.userAgent, "test-agentwith-control-char");
assert.deepEqual(normalized.metadata, { method: "password" });

assert.throws(
  () => normalizeAuditEvent({ action: "login", result: AUDIT_RESULTS.SUCCESS }),
  /eventType is required/,
);

assert.throws(
  () =>
    assertAuditEventSafe({
      eventType: AUDIT_EVENT_TYPES.AUTH_LOGIN_FAILURE,
      action: "login",
      result: AUDIT_RESULTS.FAILURE,
      metadata: { nested: { sessionToken: "secret" } },
    }),
  /nested.sessionToken/,
);

const inserted = await createAuditEvent({
  database: fakeDatabase(),
  eventType: AUDIT_EVENT_TYPES.AUTHZ_DENIED,
  action: "policy.update",
  result: AUDIT_RESULTS.DENIED,
  severity: AUDIT_SEVERITIES.MEDIUM,
  organizationId: "org-1",
  userId: "user-1",
  resourceType: "policy",
  requestId: "request-2",
  metadata: { permission: "policy.update" },
});

assert.equal(inserted.id, "audit-1");
assert.equal(inserted.result, "denied");
assert.equal(inserted.metadata.permission, "policy.update");

console.log("audit tests passed");

function fakeDatabase() {
  return {
    insert() {
      return {
        values(value) {
          return {
            async returning() {
              return [{ id: "audit-1", ...value }];
            },
          };
        },
      };
    },
  };
}
