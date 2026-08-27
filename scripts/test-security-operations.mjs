import assert from "node:assert/strict";
import { PERMISSIONS } from "../src/lib/rbac/catalog.js";
import {
  handleSecurityOperationRequest,
  securityOperationConfig,
} from "../src/lib/security-operations/api.js";
import {
  computeAlertReliabilityScore,
  mapDeliveryStatus,
  maskChannelName,
  normalizeSecurityOperationsQuery,
} from "../src/lib/security-operations/query.js";

assert.equal(computeAlertReliabilityScore({ delivered: 987, total: 1000 }), 98.7);
assert.equal(computeAlertReliabilityScore({ delivered: 0, total: 0 }), 100);
assert.equal(mapDeliveryStatus("pending"), "pending");
assert.equal(mapDeliveryStatus("delivered"), "delivered");
assert.equal(mapDeliveryStatus("retry"), "retrying");
assert.equal(mapDeliveryStatus("claimed"), "retrying");
assert.equal(mapDeliveryStatus("failed", 1, 5), "failed");
assert.equal(mapDeliveryStatus("failed", 5, 5), "dead_letter");
assert.equal(mapDeliveryStatus("blocked"), "dead_letter");
assert.equal(maskChannelName("Enterprise Webhook"), "En***ok");
assert.equal(maskChannelName("SIEM"), "SIEM");

assert.ok(securityOperationConfig("dashboard").permissions.includes(PERMISSIONS.METRICS_READ));
assert.ok(securityOperationConfig("notificationHealth").permissions.includes(PERMISSIONS.ALERTS_READ));

const normalized = await normalizeSecurityOperationsQuery({
  database: fakeOwnershipDatabase(),
  organizationId: "org-1",
  filters: {
    since: "2026-08-01T00:00:00.000Z",
    until: "2026-08-02T00:00:00.000Z",
    bucket: "day",
    limit: "500",
    firewallInstanceId: "firewall-1",
  },
});
assert.equal(normalized.limit, 100);
assert.equal(normalized.bucket, "day");
assert.equal(normalized.firewallInstanceId, "firewall-1");

const identity = {
  userId: "user-1",
  organizationId: "org-1",
  sessionId: "session-1",
};

const allowed = await handleSecurityOperationRequest({
  request: new Request("http://localhost/api/security/dashboard?limit=5"),
  operation: "dashboard",
  database: {},
  identity,
  authorizationContext: { permissions: [PERMISSIONS.METRICS_READ] },
  queryOperation: async ({ organizationId, filters }) => {
    assert.equal(organizationId, "org-1");
    assert.equal(filters.limit, "5");
    return { ok: true };
  },
});
assert.equal(allowed.status, 200);
assert.equal((await allowed.json()).data.ok, true);

const unauthorized = await handleSecurityOperationRequest({
  request: new Request("http://localhost/api/security/dashboard"),
  operation: "dashboard",
  database: {},
  identity: null,
});
assert.equal(unauthorized.status, 401);

const forbidden = await handleSecurityOperationRequest({
  request: new Request("http://localhost/api/security/dashboard"),
  operation: "dashboard",
  database: {},
  identity,
  authorizationContext: { permissions: [PERMISSIONS.EVENTS_READ] },
});
assert.equal(forbidden.status, 403);

const firewallScoped = await handleSecurityOperationRequest({
  request: new Request("http://localhost/api/security/metrics?firewallInstanceId=firewall-2"),
  operation: "metrics",
  database: {},
  identity: { ...identity, activeFirewallInstanceId: "firewall-1" },
  authorizationContext: { permissions: [PERMISSIONS.METRICS_READ] },
  queryOperation: async () => ({ unreachable: true }),
});
assert.equal(firewallScoped.status, 403);

const notificationAllowed = await handleSecurityOperationRequest({
  request: new Request("http://localhost/api/security/notification-health"),
  operation: "notificationHealth",
  database: {},
  identity,
  authorizationContext: { permissions: [PERMISSIONS.INCIDENTS_READ] },
  queryOperation: async () => ({ reliability: { score: 99.2 } }),
});
assert.equal(notificationAllowed.status, 200);
assert.equal((await notificationAllowed.json()).data.reliability.score, 99.2);

console.log("security operations tests passed");

function fakeOwnershipDatabase() {
  return {
    select() {
      return {
        from() {
          return {
            where() {
              return {
                async limit() {
                  return [{ id: "firewall-1", organizationId: "org-1", status: "active" }];
                },
              };
            },
          };
        },
      };
    },
  };
}
