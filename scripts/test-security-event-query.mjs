import assert from "node:assert/strict";
import { PERMISSIONS } from "../src/lib/rbac/catalog.js";
import {
  decodeSecurityEventCursor,
  encodeSecurityEventCursor,
  normalizeAnalyticsQuery,
  normalizeSecurityEventQuery,
} from "../src/lib/security-events/query.js";
import {
  handleSecurityEventAnalyticsRequest,
  handleSecurityEventsRequest,
} from "../src/lib/security-events/api.js";

const normalized = normalizeSecurityEventQuery({
  source_ip: "203.0.113.10",
  method: "post",
  path_contains: "/api/orders",
  severity: "HIGH",
  attackType: "sql_injection",
  actionTaken: "blocked",
  limit: "500",
});

assert.equal(normalized.sourceIp, "203.0.113.10");
assert.equal(normalized.httpMethod, "POST");
assert.equal(normalized.requestPath, "/api/orders");
assert.equal(normalized.severity, "high");
assert.equal(normalized.attackType, "sql_injection");
assert.equal(normalized.actionTaken, "blocked");
assert.equal(normalized.limit, 100);

const cursor = encodeSecurityEventCursor({
  id: "event-1",
  occurredAt: "2026-08-12T10:00:00.000Z",
});
assert.deepEqual(decodeSecurityEventCursor(cursor), {
  id: "event-1",
  occurredAt: new Date("2026-08-12T10:00:00.000Z"),
});
assert.throws(() => decodeSecurityEventCursor("not-base64-json"), /cursor is invalid/);

const analyticsWindow = normalizeAnalyticsQuery({
  since: "2026-08-11T10:00:00.000Z",
  until: "2026-08-12T10:00:00.000Z",
});
assert.equal(analyticsWindow.since.toISOString(), "2026-08-11T10:00:00.000Z");
assert.equal(analyticsWindow.until.toISOString(), "2026-08-12T10:00:00.000Z");

const identity = {
  userId: "user-1",
  organizationId: "org-1",
  sessionId: "session-1",
};

const eventsAllowed = await handleSecurityEventsRequest({
  request: new Request("http://localhost/api/security-events?limit=5&source_ip=203.0.113.10"),
  database: {},
  identity,
  authorizationContext: { permissions: [PERMISSIONS.EVENTS_READ] },
  querySecurityEvents: async ({ organizationId, filters }) => {
    assert.equal(organizationId, "org-1");
    assert.equal(filters.limit, "5");
    return {
      items: [
        {
          id: "event-1",
          firewallInstanceId: "firewall-1",
          eventType: "attack",
          attackType: "sql_injection",
          severity: "high",
          sourceIp: "203.0.113.10",
          requestPath: "/api/orders",
          httpMethod: "POST",
          actionTaken: "blocked",
          requestId: "request-1",
          rawMetadata: { ruleIds: ["sqli.basic"] },
          occurredAt: new Date("2026-08-12T10:00:00.000Z"),
          receivedAt: new Date("2026-08-12T10:00:01.000Z"),
        },
      ],
      pageInfo: { limit: 5, hasMore: false, nextCursor: null },
      filters: { limit: 5 },
    };
  },
});
const eventsAllowedBody = await eventsAllowed.json();
assert.equal(eventsAllowed.status, 200);
assert.equal(eventsAllowedBody.success, true);
assert.equal(eventsAllowedBody.data.items[0].organizationId, undefined);
assert.equal(JSON.stringify(eventsAllowedBody).includes("password_hash"), false);

const eventsUnauthorized = await handleSecurityEventsRequest({
  request: new Request("http://localhost/api/security-events"),
  database: {},
  identity: null,
});
assert.equal(eventsUnauthorized.status, 401);

const eventsForbidden = await handleSecurityEventsRequest({
  request: new Request("http://localhost/api/security-events"),
  database: {},
  identity,
  authorizationContext: { permissions: [PERMISSIONS.METRICS_READ] },
});
assert.equal(eventsForbidden.status, 403);

const analyticsAllowed = await handleSecurityEventAnalyticsRequest({
  request: new Request("http://localhost/api/security-events/analytics"),
  database: {},
  identity,
  authorizationContext: { permissions: [PERMISSIONS.METRICS_READ] },
  queryAnalytics: async ({ organizationId }) => {
    assert.equal(organizationId, "org-1");
    return {
      totals: {
        total: 1,
        blocked: 1,
        allowed: 0,
        rateLimited: 0,
        critical: 0,
        high: 1,
      },
    };
  },
});
assert.equal(analyticsAllowed.status, 200);
assert.equal((await analyticsAllowed.json()).data.totals.blocked, 1);

const analyticsForbidden = await handleSecurityEventAnalyticsRequest({
  request: new Request("http://localhost/api/security-events/analytics"),
  database: {},
  identity,
  authorizationContext: { permissions: [PERMISSIONS.EVENTS_READ] },
});
assert.equal(analyticsForbidden.status, 403);

console.log("security event query tests passed");
