import assert from "node:assert/strict";
import {
  normalizeInventoryQuery,
  upsertApiInventoryFromSecurityEvent,
} from "../src/lib/api-inventory/index.js";
import { normalizeSecurityEvent } from "../src/lib/security-events/index.js";

const event = normalizeSecurityEvent({
  organizationId: "org-1",
  firewallInstanceId: "firewall-1",
  eventType: "attack",
  attackType: "schema_violation",
  severity: "medium",
  sourceIp: "203.0.113.10",
  requestPath: "/api/orders/123?token=redacted",
  httpMethod: "post",
  confidence: 0.87,
  detectorId: "UZ-API-SCHEMA-001",
  detectorIds: ["UZ-API-SCHEMA-001", "UZ-API-SCHEMA-001", "UZ-SSRF-001"],
  score: 46.8,
  apiRouteId: "/api/orders/{id}",
  anomalyType: "schema",
  actionTaken: "allowed",
  requestId: "request-1",
  rawMetadata: {
    detector_ids: ["UZ-API-SCHEMA-001"],
    categories: ["schema"],
    observedStatusCodes: [200, 400],
    requestContentType: "application/json; charset=utf-8",
  },
  occurredAt: "2026-08-14T10:00:00.000Z",
});

assert.equal(event.detectorId, "uz-api-schema-001");
assert.deepEqual(event.detectorIds, ["uz-api-schema-001", "uz-ssrf-001"]);
assert.equal(event.score, 46.8);
assert.equal(event.apiRouteId, "/api/orders/{id}");
assert.equal(event.anomalyType, "schema");

const writes = [];
const route = await upsertApiInventoryFromSecurityEvent({
  database: fakeDatabase(writes),
  event,
});

assert.equal(route.routeTemplate, "/api/orders/{id}");
assert.deepEqual(route.methods, ["POST"]);
assert.equal(route.status, "known");
assert.equal(route.learnedSchemaSummary.findingCount, 0);
assert.equal(JSON.stringify(writes).includes("token=redacted"), false);

const query = normalizeInventoryQuery({
  status: "NEW",
  path_contains: "/api",
  limit: 500,
});
assert.equal(query.status, "new");
assert.equal(query.route, "/api");
assert.equal(query.limit, 200);

assert.throws(() => normalizeInventoryQuery({ status: "invalid" }), /status filter/);

console.log("phase 5 detection UI tests passed");

function fakeDatabase(writes) {
  return {
    insert() {
      return {
        values(value) {
          writes.push(value);
          return {
            async returning() {
              return [{ id: "route-1", ...value }];
            },
          };
        },
      };
    },
  };
}
