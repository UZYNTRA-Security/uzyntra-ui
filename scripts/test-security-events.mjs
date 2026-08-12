import assert from "node:assert/strict";
import {
  SECURITY_EVENT_ACTIONS,
  SECURITY_EVENT_SEVERITIES,
  SECURITY_EVENT_TYPES,
  createSecurityEvent,
  normalizeSecurityEvent,
  sanitizeMetadata,
  validateSecurityEvent,
} from "../src/lib/security-events/index.js";

const baseEvent = {
  organizationId: "org-1",
  firewallInstanceId: "firewall-1",
  eventType: SECURITY_EVENT_TYPES.ATTACK,
  attackType: "sql_injection",
  severity: SECURITY_EVENT_SEVERITIES.HIGH,
  sourceIp: "203.0.113.10",
  requestPath: "/api/orders?id=1",
  httpMethod: "post",
  userAgent: "curl/8.0",
  country: "us",
  confidence: 0.94,
  actionTaken: SECURITY_EVENT_ACTIONS.BLOCKED,
  requestId: "request-1",
  rawMetadata: {
    ruleIds: ["sql.union.select"],
    decision: { outcome: "reject:403" },
  },
  occurredAt: "2026-08-12T10:00:00.000Z",
};

const normalized = normalizeSecurityEvent(baseEvent);
assert.equal(normalized.httpMethod, "POST");
assert.equal(normalized.country, "US");
assert.equal(normalized.occurredAt instanceof Date, true);
assert.equal(validateSecurityEvent(normalized), true);

const writes = [];
const created = await createSecurityEvent({
  database: fakeDatabase({
    firewall: {
      id: "firewall-1",
      organizationId: "org-1",
      status: "active",
      deletedAt: null,
    },
    writes,
  }),
  ...baseEvent,
});

assert.equal(created.id, "security-event-1");
assert.equal(created.organizationId, "org-1");
assert.equal(created.firewallInstanceId, "firewall-1");
assert.equal(created.severity, "high");
assert.equal(created.actionTaken, "blocked");
assert.equal(writes.length, 1);
assert.equal(JSON.stringify(writes[0]).includes("AUTH_API_KEY_SECRET"), false);

await assert.rejects(
  () =>
    createSecurityEvent({
      database: fakeDatabase({
        firewall: {
          id: "firewall-1",
          organizationId: "org-2",
          status: "active",
          deletedAt: null,
        },
      }),
      ...baseEvent,
    }),
  /firewall instance is not available/,
);

assert.throws(
  () =>
    normalizeSecurityEvent({
      ...baseEvent,
      attackType: "",
    }),
  /attackType is required/,
);

assert.throws(
  () =>
    sanitizeMetadata({
      headers: {
        authorization: "Bearer secret",
      },
    }),
  /sensitive field/,
);

assert.throws(
  () =>
    normalizeSecurityEvent({
      ...baseEvent,
      rawMetadata: {
        credentials: {
          apiKey: "uz_live_should_not_be_stored",
        },
      },
    }),
  /sensitive field/,
);

console.log("security event tests passed");

function fakeDatabase({ firewall, writes = [] } = {}) {
  return {
    select() {
      return {
        from() {
          return {
            where() {
              return {
                async limit() {
                  return firewall ? [firewall] : [];
                },
              };
            },
          };
        },
      };
    },
    insert() {
      return {
        values(value) {
          writes.push(value);
          return {
            async returning() {
              return [{ id: "security-event-1", ...value }];
            },
          };
        },
      };
    },
  };
}
