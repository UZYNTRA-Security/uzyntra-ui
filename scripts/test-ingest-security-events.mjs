import assert from "node:assert/strict";
import { API_KEY_STATUSES, hashApiKey } from "../src/lib/api-keys/index.js";
import { handleSecurityEventIngestion } from "../src/app/api/ingest/security-events/route.js";

process.env.AUTH_API_KEY_SECRET = "0123456789abcdef0123456789abcdef";

const plaintextKey =
  "uz_live_0123456789ab_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const keyPrefix = "uz_live_0123456789ab";
const apiKey = {
  id: "api-key-1",
  organizationId: "org-1",
  serviceAccountId: "service-account-1",
  keyPrefix,
  keyHash: hashApiKey(plaintextKey),
  status: API_KEY_STATUSES.ACTIVE,
  expiresAt: new Date(Date.now() + 60_000),
  revokedAt: null,
};
const serviceAccount = {
  id: "service-account-1",
  organizationId: "org-1",
  status: "active",
  deletedAt: null,
};
const firewall = {
  id: "firewall-1",
  organizationId: "org-1",
  status: "active",
  deletedAt: null,
};

const validPayload = {
  firewallInstanceId: "firewall-1",
  eventType: "attack",
  attackType: "sql_injection",
  severity: "high",
  sourceIp: "203.0.113.10",
  requestPath: "/api/orders",
  httpMethod: "POST",
  userAgent: "uzyntra-firewall/0.1",
  country: "US",
  confidence: 0.98,
  actionTaken: "blocked",
  requestId: "firewall-request-1",
  rawMetadata: { ruleIds: ["sql.union.select"] },
  occurredAt: "2026-08-12T12:00:00.000Z",
};

const validWrites = [];
const validResponse = await handleSecurityEventIngestion({
  request: requestWithJson(validPayload, plaintextKey),
  database: fakeDatabase({
    authRow: { apiKey, serviceAccount },
    firewall,
    writes: validWrites,
  }),
});
const validBody = await validResponse.json();
assert.equal(validResponse.status, 201);
assert.equal(validBody.success, true);
assert.equal(validBody.eventId, "security-event-1");
assert.ok(validWrites.find((write) => write.actionTaken === "blocked"));
assert.ok(validWrites.find((write) => write.eventType === "security_event.ingested"));
assert.equal(JSON.stringify(validWrites).includes(plaintextKey), false);
assert.equal(JSON.stringify(validWrites).includes(apiKey.keyHash), false);

const invalidKeyResponse = await handleSecurityEventIngestion({
  request: requestWithJson(validPayload, "uz_live_0123456789ab_badbadbadbad"),
  database: fakeDatabase(),
});
assert.equal(invalidKeyResponse.status, 401);

const revokedKeyResponse = await handleSecurityEventIngestion({
  request: requestWithJson(validPayload, plaintextKey),
  database: fakeDatabase({
    authRow: {
      apiKey: { ...apiKey, status: API_KEY_STATUSES.REVOKED },
      serviceAccount,
    },
  }),
});
assert.equal(revokedKeyResponse.status, 401);

const crossOrgResponse = await handleSecurityEventIngestion({
  request: requestWithJson(validPayload, plaintextKey),
  database: fakeDatabase({
    authRow: { apiKey, serviceAccount },
    firewall: { ...firewall, organizationId: "org-2" },
  }),
});
assert.equal(crossOrgResponse.status, 403);

const secretMetadataResponse = await handleSecurityEventIngestion({
  request: requestWithJson(
    {
      ...validPayload,
      rawMetadata: {
        headers: {
          authorization: "Bearer should-not-store",
        },
      },
    },
    plaintextKey,
  ),
  database: fakeDatabase({
    authRow: { apiKey, serviceAccount },
    firewall,
  }),
});
assert.equal(secretMetadataResponse.status, 400);

console.log("security event ingestion tests passed");

function requestWithJson(payload, key) {
  return new Request("http://localhost/api/ingest/security-events", {
    method: "POST",
    headers: {
      authorization: `Bearer ${key}`,
      "content-type": "application/json",
      "user-agent": "test-agent",
      "x-forwarded-for": "198.51.100.10",
    },
    body: JSON.stringify(payload),
  });
}

function fakeDatabase({ authRow, firewall, writes = [] } = {}) {
  return {
    select() {
      return {
        from() {
          return {
            innerJoin() {
              return {
                where() {
                  return {
                    async limit() {
                      return authRow ? [authRow] : [];
                    },
                  };
                },
              };
            },
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
              if (value.actionTaken) {
                return [{ id: "security-event-1", ...value }];
              }

              return [{ id: "audit-event-1", ...value }];
            },
          };
        },
      };
    },
  };
}
