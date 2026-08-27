import assert from "node:assert/strict";
import {
  ADVANCED_DETECTORS,
  calculateCompositeRisk,
  classifyThreatContext,
  evaluateAdvancedDetectionCandidates,
  normalizeAdvancedDetectionQuery,
} from "../src/lib/advanced-detection/index.js";

const event = {
  id: "event-current",
  organizationId: "org-1",
  firewallInstanceId: "fw-1",
  eventType: "attack",
  attackType: "sql_injection",
  severity: "high",
  sourceIp: "203.0.113.10",
  requestPath: "/admin/users?id=123",
  httpMethod: "GET",
  userAgent: "sqlmap/1.8",
  country: "US",
  confidence: 0.82,
  detectorId: "phase5.sql_injection",
  detectorIds: ["phase5.sql_injection"],
  score: 76,
  anomalyType: null,
  actionTaken: "blocked",
  rawMetadata: {},
  occurredAt: new Date("2026-08-24T00:10:00.000Z"),
};

const recentEvents = Array.from({ length: 24 }, (_, index) => ({
  ...event,
  id: `event-${index}`,
  requestPath: `/admin/users?id=${index}`,
  detectorId: index % 2 ? "phase5.auth_abuse" : "phase5.sql_injection",
  detectorIds: index % 2 ? ["phase5.auth_abuse"] : ["phase5.sql_injection"],
  attackType: index % 3 === 0 ? "credential_attack" : "sql_injection",
  anomalyType: index % 3 === 0 ? "auth_failure" : null,
  occurredAt: new Date(`2026-08-24T00:0${Math.floor(index / 4)}:00.000Z`),
}));

const candidates = evaluateAdvancedDetectionCandidates({
  event,
  recentEvents,
  apiContext: { isShadow: true, isSensitive: true, isUnknown: false },
  now: new Date("2026-08-24T00:15:00.000Z"),
});

const detectorIds = candidates.findings.map((finding) => finding.detectorId);
assert.ok(detectorIds.includes(ADVANCED_DETECTORS.BEHAVIOR_ENDPOINT_DISCOVERY));
assert.ok(detectorIds.includes(ADVANCED_DETECTORS.BEHAVIOR_RECONNAISSANCE));
assert.ok(detectorIds.includes(ADVANCED_DETECTORS.ABUSE_SCANNER));
assert.ok(detectorIds.includes(ADVANCED_DETECTORS.ABUSE_CREDENTIAL_STUFFING));
assert.ok(candidates.correlation, "expected multi-signal correlation");
assert.equal(candidates.correlation.detectorId, ADVANCED_DETECTORS.CORRELATION_ATTACK_CHAIN);
assert.ok(candidates.correlation.relatedEventIds.length <= 50);
assert.equal(candidates.context.storesSensitivePayload, false);

const risk = calculateCompositeRisk({
  event,
  signals: [{ reasonCode: "route_enumeration", clientRisk: 85 }],
  apiContext: { isShadow: true, isSensitive: true },
  tenantContext: { activeIncidents: 2, openCriticalAlerts: 1 },
});
assert.ok(risk.score >= 0 && risk.score <= 100);
assert.ok(["low", "medium", "high", "critical"].includes(risk.severity));
assert.equal(risk.version, "8.2.v1");
assert.deepEqual(Object.keys(risk.components), ["event", "client", "api", "tenant", "threat"]);

const threatContext = classifyThreatContext(event);
assert.equal(threatContext.userAgentFamily, "scanner");
assert.equal(threatContext.ipReputation, "suspicious");

const tokenReplay = evaluateAdvancedDetectionCandidates({
  event: { ...event, detectorId: "phase5.auth_abuse", rawMetadata: { tokenReplay: true }, anomalyType: "token_replay" },
  recentEvents: [],
  apiContext: {},
});
assert.ok(tokenReplay.findings.some((finding) => finding.detectorId === ADVANCED_DETECTORS.ABUSE_TOKEN_REPLAY));

await assert.rejects(
  () =>
    normalizeAdvancedDetectionQuery({
      database: fakeOwnershipDatabase(),
      organizationId: "org-1",
      filters: {
        since: "2026-01-01T00:00:00.000Z",
        until: "2026-08-24T00:00:00.000Z",
      },
    }),
  /limited to 90 days/,
);

const normalized = await normalizeAdvancedDetectionQuery({
  database: fakeOwnershipDatabase(),
  organizationId: "org-1",
  filters: {
    since: "2026-08-23T00:00:00.000Z",
    until: "2026-08-24T00:00:00.000Z",
    limit: "999",
    firewallInstanceId: "fw-1",
  },
});
assert.equal(normalized.limit, 100);
assert.equal(normalized.firewallInstanceId, "fw-1");

console.log("phase 8.2 advanced detection tests passed");

function fakeOwnershipDatabase() {
  return {
    select() {
      return {
        from() {
          return {
            where() {
              return {
                async limit() {
                  return [{ id: "fw-1", organizationId: "org-1", status: "active" }];
                },
              };
            },
          };
        },
      };
    },
  };
}
