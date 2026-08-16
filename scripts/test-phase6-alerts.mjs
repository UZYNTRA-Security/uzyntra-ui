import assert from "node:assert/strict";
import {
  alertFingerprint,
  normalizeAlertRule,
  ruleMatchesEvent,
} from "../src/lib/alerts/index.js";

const baseRule = normalizeAlertRule({
  name: "Critical SSRF",
  severityThreshold: "high",
  scoreThreshold: 60,
  confidenceThreshold: 0.8,
  detectorIds: ["UZ-SSRF-001"],
  attackTypes: ["ssrf"],
  actions: ["blocked"],
  thresholdCount: 5,
  aggregationWindowSeconds: 60,
  cooldownSeconds: 300,
});

assert.equal(baseRule.detectorIds[0], "uz-ssrf-001");
assert.equal(baseRule.thresholdCount, 5);
assert.throws(() => normalizeAlertRule({ name: "empty" }), /at least one criterion/);
assert.throws(() => normalizeAlertRule({ name: "bad", detectorIds: ["unknown.detector"] }), /unsupported detector/);
assert.throws(() => normalizeAlertRule({ name: "bad route", routePatterns: ["file://x"] }), /route selector/);

const event = {
  organizationId: "org-1",
  firewallInstanceId: "fw-1",
  severity: "critical",
  score: 91,
  confidence: 0.98,
  detectorId: "uz-ssrf-001",
  attackType: "ssrf",
  anomalyType: null,
  actionTaken: "blocked",
  sourceIp: "203.0.113.10",
  requestPath: "/proxy/api/admin",
};

assert.equal(ruleMatchesEvent(baseRule, event), true);
assert.equal(ruleMatchesEvent({ ...baseRule, thresholdCount: 6 }, event), true);
assert.equal(ruleMatchesEvent({ ...baseRule, severityThreshold: "critical" }, event), true);
assert.equal(ruleMatchesEvent({ ...baseRule, severityThreshold: "critical", scoreThreshold: 99 }, event), false);

const fp1 = alertFingerprint({ rule: { ...baseRule, id: "rule-1" }, event });
const fp2 = alertFingerprint({ rule: { ...baseRule, id: "rule-1" }, event: { ...event } });
const fp3 = alertFingerprint({ rule: { ...baseRule, id: "rule-1" }, event: { ...event, sourceIp: "203.0.113.11" } });
assert.equal(fp1, fp2);
assert.notEqual(fp1, fp3);

console.log("phase 6 alert validation and dedupe tests passed");
