import assert from "node:assert/strict";
import {
  INDICATOR_TYPES,
  extractEventLookups,
  normalizeIndicatorInput,
  normalizeLookupValue,
  providerRegistry,
  clearThreatIntelHotCache,
  hotCacheStats,
} from "../src/lib/threat-intelligence/index.js";
import { calculateCompositeRisk, evaluateAdvancedDetectionCandidates } from "../src/lib/advanced-detection/index.js";

const indicator = normalizeIndicatorInput({
  indicatorType: "ip",
  value: "203.0.113.10",
  category: "scanner",
  reputationScore: 85,
  confidence: 0.9,
  severity: "high",
  tags: ["scanner", "local", "scanner"],
});
assert.equal(indicator.indicatorType, INDICATOR_TYPES.IP);
assert.equal(indicator.reputationScore, 85);
assert.equal(indicator.confidence, 0.9);
assert.deepEqual(indicator.tags, ["scanner", "local"]);
assert.ok(indicator.expiresAt instanceof Date);

const domainLookup = normalizeLookupValue("domain", "HTTPS://Scanner.Example.COM/path?q=1");
assert.equal(domainLookup.value, "scanner.example.com");
assert.equal(domainLookup.hash.length, 64);

const urlLookup = normalizeLookupValue("url", "https://Scanner.Example.COM/path?q=1");
assert.equal(urlLookup.value, "https://scanner.example.com/path");

assert.throws(
  () =>
    normalizeIndicatorInput({
      indicatorType: "ip",
      value: "203.0.113.10",
      sourceMetadata: { apiKey: "do-not-store" },
    }),
  /sensitive field/,
);

const event = {
  organizationId: "org-1",
  firewallInstanceId: "fw-1",
  sourceIp: "203.0.113.10",
  userAgent: "sqlmap/1.8",
  rawMetadata: {
    asn: "AS64500",
    domain: "scanner.example.com",
    url: "https://scanner.example.com/probe",
    fileHash: "abcdef123456",
  },
};
const lookups = extractEventLookups(event);
assert.equal(lookups.length, 6);
assert.ok(lookups.some((lookup) => lookup.indicatorType === INDICATOR_TYPES.ASN));
assert.ok(lookups.some((lookup) => lookup.indicatorType === INDICATOR_TYPES.USER_AGENT));

assert.equal(providerRegistry.abuseipdb.capabilities.includes("ip_reputation"), true);
assert.equal(providerRegistry.greynoise.capabilities.includes("scanner_signatures"), true);
assert.equal(providerRegistry.stix_taxii.capabilities.includes("campaign_context"), true);

clearThreatIntelHotCache();
assert.deepEqual(hotCacheStats(), { size: 0, maxEntries: 5000 });

const riskWithoutIntel = calculateCompositeRisk({
  event: { severity: "medium", score: 30, confidence: 0.45 },
  signals: [{ reasonCode: "route_enumeration", clientRisk: 35 }],
  apiContext: {},
});
const riskWithIntel = calculateCompositeRisk({
  event: { severity: "medium", score: 30, confidence: 0.45 },
  signals: [{ reasonCode: "route_enumeration", clientRisk: 35 }],
  apiContext: {},
  threatIntel: { riskDelta: 70, confidenceDelta: 0.3 },
});
assert.ok(riskWithIntel.score > riskWithoutIntel.score);
assert.ok(riskWithIntel.confidence > riskWithoutIntel.confidence);
assert.equal(riskWithIntel.components.threat, 70);

const candidates = evaluateAdvancedDetectionCandidates({
  event: {
    id: "event-1",
    organizationId: "org-1",
    firewallInstanceId: "fw-1",
    attackType: "sql_injection",
    severity: "high",
    sourceIp: "203.0.113.10",
    requestPath: "/admin/users?id=1",
    httpMethod: "GET",
    userAgent: "sqlmap/1.8",
    confidence: 0.8,
    score: 75,
    rawMetadata: {},
  },
  recentEvents: Array.from({ length: 16 }, (_, index) => ({
    id: `event-${index}`,
    sourceIp: "203.0.113.10",
    requestPath: `/admin/users?id=${index}`,
    httpMethod: "GET",
    attackType: index % 3 === 0 ? "credential_attack" : "sql_injection",
    anomalyType: index % 3 === 0 ? "auth_failure" : null,
    detectorId: "phase5.sql_injection",
    detectorIds: ["phase5.sql_injection"],
  })),
  apiContext: { isSensitive: true },
  threatIntel: {
    riskDelta: 60,
    confidenceDelta: 0.2,
    matches: [{ id: "match-1" }],
    threatContext: { categories: ["scanner"], sourceIds: ["source-1"] },
  },
});
assert.ok(candidates.findings.some((finding) => finding.evidence.threatIntel.matchCount === 1));

console.log("phase 8.3 threat intelligence tests passed");
