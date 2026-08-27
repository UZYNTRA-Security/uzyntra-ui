import assert from "node:assert/strict";
import {
  PROTECTION_ACTIONS,
  PROTECTION_MODES,
  PROTECTION_PRECEDENCE,
  evaluateAdaptiveProtection,
  evaluateRateLimit,
} from "../src/lib/adaptive-protection/index.js";
import { PERMISSIONS } from "../src/lib/rbac/catalog.js";

function run() {
  testActionsAndModes();
  testDeterministicPrecedence();
  testRateLimitBounds();
  testAllowlistBlocklistPrecedence();
  testEmergencyBypass();
  testCredentialProtection();
  testSensitiveRedaction();
  testMalformedConfiguration();
  testFailSafe();
  testRbacCatalog();
  console.log("test:adaptive-protection passed");
}

function baseDecision(decision = "allow") {
  return {
    id: `decision-${decision}`,
    organizationId: "org-a",
    firewallInstanceId: "fw-a",
    policyId: "policy-a",
    policyVersionId: "version-a",
    decision,
    decisionReason: `${decision} from zero trust`,
    riskScore: decision === "allow" ? 10 : 90,
    confidence: 0.92,
    detectorReferences: ["behavior.reconnaissance"],
  };
}

function testActionsAndModes() {
  const mapping = {
    allow: PROTECTION_ACTIONS.ALLOW,
    challenge: PROTECTION_ACTIONS.CHALLENGE,
    rate_limit: PROTECTION_ACTIONS.RATE_LIMIT,
    block: PROTECTION_ACTIONS.BLOCK,
    quarantine: PROTECTION_ACTIONS.QUARANTINE,
  };
  for (const [decision, action] of Object.entries(mapping)) {
    const result = evaluateAdaptiveProtection({
      policyDecision: baseDecision(decision),
      context: { sourceIp: "203.0.113.10", route: "/api/orders" },
      mode: PROTECTION_MODES.ENFORCEMENT,
    });
    assert.equal(result.action, action);
    assert.equal(result.mode, PROTECTION_MODES.ENFORCEMENT);
    assert.equal(result.effectiveAction, result.action);
  }

  const observe = evaluateAdaptiveProtection({
    policyDecision: baseDecision("block"),
    mode: PROTECTION_MODES.OBSERVE,
  });
  assert.equal(observe.action, PROTECTION_ACTIONS.BLOCK);
  assert.equal(observe.effectiveAction, PROTECTION_ACTIONS.ALLOW);
  assert.equal(observe.outcome, "observed");

  const simulation = evaluateAdaptiveProtection({
    policyDecision: baseDecision("block"),
    mode: PROTECTION_MODES.SIMULATION,
  });
  assert.equal(simulation.action, PROTECTION_ACTIONS.BLOCK);
  assert.equal(simulation.effectiveAction, PROTECTION_ACTIONS.ALLOW);
  assert.equal(simulation.outcome, "simulated");
}

function testDeterministicPrecedence() {
  assert.deepEqual(PROTECTION_PRECEDENCE, [
    "emergency_bypass",
    "explicit_block",
    "quarantine",
    "credential_restriction",
    "adaptive_rate_limit",
    "challenge",
    "allow",
  ]);

  const result = evaluateAdaptiveProtection({
    policyDecision: baseDecision("challenge"),
    protectionRules: [
      {
        id: "quarantine-rule",
        status: "active",
        action: "quarantine",
        reason: "critical route quarantine",
        conditions: [{ field: "risk_score", operator: "gte", value: 80 }],
      },
      {
        id: "rate-rule",
        status: "active",
        action: "rate_limit",
        reason: "high velocity",
        conditions: [{ field: "risk_score", operator: "gte", value: 50 }],
      },
    ],
    mode: PROTECTION_MODES.ENFORCEMENT,
  });
  assert.equal(result.action, PROTECTION_ACTIONS.QUARANTINE);
  assert.equal(result.protectionRuleId, "quarantine-rule");
}

function testRateLimitBounds() {
  const store = new Map();
  const policy = { id: "rl-source", dimension: "source", limitCount: 2, windowSeconds: 60 };
  const context = { organizationId: "org-a", source: "198.51.100.2" };
  const first = evaluateRateLimit({ policy, context, store });
  const second = evaluateRateLimit({ policy, context, store });
  const third = evaluateRateLimit({ policy, context, store });
  assert.equal(first.exceeded, false);
  assert.equal(second.exceeded, false);
  assert.equal(third.exceeded, true);
  assert.equal(store.size, 1);
  assert.equal(third.keyLabel, "198.51.100.2");
}

function testAllowlistBlocklistPrecedence() {
  const allowAndBlock = evaluateAdaptiveProtection({
    policyDecision: baseDecision("allow"),
    context: { sourceIp: "203.0.113.5", route: "/api/users" },
    allowlist: [{ id: "allow-1", status: "active", entryType: "ip", entryLabel: "203.0.113.5", reason: "trusted scanner" }],
    blocklist: [{ id: "block-1", status: "active", entryType: "ip", entryLabel: "203.0.113.5", reason: "explicit deny" }],
    mode: PROTECTION_MODES.ENFORCEMENT,
  });
  assert.equal(allowAndBlock.action, PROTECTION_ACTIONS.BLOCK);
  assert.equal(allowAndBlock.protectionRuleId, "block-1");

  const allowOnly = evaluateAdaptiveProtection({
    policyDecision: baseDecision("block"),
    context: { sourceIp: "203.0.113.6" },
    allowlist: [{ id: "allow-2", status: "active", entryType: "ip", entryLabel: "203.0.113.6", reason: "temporary exception" }],
    mode: PROTECTION_MODES.ENFORCEMENT,
  });
  assert.equal(allowOnly.action, PROTECTION_ACTIONS.BLOCK);
}

function testEmergencyBypass() {
  const result = evaluateAdaptiveProtection({
    policyDecision: baseDecision("block"),
    emergencyBypass: { id: "bypass-1", status: "active", expiresAt: new Date(Date.now() + 60_000).toISOString() },
    mode: PROTECTION_MODES.ENFORCEMENT,
  });
  assert.equal(result.action, PROTECTION_ACTIONS.ALLOW);
  assert.equal(result.effectiveAction, PROTECTION_ACTIONS.ALLOW);
  assert.equal(result.outcome, "bypassed");
}

function testCredentialProtection() {
  const suspended = evaluateAdaptiveProtection({
    policyDecision: baseDecision("allow"),
    credentialState: { status: "suspended", reason: "confirmed leakage" },
    mode: PROTECTION_MODES.ENFORCEMENT,
  });
  assert.equal(suspended.action, PROTECTION_ACTIONS.CREDENTIAL_SUSPEND);

  const restricted = evaluateAdaptiveProtection({
    policyDecision: baseDecision("allow"),
    credentialState: { status: "restricted", reason: "abuse spike", restrictedUntil: new Date(Date.now() + 60_000).toISOString() },
    rateLimitPolicy: { id: "rl-cred", dimension: "credential", limitCount: 0, windowSeconds: 60 },
    context: { credentialFingerprint: "credential-a" },
    mode: PROTECTION_MODES.ENFORCEMENT,
  });
  assert.equal(restricted.action, PROTECTION_ACTIONS.RATE_LIMIT);
}

function testSensitiveRedaction() {
  const result = evaluateAdaptiveProtection({
    policyDecision: baseDecision("block"),
    context: {
      requestContext: {
        path: "/api/export",
        authorization: "Bearer secret",
        body: "raw-payload",
        safe: "visible",
      },
      credentialFingerprint: "cred-a",
    },
    mode: PROTECTION_MODES.ENFORCEMENT,
  });
  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes("Bearer secret"), false);
  assert.equal(serialized.includes("raw-payload"), false);
  assert.equal(serialized.includes("authorization"), false);
}

function testMalformedConfiguration() {
  assert.throws(
    () =>
      evaluateAdaptiveProtection({
        policyDecision: baseDecision("allow"),
        protectionRules: [
          {
            status: "active",
            action: "block",
            conditions: [{ field: "payload", operator: "contains", value: "x" }],
          },
        ],
      }),
    /condition field is invalid/,
  );
}

function testFailSafe() {
  const result = evaluateAdaptiveProtection({
    context: { organizationId: "org-a", sourceIp: "203.0.113.7" },
    mode: PROTECTION_MODES.ENFORCEMENT,
  });
  assert.equal(result.action, PROTECTION_ACTIONS.BLOCK);
  assert.equal(result.effectiveAction, PROTECTION_ACTIONS.BLOCK);
  assert.equal(result.outcome, "failed");
  assert.equal(result.reason, "policy_decision_unavailable");
}

function testRbacCatalog() {
  for (const permission of [
    "protection.read",
    "protection.manage",
    "enforcement_events.read",
    "rate_limits.manage",
    "blocklists.manage",
    "allowlists.manage",
    "credential_protection.manage",
  ]) {
    assert.ok(Object.values(PERMISSIONS).includes(permission));
  }
}

run();
