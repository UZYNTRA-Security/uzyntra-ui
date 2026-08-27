import assert from "node:assert/strict";
import {
  ZERO_TRUST_DECISIONS,
  ZERO_TRUST_FAIL_BEHAVIORS,
  ZERO_TRUST_MODES,
  buildZeroTrustEvaluationContext,
  evaluateZeroTrustPolicy,
  normalizePolicySnapshot,
} from "../src/lib/zero-trust/index.js";

function run() {
  testDecisionActions();
  testModeTranslation();
  testFailBehavior();
  testEmergencyBypass();
  testSensitiveContextRedaction();
  testPolicyBounds();
  testDeterminism();
  console.log("test:zero-trust passed");
}

function testDecisionActions() {
  for (const decision of Object.values(ZERO_TRUST_DECISIONS)) {
    const result = evaluateZeroTrustPolicy({
      policy: {
        id: `policy-${decision}`,
        organizationId: "org-1",
        mode: ZERO_TRUST_MODES.ENFORCE,
        failBehavior: ZERO_TRUST_FAIL_BEHAVIORS.FAIL_OPEN,
      },
      policyVersion: {
        id: `version-${decision}`,
        policySnapshot: {
          defaultDecision: ZERO_TRUST_DECISIONS.ALLOW,
          rules: [
            {
              id: `rule-${decision}`,
              name: `Rule ${decision}`,
              decision,
              reason: `decision ${decision}`,
              conditions: [{ field: "risk_score", operator: "gte", value: 10 }],
            },
          ],
        },
      },
      context: { organizationId: "org-1", riskScore: 80, confidence: 0.9 },
    });
    assert.equal(result.decision, decision);
    assert.equal(result.effectiveDecision, decision);
    assert.equal(result.matchedRuleId, `rule-${decision}`);
  }
}

function testModeTranslation() {
  const base = {
    policyVersion: {
      policySnapshot: {
        defaultDecision: ZERO_TRUST_DECISIONS.BLOCK,
        rules: [],
      },
    },
    context: { organizationId: "org-1", riskScore: 99 },
  };

  const observe = evaluateZeroTrustPolicy({
    ...base,
    policy: { organizationId: "org-1", mode: ZERO_TRUST_MODES.OBSERVE, failBehavior: ZERO_TRUST_FAIL_BEHAVIORS.FAIL_OPEN },
  });
  assert.equal(observe.decision, ZERO_TRUST_DECISIONS.BLOCK);
  assert.equal(observe.effectiveDecision, ZERO_TRUST_DECISIONS.ALLOW);

  const simulate = evaluateZeroTrustPolicy({
    ...base,
    policy: { organizationId: "org-1", mode: ZERO_TRUST_MODES.SIMULATE, failBehavior: ZERO_TRUST_FAIL_BEHAVIORS.FAIL_OPEN },
  });
  assert.equal(simulate.decision, ZERO_TRUST_DECISIONS.BLOCK);
  assert.equal(simulate.effectiveDecision, ZERO_TRUST_DECISIONS.ALLOW);
}

function testFailBehavior() {
  const badVersion = {
    policySnapshot: {
      defaultDecision: "invalid",
      rules: [],
    },
  };

  const open = evaluateZeroTrustPolicy({
    policy: { organizationId: "org-1", mode: ZERO_TRUST_MODES.ENFORCE, failBehavior: ZERO_TRUST_FAIL_BEHAVIORS.FAIL_OPEN },
    policyVersion: badVersion,
    context: { organizationId: "org-1", riskScore: 100 },
  });
  assert.equal(open.decision, ZERO_TRUST_DECISIONS.ALLOW);

  const closed = evaluateZeroTrustPolicy({
    policy: { organizationId: "org-1", mode: ZERO_TRUST_MODES.ENFORCE, failBehavior: ZERO_TRUST_FAIL_BEHAVIORS.FAIL_CLOSED },
    policyVersion: badVersion,
    context: { organizationId: "org-1", riskScore: 100 },
  });
  assert.equal(closed.decision, ZERO_TRUST_DECISIONS.BLOCK);
}

function testEmergencyBypass() {
  const result = evaluateZeroTrustPolicy({
    policy: { organizationId: "org-1", mode: ZERO_TRUST_MODES.ENFORCE, failBehavior: ZERO_TRUST_FAIL_BEHAVIORS.FAIL_CLOSED },
    policyVersion: {
      policySnapshot: { defaultDecision: ZERO_TRUST_DECISIONS.BLOCK, rules: [] },
    },
    emergencyBypass: {
      id: "bypass-1",
      status: "active",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    },
    context: { organizationId: "org-1", riskScore: 100 },
  });
  assert.equal(result.decision, ZERO_TRUST_DECISIONS.ALLOW);
  assert.equal(result.enforcementMetadata.bypassId, "bypass-1");
}

function testSensitiveContextRedaction() {
  const context = buildZeroTrustEvaluationContext({
    riskScore: 70,
    requestContext: {
      path: "/api/orders",
      authorization: "Bearer should-not-appear",
      headers: { cookie: "nope", accept: "json" },
    },
    identityContext: {
      type: "api_key",
      apiKey: "plain-secret",
      fingerprint: "fp-1",
    },
    threatContext: {
      token: "secret",
      reputation: "scanner",
    },
  });
  const serialized = JSON.stringify(context);
  assert.equal(serialized.includes("should-not-appear"), false);
  assert.equal(serialized.includes("plain-secret"), false);
  assert.equal(serialized.includes("cookie"), false);
  assert.equal(context.identityType, "api_key");
  assert.equal(context.threatReputation, "scanner");
}

function testPolicyBounds() {
  const rules = Array.from({ length: 51 }, (_, index) => ({
    id: `rule-${index}`,
    name: `Rule ${index}`,
    decision: ZERO_TRUST_DECISIONS.ALLOW,
    conditions: [],
  }));
  assert.throws(() => normalizePolicySnapshot({ defaultDecision: "allow", rules }), /rule count exceeds limit/);
  assert.throws(
    () =>
      normalizePolicySnapshot({
        defaultDecision: "allow",
        rules: [{ name: "bad", decision: "block", conditions: [{ field: "body", operator: "contains", value: "secret" }] }],
      }),
    /condition field is invalid/,
  );
}

function testDeterminism() {
  const input = {
    policy: { organizationId: "org-1", mode: ZERO_TRUST_MODES.ENFORCE, failBehavior: ZERO_TRUST_FAIL_BEHAVIORS.FAIL_OPEN },
    policyVersion: {
      id: "version-1",
      policySnapshot: {
        defaultDecision: ZERO_TRUST_DECISIONS.ALLOW,
        rules: [
          {
            id: "scanner-block",
            name: "Scanner block",
            decision: ZERO_TRUST_DECISIONS.BLOCK,
            reason: "scanner with elevated risk",
            conditions: [
              { field: "threat_reputation", operator: "eq", value: "scanner" },
              { field: "risk_score", operator: "gte", value: 80 },
            ],
          },
        ],
      },
    },
    context: {
      organizationId: "org-1",
      riskScore: 84,
      confidence: 0.77,
      threatReputation: "scanner",
      detectorIds: ["abuse.scanner"],
    },
  };

  const first = evaluateZeroTrustPolicy(input);
  const second = evaluateZeroTrustPolicy(input);
  assert.deepEqual(first, second);
  assert.equal(first.decision, ZERO_TRUST_DECISIONS.BLOCK);
}

run();
