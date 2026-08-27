import assert from "node:assert/strict";
import {
  POLICY_SIMULATION_MODES,
  evaluatePolicySimulation,
} from "../src/lib/policy-simulation/index.js";
import { PERMISSIONS } from "../src/lib/rbac/catalog.js";

function run() {
  testDryRunNeverEnforces();
  testShadowModeDecisionExplanation();
  testWhatIfAdaptiveProtection();
  testHistoricalReplayShape();
  testRegressionFields();
  testRollbackVersionSelection();
  testSensitivePayloadRedaction();
  testMalformedPoliciesFailClosedSafely();
  testRbacCatalog();
  console.log("test:policy-simulation passed");
}

function basePolicy() {
  return {
    id: "policy-1",
    organizationId: "org-1",
    firewallInstanceId: "fw-1",
    failBehavior: "fail_closed",
  };
}

function baseVersion(overrides = {}) {
  return {
    id: overrides.id || "version-1",
    policySnapshot: {
      defaultDecision: "allow",
      rules: [
        {
          id: "critical-risk",
          name: "Critical risk",
          decision: "block",
          reason: "critical risk threshold",
          conditions: [{ field: "risk_score", operator: "gte", value: 90 }],
        },
      ],
      ...(overrides.policySnapshot || {}),
    },
  };
}

function baseContext(overrides = {}) {
  return {
    organizationId: "org-1",
    firewallInstanceId: "fw-1",
    riskScore: 95,
    confidence: 0.94,
    severity: "critical",
    requestPath: "/api/admin/export",
    httpMethod: "POST",
    detectorIds: ["detector.recon"],
    threatReputation: "scanner",
    ...overrides,
  };
}

function testDryRunNeverEnforces() {
  const result = evaluatePolicySimulation({
    policy: basePolicy(),
    policyVersion: baseVersion(),
    context: baseContext(),
    mode: POLICY_SIMULATION_MODES.DRY_RUN,
  });
  assert.equal(result.expectedDecision, "block");
  assert.equal(result.expectedAction, "block");
  assert.equal(result.effectiveAction, "allow");
  assert.equal(result.enforced, false);
  assert.equal(result.simulated, true);
}

function testShadowModeDecisionExplanation() {
  const result = evaluatePolicySimulation({
    policy: basePolicy(),
    policyVersion: baseVersion(),
    context: baseContext({ riskScore: 72, confidence: 0.82 }),
    mode: POLICY_SIMULATION_MODES.SHADOW,
  });
  assert.equal(result.mode, "shadow");
  assert.equal(result.expectedDecision, "allow");
  assert.ok(result.explanation.summary.includes("not modified"));
  assert.ok(result.reasonCodes.includes("default_policy_decision"));
}

function testWhatIfAdaptiveProtection() {
  const result = evaluatePolicySimulation({
    policy: basePolicy(),
    policyVersion: baseVersion({ policySnapshot: { rules: [] } }),
    context: baseContext({ riskScore: 80 }),
    protectionRules: [
      {
        id: "challenge-rule",
        status: "active",
        action: "challenge",
        precedence: 100,
        reason: "sensitive route challenge",
        conditions: [{ field: "route", operator: "contains", value: "/api/admin" }],
      },
    ],
    mode: POLICY_SIMULATION_MODES.WHAT_IF,
  });
  assert.equal(result.expectedDecision, "allow");
  assert.equal(result.expectedAction, "challenge");
  assert.equal(result.matchedProtectionRuleId, "challenge-rule");
}

function testHistoricalReplayShape() {
  const result = evaluatePolicySimulation({
    policy: basePolicy(),
    policyVersion: baseVersion(),
    context: baseContext({ securityEventId: "event-1" }),
    actualAction: "allow",
    mode: POLICY_SIMULATION_MODES.HISTORICAL_REPLAY,
  });
  assert.equal(result.mode, "historical_replay");
  assert.equal(result.actualAction, "allow");
  assert.equal(result.explanation.sourcePolicyVersion, "version-1");
}

function testRegressionFields() {
  const result = evaluatePolicySimulation({
    policy: basePolicy(),
    policyVersion: baseVersion(),
    context: baseContext(),
  });
  assert.equal(result.expectedDecision, "block");
  assert.equal(result.expectedAction, "block");
  assert.ok(result.falsePositiveRisk >= 0);
  assert.ok(result.falsePositiveRisk <= 1);
}

function testRollbackVersionSelection() {
  const rolledBack = evaluatePolicySimulation({
    policy: basePolicy(),
    policyVersion: baseVersion({
      id: "version-rollback",
      policySnapshot: {
        defaultDecision: "allow",
        rules: [{ id: "rollback-rule", name: "Rollback allow", decision: "allow", conditions: [] }],
      },
    }),
    context: baseContext(),
  });
  assert.equal(rolledBack.policyVersionId, "version-rollback");
  assert.equal(rolledBack.expectedDecision, "allow");
}

function testSensitivePayloadRedaction() {
  const result = evaluatePolicySimulation({
    policy: basePolicy(),
    policyVersion: baseVersion(),
    context: baseContext({
      requestContext: {
        path: "/api/admin/export",
        authorization: "Bearer no",
        cookie: "also-no",
        body: "raw secret payload",
        safeHeader: "visible",
      },
    }),
  });
  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes("Bearer no"), false);
  assert.equal(serialized.includes("raw secret payload"), false);
  assert.equal(serialized.includes("authorization"), false);
}

function testMalformedPoliciesFailClosedSafely() {
  assert.throws(
    () =>
      evaluatePolicySimulation({
        policy: basePolicy(),
        policyVersion: { id: "bad", policySnapshot: { defaultDecision: "explode", rules: [] } },
        context: baseContext(),
      }),
    /default decision is invalid/,
  );
}

function testRbacCatalog() {
  for (const permission of [
    "policy_simulation.read",
    "policy_simulation.manage",
    "policy_tests.manage",
    "policy_approvals.manage",
    "policy_simulation.run",
  ]) {
    assert.ok(Object.values(PERMISSIONS).includes(permission));
  }
}

run();
