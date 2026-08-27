import assert from "node:assert/strict";
import {
  SOAR_ACTION_TYPES,
  SOAR_AUTOMATION_LEVELS,
  buildAutomationIdempotencyKey,
  evaluatePlaybookTrigger,
  planResponseActions,
  sanitizeEvidenceMetadata,
} from "../src/lib/soar/index.js";
import { AUDIT_EVENT_TYPES } from "../src/lib/audit/index.js";
import { PERMISSIONS } from "../src/lib/rbac/catalog.js";

function run() {
  testTriggerEvaluation();
  testSimulationResultTriggerSource();
  testRecommendationOnlyDoesNotExecute();
  testLowRiskExecution();
  testHighImpactRequiresApproval();
  testEvidenceSanitization();
  testIdempotencyKey();
  testRbacCatalog();
  testAuditCatalog();
  console.log("test:soar passed");
}

function basePlaybook(overrides = {}) {
  return {
    id: "playbook-1",
    organizationId: "org-1",
    firewallInstanceId: "fw-1",
    name: "Critical containment",
    description: "critical risk response",
    triggerType: "policy_decision",
    triggerConditions: { minRiskScore: 90, severity: "critical" },
    automationLevel: SOAR_AUTOMATION_LEVELS.RECOMMEND,
    requiresApproval: false,
    rollbackPlan: { note: "rollback through policy workflow" },
    ...overrides,
  };
}

function baseTrigger(overrides = {}) {
  return {
    triggerType: "policy_decision",
    sourceId: "decision-1",
    fingerprint: "fingerprint-1",
    firewallInstanceId: "fw-1",
    refs: { policyDecisionId: "decision-1", enforcementEventId: null },
    context: {
      riskScore: 95,
      severity: "critical",
      detectorIds: ["detector.recon"],
    },
    ...overrides,
  };
}

function testTriggerEvaluation() {
  assert.equal(evaluatePlaybookTrigger({ playbook: basePlaybook(), trigger: baseTrigger() }), true);
  assert.equal(
    evaluatePlaybookTrigger({
      playbook: basePlaybook({ triggerConditions: { minRiskScore: 99 } }),
      trigger: baseTrigger(),
    }),
    false,
  );
}

function testSimulationResultTriggerSource() {
  const playbook = basePlaybook({
    triggerType: "simulation_result",
    triggerConditions: { any: true },
  });
  const trigger = baseTrigger({
    triggerType: "simulation_result",
    sourceId: "simulation-result-1",
    refs: { simulationResultId: "simulation-result-1" },
  });
  assert.equal(evaluatePlaybookTrigger({ playbook, trigger }), true);
}

function testRecommendationOnlyDoesNotExecute() {
  const plan = planResponseActions({
    playbook: basePlaybook({ automationLevel: SOAR_AUTOMATION_LEVELS.RECOMMEND }),
    trigger: baseTrigger(),
    steps: [{ actionType: SOAR_ACTION_TYPES.CREATE_INCIDENT, riskLevel: "low" }],
  });
  assert.equal(plan.requiresApproval, false);
  assert.equal(plan.actions[0].status, "recommended");
  assert.equal(plan.actions[0].executionResult.executedInternalOnly, false);
}

function testLowRiskExecution() {
  const plan = planResponseActions({
    playbook: basePlaybook({ automationLevel: SOAR_AUTOMATION_LEVELS.EXECUTE_LOW_RISK }),
    trigger: baseTrigger(),
    steps: [{ actionType: SOAR_ACTION_TYPES.COLLECT_EVIDENCE, riskLevel: "low" }],
  });
  assert.equal(plan.requiresApproval, false);
  assert.equal(plan.actions[0].status, "completed");
  assert.equal(plan.actions[0].executionResult.simulatedExternalSideEffects, true);
}

function testHighImpactRequiresApproval() {
  const plan = planResponseActions({
    playbook: basePlaybook({ automationLevel: SOAR_AUTOMATION_LEVELS.EXECUTE_LOW_RISK }),
    trigger: baseTrigger(),
    steps: [{ actionType: SOAR_ACTION_TYPES.QUARANTINE_API_KEY, riskLevel: "high" }],
  });
  assert.equal(plan.requiresApproval, true);
  assert.equal(plan.actions[0].status, "approval_required");
  assert.equal(plan.actions[0].approvalState, "pending");
}

function testEvidenceSanitization() {
  const evidence = sanitizeEvidenceMetadata({
    authorization: "Bearer should-not-store",
    cookie: "nope",
    body: "raw request payload",
    safeSummary: "critical policy decision",
    nested: { apiKey: "also-no", detector: "detector.recon" },
  });
  const serialized = JSON.stringify(evidence);
  assert.equal(serialized.includes("should-not-store"), false);
  assert.equal(serialized.includes("raw request payload"), false);
  assert.equal(serialized.includes("apiKey"), false);
  assert.equal(evidence.safeSummary, "critical policy decision");
  assert.equal(evidence.nested.detector, "detector.recon");
}

function testIdempotencyKey() {
  const first = buildAutomationIdempotencyKey({
    organizationId: "org-1",
    playbookId: "playbook-1",
    trigger: baseTrigger(),
  });
  const second = buildAutomationIdempotencyKey({
    organizationId: "org-1",
    playbookId: "playbook-1",
    trigger: baseTrigger(),
  });
  assert.equal(first, second);
  assert.equal(first.length, 64);
}

function testRbacCatalog() {
  for (const permission of [
    "playbooks.read",
    "playbooks.manage",
    "automation_runs.read",
    "response_actions.read",
    "response_actions.manage",
    "investigations.read",
    "investigations.manage",
    "evidence.read",
  ]) {
    assert.ok(Object.values(PERMISSIONS).includes(permission));
  }
}

function testAuditCatalog() {
  for (const eventType of [
    "soar.playbook.created",
    "soar.automation.executed",
    "soar.action.executed",
    "soar.investigation.created",
    "soar.evidence.collected",
  ]) {
    assert.ok(Object.values(AUDIT_EVENT_TYPES).includes(eventType));
  }
}

run();
