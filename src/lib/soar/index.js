import "server-only";

import crypto from "node:crypto";
import { and, desc, eq, gte, isNull, lte } from "drizzle-orm";
import { db } from "../../db/client.js";
import {
  alerts,
  automationRuns,
  correlationEvents,
  detectionFindings,
  enforcementEvents,
  evidenceItems,
  firewallInstances,
  incidents,
  investigationCases,
  notificationDeliveries,
  playbookSteps,
  policyDecisions,
  responseActions,
  securityEvents,
  securityPlaybooks,
  simulationResults,
  threatMatches,
} from "../../db/schema.js";
import { AUDIT_EVENT_TYPES, createAuditEvent } from "../audit/index.js";

export const SOAR_AUTOMATION_LEVELS = Object.freeze({
  OBSERVE: 0,
  RECOMMEND: 1,
  EXECUTE_LOW_RISK: 2,
  REQUIRE_APPROVAL: 3,
  EMERGENCY: 4,
});

export const SOAR_ACTION_TYPES = Object.freeze({
  BLOCK_INDICATOR: "block_indicator",
  CREATE_INCIDENT: "create_incident",
  NOTIFY_SECURITY_TEAM: "notify_security_team",
  REQUEST_APPROVAL: "request_approval",
  COLLECT_EVIDENCE: "collect_evidence",
  QUARANTINE_API_KEY: "quarantine_api_key",
  SUSPEND_SERVICE_ACCOUNT: "suspend_service_account",
  INCREASE_RATE_LIMIT_RESTRICTION: "increase_rate_limit_restriction",
});

export const SOAR_TRIGGER_TYPES = Object.freeze({
  SECURITY_EVENT: "security_event",
  DETECTION_FINDING: "detection_finding",
  CORRELATION_EVENT: "correlation_event",
  THREAT_MATCH: "threat_match",
  POLICY_DECISION: "policy_decision",
  ENFORCEMENT_EVENT: "enforcement_event",
  INCIDENT: "incident",
  NOTIFICATION_DELIVERY: "notification_delivery",
  SIMULATION_RESULT: "simulation_result",
  MANUAL: "manual",
});

const RUN_STATUSES = ["queued", "running", "approval_required", "completed", "failed", "cancelled", "skipped"];
const APPROVAL_STATES = ["not_required", "pending", "approved", "rejected", "expired"];
const PLAYBOOK_STATUSES = ["draft", "testing", "active", "disabled", "deleted"];
const RESPONSE_STATUSES = ["recommended", "pending", "approval_required", "approved", "executing", "completed", "failed", "skipped", "rolled_back"];
const CASE_STATUSES = ["open", "investigating", "contained", "resolved", "closed"];
const RISK_LEVELS = ["low", "medium", "high", "critical"];
const HIGH_IMPACT_ACTIONS = new Set([
  SOAR_ACTION_TYPES.BLOCK_INDICATOR,
  SOAR_ACTION_TYPES.QUARANTINE_API_KEY,
  SOAR_ACTION_TYPES.SUSPEND_SERVICE_ACCOUNT,
  SOAR_ACTION_TYPES.INCREASE_RATE_LIMIT_RESTRICTION,
]);
const SAFE_EXECUTION_ACTIONS = new Set([
  SOAR_ACTION_TYPES.CREATE_INCIDENT,
  SOAR_ACTION_TYPES.COLLECT_EVIDENCE,
  SOAR_ACTION_TYPES.NOTIFY_SECURITY_TEAM,
]);
const SENSITIVE_KEY = /password|secret|token|credential|authorization|cookie|session|private[_-]?key|api[_-]?key|body|payload|query/i;
const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;

export async function listSecurityPlaybooks({ database = db(), organizationId, filters = {} } = {}) {
  const query = await normalizeQuery({ database, organizationId, filters });
  const predicates = [eq(securityPlaybooks.organizationId, organizationId), isNull(securityPlaybooks.deletedAt)];
  if (query.firewallInstanceId) predicates.push(eq(securityPlaybooks.firewallInstanceId, query.firewallInstanceId));
  if (query.status) predicates.push(eq(securityPlaybooks.status, query.status));
  if (query.triggerType) predicates.push(eq(securityPlaybooks.triggerType, query.triggerType));

  const rows = await database
    .select()
    .from(securityPlaybooks)
    .where(and(...predicates))
    .orderBy(desc(securityPlaybooks.updatedAt))
    .limit(query.limit);

  return { items: rows.map(presentPlaybook), pageInfo: { limit: query.limit, hasMore: rows.length === query.limit } };
}

export async function createSecurityPlaybook({
  database = db(),
  organizationId,
  userId,
  input = {},
  auditContext = {},
} = {}) {
  const values = await normalizePlaybookInput({ database, organizationId, userId, input });
  const [playbook] = await database.insert(securityPlaybooks).values(values.playbook).returning();

  if (values.steps.length) {
    await database.insert(playbookSteps).values(values.steps.map((step) => ({ ...step, playbookId: playbook.id })));
  }

  await auditSoar({
    database,
    organizationId,
    userId,
    firewallInstanceId: playbook.firewallInstanceId,
    eventType: AUDIT_EVENT_TYPES.SOAR_PLAYBOOK_CREATED,
    action: "soar.playbook.create",
    resourceType: "security_playbook",
    resourceId: playbook.id,
    requestId: auditContext.requestId,
    metadata: { triggerType: playbook.triggerType, automationLevel: playbook.automationLevel, requiresApproval: playbook.requiresApproval },
  });

  return getSecurityPlaybook({ database, organizationId, playbookId: playbook.id });
}

export async function getSecurityPlaybook({ database = db(), organizationId, playbookId } = {}) {
  const playbook = await requirePlaybook(database, organizationId, requiredString(playbookId, "playbookId", 160));
  const steps = await database
    .select()
    .from(playbookSteps)
    .where(and(eq(playbookSteps.organizationId, organizationId), eq(playbookSteps.playbookId, playbook.id)))
    .orderBy(playbookSteps.stepOrder)
    .limit(100);
  return { ...presentPlaybook(playbook), steps: steps.map(presentPlaybookStep) };
}

export async function listAutomationRuns({ database = db(), organizationId, filters = {} } = {}) {
  const query = await normalizeQuery({ database, organizationId, filters, includeWindow: true });
  const predicates = [
    eq(automationRuns.organizationId, organizationId),
    gte(automationRuns.startedAt, query.since),
    lte(automationRuns.startedAt, query.until),
  ];
  if (query.firewallInstanceId) predicates.push(eq(automationRuns.firewallInstanceId, query.firewallInstanceId));
  if (query.status) predicates.push(eq(automationRuns.status, query.status));
  if (query.playbookId) predicates.push(eq(automationRuns.playbookId, query.playbookId));

  const rows = await database
    .select()
    .from(automationRuns)
    .where(and(...predicates))
    .orderBy(desc(automationRuns.startedAt))
    .limit(query.limit);

  return { items: rows.map(presentAutomationRun), pageInfo: { limit: query.limit, hasMore: rows.length === query.limit } };
}

export async function triggerAutomationRun({
  database = db(),
  organizationId,
  userId,
  input = {},
  auditContext = {},
} = {}) {
  const playbook = await requirePlaybook(database, organizationId, requiredString(input.playbookId, "playbookId", 160));
  if (!["active", "testing"].includes(playbook.status)) throw new Error("playbook is not executable");

  const trigger = await normalizeTrigger({ database, organizationId, input });
  const idempotencyKey = buildAutomationIdempotencyKey({ organizationId, playbookId: playbook.id, trigger });
  const existing = await findExistingRun(database, organizationId, idempotencyKey);
  if (existing && !input.force) return { ...presentAutomationRun(existing), duplicate: true };

  const steps = await database
    .select()
    .from(playbookSteps)
    .where(and(eq(playbookSteps.organizationId, organizationId), eq(playbookSteps.playbookId, playbook.id), eq(playbookSteps.status, "active")))
    .orderBy(playbookSteps.stepOrder)
    .limit(100);
  const planned = planResponseActions({ playbook, steps, trigger, requestedByUserId: userId });
  const runStatus = planned.requiresApproval ? "approval_required" : planned.actions.some((action) => action.status === "completed") ? "completed" : "skipped";
  const approvalState = planned.requiresApproval ? "pending" : "not_required";
  const now = new Date();

  const [run] = await database
    .insert(automationRuns)
    .values({
      organizationId,
      firewallInstanceId: trigger.firewallInstanceId || playbook.firewallInstanceId || null,
      playbookId: playbook.id,
      incidentId: trigger.refs.incidentId,
      alertId: trigger.refs.alertId,
      securityEventId: trigger.refs.securityEventId,
      detectionFindingId: trigger.refs.detectionFindingId,
      correlationEventId: trigger.refs.correlationEventId,
      threatMatchId: trigger.refs.threatMatchId,
      policyDecisionId: trigger.refs.policyDecisionId,
      enforcementEventId: trigger.refs.enforcementEventId,
      notificationDeliveryId: trigger.refs.notificationDeliveryId,
      simulationResultId: trigger.refs.simulationResultId,
      triggerType: trigger.triggerType,
      triggerFingerprint: trigger.fingerprint,
      status: runStatus,
      automationLevel: playbook.automationLevel,
      approvalState,
      idempotencyKey,
      playbookVersion: playbook.version,
      startedByUserId: userId || null,
      completedAt: runStatus === "completed" || runStatus === "skipped" ? now : null,
      resultSummary: planned.summary,
      evidenceSummary: sanitizeMetadata({ triggerType: trigger.triggerType, actions: planned.actions.length, requiresApproval: planned.requiresApproval }),
      metadata: sanitizeMetadata({ matched: true, playbookName: playbook.name }),
    })
    .returning();

  let createdIncidentId = trigger.refs.incidentId || null;
  const createdActions = [];
  for (const action of planned.actions) {
    const rowInput = { ...action, automationRunId: run.id, incidentId: createdIncidentId || action.incidentId || null };
    if (action.actionType === SOAR_ACTION_TYPES.CREATE_INCIDENT && action.status === "completed" && !createdIncidentId) {
      const incident = await createIncidentForAutomation({ database, organizationId, userId, playbook, trigger, runId: run.id });
      createdIncidentId = incident.id;
      rowInput.incidentId = incident.id;
      rowInput.executionResult = sanitizeMetadata({ ...(rowInput.executionResult || {}), incidentId: incident.id });
    }
    const [created] = await database.insert(responseActions).values(rowInput).returning();
    createdActions.push(created);
  }

  if (createdIncidentId && createdIncidentId !== run.incidentId) {
    await database
      .update(automationRuns)
      .set({ incidentId: createdIncidentId, updatedAt: new Date() })
      .where(eq(automationRuns.id, run.id));
  }

  await collectEvidence({
    database,
    organizationId,
    userId,
    input: {
      firewallInstanceId: trigger.firewallInstanceId || playbook.firewallInstanceId || null,
      automationRunId: run.id,
      incidentId: createdIncidentId,
      sourceType: trigger.triggerType,
      sourceRefId: trigger.sourceId,
      evidenceType: "automation_trigger",
      metadata: { playbookId: playbook.id, trigger: trigger.context, planned },
    },
    auditContext,
  });

  await auditSoar({
    database,
    organizationId,
    userId,
    firewallInstanceId: trigger.firewallInstanceId || playbook.firewallInstanceId || null,
    eventType: AUDIT_EVENT_TYPES.SOAR_AUTOMATION_EXECUTED,
    action: "soar.automation.run",
    resourceType: "automation_run",
    resourceId: run.id,
    requestId: auditContext.requestId,
    metadata: { status: runStatus, approvalState, actionCount: createdActions.length },
  });

  return {
    ...presentAutomationRun({ ...run, incidentId: createdIncidentId }),
    actions: createdActions.map(presentResponseAction),
  };
}

export async function listResponseActions({ database = db(), organizationId, filters = {} } = {}) {
  const query = await normalizeQuery({ database, organizationId, filters, includeWindow: true });
  const predicates = [eq(responseActions.organizationId, organizationId), gte(responseActions.createdAt, query.since), lte(responseActions.createdAt, query.until)];
  if (query.firewallInstanceId) predicates.push(eq(responseActions.firewallInstanceId, query.firewallInstanceId));
  if (query.status) predicates.push(eq(responseActions.status, query.status));
  if (query.actionType) predicates.push(eq(responseActions.actionType, query.actionType));
  if (query.automationRunId) predicates.push(eq(responseActions.automationRunId, query.automationRunId));

  const rows = await database.select().from(responseActions).where(and(...predicates)).orderBy(desc(responseActions.createdAt)).limit(query.limit);
  return { items: rows.map(presentResponseAction), pageInfo: { limit: query.limit, hasMore: rows.length === query.limit } };
}

export async function createManualResponseAction({
  database = db(),
  organizationId,
  userId,
  input = {},
  auditContext = {},
} = {}) {
  const firewallInstanceId = cleanString(input.firewallInstanceId, 160);
  if (firewallInstanceId) await validateFirewallOwnership(database, organizationId, firewallInstanceId);
  const actionType = enumValue(input.actionType, Object.values(SOAR_ACTION_TYPES), "action type");
  const riskLevel = enumValue(input.riskLevel || inferActionRisk(actionType), RISK_LEVELS, "risk level");
  const approvalRequired = isHighImpactAction({ actionType, riskLevel });
  const idempotencyKey = cleanString(input.idempotencyKey, 160) || buildHash({ organizationId, actionType, targetType: input.targetType, targetRef: input.targetRef, reason: input.reason });
  const [row] = await database
    .insert(responseActions)
    .values({
      organizationId,
      firewallInstanceId,
      actionType,
      targetType: cleanString(input.targetType, 80),
      targetRef: cleanString(input.targetRef, 240),
      status: approvalRequired ? "approval_required" : "recommended",
      approvalState: approvalRequired ? "pending" : "not_required",
      riskLevel,
      idempotencyKey,
      reason: requiredString(input.reason, "reason", 2000),
      requestedByUserId: userId || null,
      executionResult: sanitizeMetadata({ recommendedOnly: true }),
      rollbackPlan: sanitizeMetadata(input.rollbackPlan || {}),
    })
    .returning();
  await auditSoar({
    database,
    organizationId,
    userId,
    firewallInstanceId,
    eventType: AUDIT_EVENT_TYPES.SOAR_ACTION_EXECUTED,
    action: "soar.response_action.create",
    resourceType: "response_action",
    resourceId: row.id,
    requestId: auditContext.requestId,
    metadata: { actionType, status: row.status, approvalState: row.approvalState },
  });
  return presentResponseAction(row);
}

export async function listInvestigationCases({ database = db(), organizationId, filters = {} } = {}) {
  const query = await normalizeQuery({ database, organizationId, filters, includeWindow: true });
  const predicates = [
    eq(investigationCases.organizationId, organizationId),
    gte(investigationCases.lastSeenAt, query.since),
    lte(investigationCases.lastSeenAt, query.until),
  ];
  if (query.firewallInstanceId) predicates.push(eq(investigationCases.firewallInstanceId, query.firewallInstanceId));
  if (query.status) predicates.push(eq(investigationCases.status, query.status));

  const rows = await database
    .select()
    .from(investigationCases)
    .where(and(...predicates))
    .orderBy(desc(investigationCases.lastSeenAt))
    .limit(query.limit);
  return { items: rows.map(presentInvestigationCase), pageInfo: { limit: query.limit, hasMore: rows.length === query.limit } };
}

export async function createInvestigationCase({
  database = db(),
  organizationId,
  userId,
  input = {},
  auditContext = {},
} = {}) {
  const values = await normalizeInvestigationInput({ database, organizationId, userId, input });
  const [row] = await database.insert(investigationCases).values(values).returning();
  await auditSoar({
    database,
    organizationId,
    userId,
    firewallInstanceId: row.firewallInstanceId,
    eventType: AUDIT_EVENT_TYPES.SOAR_INVESTIGATION_CREATED,
    action: "soar.investigation.create",
    resourceType: "investigation_case",
    resourceId: row.id,
    requestId: auditContext.requestId,
    metadata: { severity: row.severity, status: row.status },
  });
  return presentInvestigationCase(row);
}

export async function listEvidenceItems({ database = db(), organizationId, filters = {} } = {}) {
  const query = await normalizeQuery({ database, organizationId, filters, includeWindow: true });
  const predicates = [eq(evidenceItems.organizationId, organizationId), isNull(evidenceItems.deletedAt), gte(evidenceItems.occurredAt, query.since), lte(evidenceItems.occurredAt, query.until)];
  if (query.firewallInstanceId) predicates.push(eq(evidenceItems.firewallInstanceId, query.firewallInstanceId));
  if (query.investigationCaseId) predicates.push(eq(evidenceItems.investigationCaseId, query.investigationCaseId));
  if (query.automationRunId) predicates.push(eq(evidenceItems.automationRunId, query.automationRunId));
  if (query.sourceType) predicates.push(eq(evidenceItems.sourceType, query.sourceType));

  const rows = await database.select().from(evidenceItems).where(and(...predicates)).orderBy(desc(evidenceItems.occurredAt)).limit(query.limit);
  return { items: rows.map(presentEvidenceItem), pageInfo: { limit: query.limit, hasMore: rows.length === query.limit } };
}

export async function collectEvidence({
  database = db(),
  organizationId,
  userId,
  input = {},
  auditContext = {},
} = {}) {
  const values = await normalizeEvidenceInput({ database, organizationId, userId, input });
  const [row] = await database.insert(evidenceItems).values(values).returning();
  await auditSoar({
    database,
    organizationId,
    userId,
    firewallInstanceId: row.firewallInstanceId,
    eventType: AUDIT_EVENT_TYPES.SOAR_EVIDENCE_COLLECTED,
    action: "soar.evidence.collect",
    resourceType: "evidence_item",
    resourceId: row.id,
    requestId: auditContext.requestId,
    metadata: { sourceType: row.sourceType, evidenceType: row.evidenceType },
  });
  return presentEvidenceItem(row);
}

export function evaluatePlaybookTrigger({ playbook = {}, trigger = {} } = {}) {
  if (!playbook || !trigger) return false;
  if (playbook.triggerType && playbook.triggerType !== trigger.triggerType) return false;
  const conditions = sanitizeMetadata(playbook.triggerConditions || {});
  const context = sanitizeMetadata(trigger.context || trigger);
  return Object.entries(conditions).every(([key, expected]) => {
    if (expected == null || expected === "" || key === "any") return true;
    if (key === "minRiskScore") return Number(context.riskScore || context.score || 0) >= Number(expected);
    if (key === "severity") return String(context.severity || "").toLowerCase() === String(expected).toLowerCase();
    if (key === "detectorId") return (context.detectorIds || []).includes(expected) || context.detectorId === expected;
    return context[key] === expected;
  });
}

export function planResponseActions({ playbook = {}, steps = [], trigger = {}, requestedByUserId = null } = {}) {
  const actions = [];
  let requiresApproval = Boolean(playbook.requiresApproval);
  const automationLevel = Number(playbook.automationLevel ?? SOAR_AUTOMATION_LEVELS.RECOMMEND);

  for (const step of steps.length ? steps : normalizeActionSequence(playbook.actionSequence || [])) {
    const actionType = enumValue(step.actionType, Object.values(SOAR_ACTION_TYPES), "action type");
    const riskLevel = enumValue(step.riskLevel || inferActionRisk(actionType), RISK_LEVELS, "risk level");
    const highImpact = isHighImpactAction({ actionType, riskLevel });
    const approvalRequired = Boolean(step.approvalRequired || playbook.requiresApproval || highImpact || automationLevel === SOAR_AUTOMATION_LEVELS.REQUIRE_APPROVAL);
    if (approvalRequired) requiresApproval = true;

    const status = actionStatusFor({ automationLevel, actionType, approvalRequired });
    const approvalState = approvalRequired ? "pending" : "not_required";
    actions.push({
      organizationId: playbook.organizationId,
      firewallInstanceId: trigger.firewallInstanceId || playbook.firewallInstanceId || null,
      playbookStepId: step.id || null,
      policyDecisionId: trigger.refs?.policyDecisionId || null,
      enforcementEventId: trigger.refs?.enforcementEventId || null,
      actionType,
      targetType: cleanString(step.targetType || trigger.targetType || trigger.triggerType, 80),
      targetRef: cleanString(step.targetRef || trigger.sourceId, 240),
      status,
      approvalState,
      riskLevel,
      idempotencyKey: buildHash({ playbookId: playbook.id, trigger: trigger.fingerprint, actionType, order: step.stepOrder || actions.length + 1 }),
      reason: cleanString(step.reason || playbook.description || `SOAR ${actionType} from ${trigger.triggerType}`, 2000) || "SOAR action recommendation",
      requestedByUserId,
      executionResult: sanitizeMetadata({
        simulatedExternalSideEffects: true,
        executedInternalOnly: status === "completed",
        triggerType: trigger.triggerType,
      }),
      rollbackPlan: sanitizeMetadata(step.rollbackConfiguration || step.rollbackPlan || playbook.rollbackPlan || {}),
      executedAt: status === "completed" ? new Date() : null,
      completedAt: status === "completed" || status === "skipped" || status === "recommended" ? new Date() : null,
    });
  }

  return {
    actions,
    requiresApproval,
    summary: `${actions.length} response action${actions.length === 1 ? "" : "s"} planned; ${requiresApproval ? "approval required" : "no approval required"}`,
  };
}

export function sanitizeEvidenceMetadata(value) {
  return sanitizeMetadata(value);
}

export function buildAutomationIdempotencyKey({ organizationId, playbookId, trigger } = {}) {
  return buildHash({ organizationId, playbookId, triggerType: trigger?.triggerType, triggerSource: trigger?.sourceId || trigger?.fingerprint });
}

async function normalizePlaybookInput({ database, organizationId, userId, input }) {
  const firewallInstanceId = cleanString(input.firewallInstanceId, 160);
  if (firewallInstanceId) await validateFirewallOwnership(database, organizationId, firewallInstanceId);
  const actionSequence = normalizeActionSequence(input.actionSequence || input.actions || []);
  const automationLevel = numberInRange(input.automationLevel ?? SOAR_AUTOMATION_LEVELS.RECOMMEND, 0, 4, "automation level");
  const riskLevel = enumValue(input.riskLevel || maxRiskLevel(actionSequence), RISK_LEVELS, "risk level");
  const requiresApproval = input.requiresApproval ?? (
    automationLevel >= SOAR_AUTOMATION_LEVELS.REQUIRE_APPROVAL ||
    actionSequence.some((action) => isHighImpactAction(action))
  );
  const triggerType = enumValue(input.triggerType || SOAR_TRIGGER_TYPES.MANUAL, Object.values(SOAR_TRIGGER_TYPES), "trigger type");

  return {
    playbook: {
      organizationId,
      firewallInstanceId,
      name: requiredString(input.name, "name", 160),
      description: cleanString(input.description, 2000),
      triggerType,
      triggerConditions: sanitizeMetadata(input.triggerConditions || {}),
      automationLevel,
      riskLevel,
      requiresApproval,
      actionSequence,
      rollbackPlan: sanitizeMetadata(input.rollbackPlan || {}),
      status: enumValue(input.status || "draft", PLAYBOOK_STATUSES, "playbook status"),
      version: numberInRange(input.version || 1, 1, 10000, "version"),
      maxRunsPerHour: numberInRange(input.maxRunsPerHour || 20, 1, 500, "max runs per hour"),
      cooldownSeconds: numberInRange(input.cooldownSeconds ?? 300, 0, 86400, "cooldown seconds"),
      createdByUserId: userId || null,
      metadata: sanitizeMetadata(input.metadata || {}),
    },
    steps: actionSequence.map((action, index) => ({
      organizationId,
      stepOrder: index + 1,
      name: cleanString(action.name, 160) || titleForAction(action.actionType),
      actionType: action.actionType,
      approvalRequired: Boolean(action.approvalRequired || isHighImpactAction(action)),
      configuration: sanitizeMetadata(action.configuration || {}),
      rollbackConfiguration: sanitizeMetadata(action.rollbackConfiguration || action.rollbackPlan || {}),
      timeoutSeconds: numberInRange(action.timeoutSeconds || 30, 1, 3600, "timeout seconds"),
      maxAttempts: numberInRange(action.maxAttempts || 1, 1, 10, "max attempts"),
      status: "active",
    })),
  };
}

function normalizeActionSequence(actions) {
  const list = Array.isArray(actions) ? actions.slice(0, 25) : [];
  return list.map((action) => ({
    actionType: enumValue(action.actionType || action.type, Object.values(SOAR_ACTION_TYPES), "action type"),
    name: cleanString(action.name, 160),
    targetType: cleanString(action.targetType, 80),
    targetRef: cleanString(action.targetRef, 240),
    riskLevel: enumValue(action.riskLevel || inferActionRisk(action.actionType || action.type), RISK_LEVELS, "risk level"),
    approvalRequired: Boolean(action.approvalRequired),
    reason: cleanString(action.reason, 2000),
    configuration: sanitizeMetadata(action.configuration || {}),
    rollbackConfiguration: sanitizeMetadata(action.rollbackConfiguration || action.rollbackPlan || {}),
    timeoutSeconds: numberInRange(action.timeoutSeconds || 30, 1, 3600, "timeout seconds"),
    maxAttempts: numberInRange(action.maxAttempts || 1, 1, 10, "max attempts"),
  }));
}

async function normalizeTrigger({ database, organizationId, input }) {
  const triggerType = enumValue(input.triggerType || SOAR_TRIGGER_TYPES.MANUAL, Object.values(SOAR_TRIGGER_TYPES), "trigger type");
  const sourceId = cleanString(input.sourceId || input[`${camelCase(triggerType)}Id`], 160);
  const source = sourceId ? await requireSource(database, organizationId, triggerType, sourceId) : null;
  const context = sanitizeMetadata({ ...(source || {}), ...(input.context || {}) });
  const firewallInstanceId = cleanString(input.firewallInstanceId || source?.firewallInstanceId, 160);
  if (firewallInstanceId) await validateFirewallOwnership(database, organizationId, firewallInstanceId);
  return {
    triggerType,
    sourceId: sourceId || null,
    firewallInstanceId,
    targetType: cleanString(input.targetType, 80),
    context,
    fingerprint: buildHash({ triggerType, sourceId, context }),
    refs: refsForTrigger(triggerType, sourceId),
  };
}

async function normalizeInvestigationInput({ database, organizationId, userId, input }) {
  const firewallInstanceId = cleanString(input.firewallInstanceId, 160);
  if (firewallInstanceId) await validateFirewallOwnership(database, organizationId, firewallInstanceId);
  const incidentId = cleanString(input.incidentId, 160);
  if (incidentId) await requireIncident(database, organizationId, incidentId);
  const automationRunId = cleanString(input.automationRunId, 160);
  if (automationRunId) await requireAutomationRun(database, organizationId, automationRunId);
  const now = new Date();
  return {
    organizationId,
    firewallInstanceId,
    incidentId,
    automationRunId,
    title: requiredString(input.title, "title", 240),
    summary: cleanString(input.summary, 4000),
    severity: enumValue(input.severity || "medium", RISK_LEVELS, "severity"),
    status: enumValue(input.status || "open", CASE_STATUSES, "case status"),
    assignedToUserId: cleanString(input.assignedToUserId, 160),
    createdByUserId: userId || null,
    firstSeenAt: parseDate(input.firstSeenAt) || now,
    lastSeenAt: parseDate(input.lastSeenAt) || now,
    slaDueAt: parseDate(input.slaDueAt),
    metadata: sanitizeMetadata(input.metadata || {}),
  };
}

async function normalizeEvidenceInput({ database, organizationId, userId, input }) {
  const firewallInstanceId = cleanString(input.firewallInstanceId, 160);
  if (firewallInstanceId) await validateFirewallOwnership(database, organizationId, firewallInstanceId);
  const investigationCaseId = cleanString(input.investigationCaseId || input.caseId, 160);
  if (investigationCaseId) await requireInvestigationCase(database, organizationId, investigationCaseId);
  const incidentId = cleanString(input.incidentId, 160);
  if (incidentId) await requireIncident(database, organizationId, incidentId);
  const automationRunId = cleanString(input.automationRunId, 160);
  if (automationRunId) await requireAutomationRun(database, organizationId, automationRunId);
  const responseActionId = cleanString(input.responseActionId, 160);
  if (responseActionId) await requireResponseAction(database, organizationId, responseActionId);
  const metadata = sanitizeMetadata(input.metadata || {});
  return {
    organizationId,
    firewallInstanceId,
    investigationCaseId,
    incidentId,
    automationRunId,
    responseActionId,
    sourceType: enumValue(input.sourceType || SOAR_TRIGGER_TYPES.MANUAL, [...Object.values(SOAR_TRIGGER_TYPES), "simulation_result", "automation_run", "response_action"], "source type"),
    sourceRefId: cleanString(input.sourceRefId, 160),
    evidenceType: requiredString(input.evidenceType || "sanitized_metadata", "evidenceType", 80),
    evidenceHash: buildHash(metadata),
    occurredAt: parseDate(input.occurredAt) || new Date(),
    collectedByUserId: userId || null,
    retentionClass: enumValue(input.retentionClass || "incident_1y", ["incident_90d", "incident_1y", "audit_1y", "customer_policy"], "retention class"),
    metadata,
  };
}

async function createIncidentForAutomation({ database, organizationId, userId, playbook, trigger, runId }) {
  const now = new Date();
  const [row] = await database
    .insert(incidents)
    .values({
      organizationId,
      firewallInstanceId: trigger.firewallInstanceId || playbook.firewallInstanceId || null,
      title: `SOAR: ${playbook.name}`,
      summary: cleanString(`Created by SOAR playbook from ${trigger.triggerType}`, 2000),
      severity: enumValue(playbook.riskLevel || trigger.context?.severity || "medium", RISK_LEVELS, "severity"),
      status: "open",
      createdByUserId: userId || null,
      firstSeenAt: now,
      lastSeenAt: now,
      metadata: sanitizeMetadata({ automationRunId: runId, playbookId: playbook.id, triggerType: trigger.triggerType }),
    })
    .returning();
  return row;
}

async function requireSource(database, organizationId, triggerType, sourceId) {
  const table = sourceTable(triggerType);
  if (!table) return null;
  const [row] = await database.select().from(table).where(and(eq(table.id, sourceId), eq(table.organizationId, organizationId))).limit(1);
  if (!row) throw new Error(`${triggerType} source not found`);
  return row;
}

function sourceTable(triggerType) {
  return {
    [SOAR_TRIGGER_TYPES.SECURITY_EVENT]: securityEvents,
    [SOAR_TRIGGER_TYPES.DETECTION_FINDING]: detectionFindings,
    [SOAR_TRIGGER_TYPES.CORRELATION_EVENT]: correlationEvents,
    [SOAR_TRIGGER_TYPES.THREAT_MATCH]: threatMatches,
    [SOAR_TRIGGER_TYPES.POLICY_DECISION]: policyDecisions,
    [SOAR_TRIGGER_TYPES.ENFORCEMENT_EVENT]: enforcementEvents,
    [SOAR_TRIGGER_TYPES.INCIDENT]: incidents,
    [SOAR_TRIGGER_TYPES.NOTIFICATION_DELIVERY]: notificationDeliveries,
    [SOAR_TRIGGER_TYPES.SIMULATION_RESULT]: simulationResults,
  }[triggerType];
}

function refsForTrigger(triggerType, sourceId) {
  const refs = {
    incidentId: null,
    alertId: null,
    securityEventId: null,
    detectionFindingId: null,
    correlationEventId: null,
    threatMatchId: null,
    policyDecisionId: null,
    enforcementEventId: null,
    notificationDeliveryId: null,
    simulationResultId: null,
  };
  if (!sourceId) return refs;
  const key = {
    [SOAR_TRIGGER_TYPES.SECURITY_EVENT]: "securityEventId",
    [SOAR_TRIGGER_TYPES.DETECTION_FINDING]: "detectionFindingId",
    [SOAR_TRIGGER_TYPES.CORRELATION_EVENT]: "correlationEventId",
    [SOAR_TRIGGER_TYPES.THREAT_MATCH]: "threatMatchId",
    [SOAR_TRIGGER_TYPES.POLICY_DECISION]: "policyDecisionId",
    [SOAR_TRIGGER_TYPES.ENFORCEMENT_EVENT]: "enforcementEventId",
    [SOAR_TRIGGER_TYPES.INCIDENT]: "incidentId",
    [SOAR_TRIGGER_TYPES.NOTIFICATION_DELIVERY]: "notificationDeliveryId",
    [SOAR_TRIGGER_TYPES.SIMULATION_RESULT]: "simulationResultId",
  }[triggerType];
  if (key) refs[key] = sourceId;
  return refs;
}

async function validateFirewallOwnership(database, organizationId, firewallInstanceId) {
  const [firewall] = await database
    .select({ id: firewallInstances.id })
    .from(firewallInstances)
    .where(and(eq(firewallInstances.id, firewallInstanceId), eq(firewallInstances.organizationId, organizationId), isNull(firewallInstances.deletedAt)))
    .limit(1);
  if (!firewall) throw new Error("firewall instance is not available for this organization");
  return firewall;
}

async function requirePlaybook(database, organizationId, playbookId) {
  const [row] = await database
    .select()
    .from(securityPlaybooks)
    .where(and(eq(securityPlaybooks.id, playbookId), eq(securityPlaybooks.organizationId, organizationId), isNull(securityPlaybooks.deletedAt)))
    .limit(1);
  if (!row) throw new Error("security playbook not found");
  return row;
}

async function requireIncident(database, organizationId, incidentId) {
  const [row] = await database.select({ id: incidents.id }).from(incidents).where(and(eq(incidents.id, incidentId), eq(incidents.organizationId, organizationId))).limit(1);
  if (!row) throw new Error("incident not found");
  return row;
}

async function requireAutomationRun(database, organizationId, runId) {
  const [row] = await database.select({ id: automationRuns.id }).from(automationRuns).where(and(eq(automationRuns.id, runId), eq(automationRuns.organizationId, organizationId))).limit(1);
  if (!row) throw new Error("automation run not found");
  return row;
}

async function requireResponseAction(database, organizationId, actionId) {
  const [row] = await database.select({ id: responseActions.id }).from(responseActions).where(and(eq(responseActions.id, actionId), eq(responseActions.organizationId, organizationId))).limit(1);
  if (!row) throw new Error("response action not found");
  return row;
}

async function requireInvestigationCase(database, organizationId, caseId) {
  const [row] = await database.select({ id: investigationCases.id }).from(investigationCases).where(and(eq(investigationCases.id, caseId), eq(investigationCases.organizationId, organizationId))).limit(1);
  if (!row) throw new Error("investigation case not found");
  return row;
}

async function findExistingRun(database, organizationId, idempotencyKey) {
  const [row] = await database
    .select()
    .from(automationRuns)
    .where(and(eq(automationRuns.organizationId, organizationId), eq(automationRuns.idempotencyKey, idempotencyKey)))
    .limit(1);
  return row || null;
}

async function normalizeQuery({ database, organizationId, filters = {}, includeWindow = false }) {
  const firewallInstanceId = cleanString(filters.firewallInstanceId, 160);
  if (firewallInstanceId) await validateFirewallOwnership(database, organizationId, firewallInstanceId);
  const until = includeWindow ? parseDate(filters.until) || new Date() : null;
  const since = includeWindow ? parseDate(filters.since) || new Date(until.getTime() - 7 * 24 * 60 * 60 * 1000) : null;
  if (includeWindow && since > until) throw new Error("since must be before until");
  return {
    firewallInstanceId,
    status: cleanString(filters.status, 32),
    triggerType: cleanString(filters.triggerType, 40),
    playbookId: cleanString(filters.playbookId, 160),
    actionType: cleanString(filters.actionType, 48),
    automationRunId: cleanString(filters.automationRunId, 160),
    investigationCaseId: cleanString(filters.investigationCaseId || filters.caseId, 160),
    sourceType: cleanString(filters.sourceType, 48),
    since,
    until,
    limit: limitValue(filters.limit, MAX_LIMIT),
  };
}

function actionStatusFor({ automationLevel, actionType, approvalRequired }) {
  if (automationLevel <= SOAR_AUTOMATION_LEVELS.OBSERVE) return "skipped";
  if (automationLevel === SOAR_AUTOMATION_LEVELS.RECOMMEND) return "recommended";
  if (approvalRequired || automationLevel === SOAR_AUTOMATION_LEVELS.REQUIRE_APPROVAL) return "approval_required";
  if (automationLevel === SOAR_AUTOMATION_LEVELS.EXECUTE_LOW_RISK && SAFE_EXECUTION_ACTIONS.has(actionType)) return "completed";
  if (automationLevel === SOAR_AUTOMATION_LEVELS.EMERGENCY && !HIGH_IMPACT_ACTIONS.has(actionType)) return "completed";
  return "approval_required";
}

function isHighImpactAction({ actionType, riskLevel }) {
  return HIGH_IMPACT_ACTIONS.has(actionType) || ["high", "critical"].includes(riskLevel);
}

function inferActionRisk(actionType) {
  return HIGH_IMPACT_ACTIONS.has(actionType) ? "high" : "low";
}

function maxRiskLevel(actions) {
  const weight = { low: 1, medium: 2, high: 3, critical: 4 };
  return actions.reduce((max, action) => (weight[action.riskLevel] > weight[max] ? action.riskLevel : max), "low");
}

async function auditSoar({
  database,
  organizationId,
  userId,
  firewallInstanceId,
  eventType,
  action,
  resourceType,
  resourceId,
  requestId,
  metadata,
} = {}) {
  return createAuditEvent({
    database,
    organizationId,
    userId,
    firewallInstanceId,
    eventType,
    action,
    resourceType,
    resourceId,
    result: "success",
    severity: "info",
    requestId,
    metadata: sanitizeMetadata(metadata || {}),
  });
}

function presentPlaybook(row = {}) {
  return {
    id: row.id,
    organizationId: row.organizationId,
    firewallInstanceId: row.firewallInstanceId,
    name: row.name,
    description: row.description,
    triggerType: row.triggerType,
    automationLevel: row.automationLevel,
    riskLevel: row.riskLevel,
    requiresApproval: row.requiresApproval,
    status: row.status,
    version: row.version,
    maxRunsPerHour: row.maxRunsPerHour,
    cooldownSeconds: row.cooldownSeconds,
    lastRunAt: row.lastRunAt,
    updatedAt: row.updatedAt,
  };
}

function presentPlaybookStep(row = {}) {
  return {
    id: row.id,
    stepOrder: row.stepOrder,
    name: row.name,
    actionType: row.actionType,
    approvalRequired: row.approvalRequired,
    status: row.status,
  };
}

function presentAutomationRun(row = {}) {
  return {
    id: row.id,
    playbookId: row.playbookId,
    incidentId: row.incidentId,
    triggerType: row.triggerType,
    status: row.status,
    automationLevel: row.automationLevel,
    approvalState: row.approvalState,
    playbookVersion: row.playbookVersion,
    resultSummary: row.resultSummary,
    startedAt: row.startedAt,
    completedAt: row.completedAt,
    duplicate: row.duplicate,
  };
}

function presentResponseAction(row = {}) {
  return {
    id: row.id,
    automationRunId: row.automationRunId,
    incidentId: row.incidentId,
    actionType: row.actionType,
    targetType: row.targetType,
    targetRef: row.targetRef,
    status: row.status,
    approvalState: row.approvalState,
    riskLevel: row.riskLevel,
    reason: row.reason,
    executedAt: row.executedAt,
    completedAt: row.completedAt,
    createdAt: row.createdAt,
  };
}

function presentInvestigationCase(row = {}) {
  return {
    id: row.id,
    incidentId: row.incidentId,
    automationRunId: row.automationRunId,
    title: row.title,
    summary: row.summary,
    severity: row.severity,
    status: row.status,
    assignedToUserId: row.assignedToUserId,
    lastSeenAt: row.lastSeenAt,
    slaDueAt: row.slaDueAt,
    createdAt: row.createdAt,
  };
}

function presentEvidenceItem(row = {}) {
  return {
    id: row.id,
    investigationCaseId: row.investigationCaseId,
    incidentId: row.incidentId,
    automationRunId: row.automationRunId,
    responseActionId: row.responseActionId,
    sourceType: row.sourceType,
    sourceRefId: row.sourceRefId,
    evidenceType: row.evidenceType,
    evidenceHash: row.evidenceHash,
    occurredAt: row.occurredAt,
    retentionClass: row.retentionClass,
  };
}

function titleForAction(actionType) {
  return String(actionType || "response action").replaceAll("_", " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function buildHash(value) {
  return crypto.createHash("sha256").update(JSON.stringify(sanitizeMetadata(value || {}))).digest("hex");
}

function sanitizeMetadata(value, depth = 0) {
  if (value == null) return value;
  if (depth > 4) return "[truncated]";
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => sanitizeMetadata(item, depth + 1));
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .slice(0, 100)
        .filter(([key]) => !SENSITIVE_KEY.test(key))
        .map(([key, child]) => [cleanString(key, 80), sanitizeMetadata(child, depth + 1)]),
    );
  }
  if (typeof value === "string") return cleanString(value, 1000);
  if (typeof value === "number") return Number.isFinite(value) ? value : 0;
  if (typeof value === "boolean") return value;
  return String(value);
}

function enumValue(value, allowed, label) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!allowed.includes(normalized)) throw new Error(`${label} is invalid`);
  return normalized;
}

function numberInRange(value, min, max, label) {
  const number = Number(value);
  if (!Number.isFinite(number) || number < min || number > max) throw new Error(`${label} is invalid`);
  return Math.floor(number);
}

function requiredString(value, label, maxLength) {
  const text = cleanString(value, maxLength);
  if (!text) throw new Error(`${label} is required`);
  return text;
}

function cleanString(value, maxLength) {
  if (value === null || value === undefined) return "";
  return String(value).replace(/[^\x20-\x7E]/g, "").trim().slice(0, maxLength);
}

function limitValue(value, max) {
  const number = Number(value || DEFAULT_LIMIT);
  if (!Number.isFinite(number)) return DEFAULT_LIMIT;
  return Math.max(1, Math.min(max, Math.floor(number)));
}

function parseDate(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function camelCase(value) {
  return String(value || "").replace(/_([a-z])/g, (_, char) => char.toUpperCase());
}
