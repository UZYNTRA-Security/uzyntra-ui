import "server-only";

import { PERMISSIONS } from "../rbac/catalog.js";
import { errorResponse, json, jsonError, readJson, requirePermission, searchParams } from "../alerts/api.js";
import {
  createPolicyChangeRequest,
  createPolicyTestCase,
  explainPolicyDecision,
  listPolicyChangeRequests,
  listPolicySimulations,
  listPolicyTestCases,
  runPolicySimulation,
  runPolicyTestCase,
} from "./index.js";

export async function requirePolicySimulationPermission({ database, request, operation, method }) {
  const permission = permissionFor(operation, method);
  return requirePermission({
    database,
    request,
    permission,
    route: `policy-simulation/${operation}`,
    method,
  });
}

export async function handleSimulationList({ request, database, identity, requestId } = {}) {
  try {
    const filters = applyActiveFirewallScope(identity, searchParams(request));
    const data = await listPolicySimulations({ database, organizationId: identity.organizationId, filters });
    return json({ success: true, data }, 200, requestId);
  } catch (error) {
    return scopedError(error, requestId);
  }
}

export async function handleSimulationRun({ request, database, identity, requestId } = {}) {
  try {
    const body = await readJson(request);
    const input = applyActiveFirewallScope(identity, body);
    const data = await runPolicySimulation({
      database,
      organizationId: identity.organizationId,
      userId: identity.userId,
      input,
      auditContext: { requestId },
    });
    return json({ success: true, data }, 201, requestId);
  } catch (error) {
    return scopedError(error, requestId);
  }
}

export async function handleDecisionExplain({ request, database, identity, requestId } = {}) {
  try {
    const params = searchParams(request);
    const data = await explainPolicyDecision({
      database,
      organizationId: identity.organizationId,
      decisionId: params.decisionId || params.id,
    });
    return json({ success: true, data }, 200, requestId);
  } catch (error) {
    return scopedError(error, requestId);
  }
}

export async function handleTestCaseList({ request, database, identity, requestId } = {}) {
  try {
    const filters = applyActiveFirewallScope(identity, searchParams(request));
    const data = await listPolicyTestCases({ database, organizationId: identity.organizationId, filters });
    return json({ success: true, data }, 200, requestId);
  } catch (error) {
    return scopedError(error, requestId);
  }
}

export async function handleTestCaseCreate({ request, database, identity, requestId } = {}) {
  try {
    const body = await readJson(request);
    const input = applyActiveFirewallScope(identity, body);
    const data = body.run
      ? await runPolicyTestCase({
          database,
          organizationId: identity.organizationId,
          userId: identity.userId,
          testCaseId: body.testCaseId || body.id,
          auditContext: { requestId },
        })
      : await createPolicyTestCase({
          database,
          organizationId: identity.organizationId,
          userId: identity.userId,
          input,
          auditContext: { requestId },
        });
    return json({ success: true, data }, 201, requestId);
  } catch (error) {
    return scopedError(error, requestId);
  }
}

export async function handleChangeRequestList({ request, database, identity, requestId } = {}) {
  try {
    const filters = applyActiveFirewallScope(identity, searchParams(request));
    const data = await listPolicyChangeRequests({ database, organizationId: identity.organizationId, filters });
    return json({ success: true, data }, 200, requestId);
  } catch (error) {
    return scopedError(error, requestId);
  }
}

export async function handleChangeRequestCreate({ request, database, identity, requestId } = {}) {
  try {
    const body = await readJson(request);
    const input = applyActiveFirewallScope(identity, body);
    const data = await createPolicyChangeRequest({
      database,
      organizationId: identity.organizationId,
      userId: identity.userId,
      input,
      auditContext: { requestId },
    });
    return json({ success: true, data }, 201, requestId);
  } catch (error) {
    return scopedError(error, requestId);
  }
}

function permissionFor(operation, method) {
  if (operation === "decisions") return PERMISSIONS.POLICY_DECISIONS_READ;
  if (operation === "test-cases") return method === "GET" ? PERMISSIONS.POLICY_SIMULATION_READ : PERMISSIONS.POLICY_TESTS_MANAGE;
  if (operation === "change-requests") return method === "GET" ? PERMISSIONS.POLICY_SIMULATION_READ : PERMISSIONS.POLICY_APPROVALS_MANAGE;
  if (method === "GET") return PERMISSIONS.POLICY_SIMULATION_READ;
  return PERMISSIONS.POLICY_SIMULATION_RUN;
}

function applyActiveFirewallScope(identity, input = {}) {
  if (!identity?.activeFirewallInstanceId) return { ...input };
  if (input.firewallInstanceId && input.firewallInstanceId !== identity.activeFirewallInstanceId) {
    throw new Error("firewall scope is not available");
  }
  return { ...input, firewallInstanceId: identity.activeFirewallInstanceId };
}

function scopedError(error, requestId) {
  if (/firewall scope|not available for this organization/i.test(error?.message || "")) {
    return jsonError("Forbidden", 403, requestId);
  }
  return errorResponse(error, requestId);
}
