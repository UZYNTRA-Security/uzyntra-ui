import "server-only";

import { PERMISSIONS } from "../rbac/catalog.js";
import { errorResponse, json, jsonError, readJson, requirePermission, searchParams } from "../alerts/api.js";
import {
  activateZeroTrustPolicyVersion,
  createEmergencyBypass,
  createZeroTrustPolicy,
  createZeroTrustPolicyVersion,
  getZeroTrustPolicy,
  listEmergencyBypasses,
  listPolicyDecisions,
  listZeroTrustPolicies,
  rollbackZeroTrustPolicy,
  simulateZeroTrustPolicy,
} from "./index.js";

export async function requireZeroTrustPermission({ database, request, operation, method }) {
  const permission =
    operation === "decisions"
      ? PERMISSIONS.POLICY_DECISIONS_READ
      : operation === "simulator"
        ? PERMISSIONS.POLICY_SIMULATION_RUN
        : operation === "bypass"
          ? method === "GET"
            ? PERMISSIONS.POLICY_READ
            : PERMISSIONS.EMERGENCY_BYPASS_MANAGE
          : method === "GET"
            ? PERMISSIONS.POLICY_READ
            : PERMISSIONS.POLICY_UPDATE;

  return requirePermission({
    database,
    request,
    permission,
    route: `zero-trust/${operation}`,
    method,
  });
}

export async function handlePolicyList({ request, database, identity, requestId } = {}) {
  try {
    const filters = applyActiveFirewallScope(identity, searchParams(request));
    const data = await listZeroTrustPolicies({ database, organizationId: identity.organizationId, filters });
    return json({ success: true, data }, 200, requestId);
  } catch (error) {
    return scopedError(error, requestId);
  }
}

export async function handlePolicyCreate({ request, database, identity, requestId } = {}) {
  try {
    const body = await readJson(request);
    const input = applyActiveFirewallScope(identity, body);
    const data = await createZeroTrustPolicy({
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

export async function handlePolicyGet({ database, identity, requestId, policyId } = {}) {
  try {
    const data = await getZeroTrustPolicy({ database, organizationId: identity.organizationId, policyId });
    if (identity.activeFirewallInstanceId && data.firewallInstanceId && data.firewallInstanceId !== identity.activeFirewallInstanceId) {
      return jsonError("Forbidden", 403, requestId);
    }
    return json({ success: true, data }, 200, requestId);
  } catch (error) {
    return scopedError(error, requestId);
  }
}

export async function handlePolicyVersionCreate({ request, database, identity, requestId, policyId } = {}) {
  try {
    const body = await readJson(request);
    const data = await createZeroTrustPolicyVersion({
      database,
      organizationId: identity.organizationId,
      userId: identity.userId,
      policyId,
      input: body,
      auditContext: { requestId },
    });
    return json({ success: true, data }, 201, requestId);
  } catch (error) {
    return scopedError(error, requestId);
  }
}

export async function handlePolicyActivate({ request, database, identity, requestId, policyId } = {}) {
  try {
    const body = await readJson(request);
    const data = await activateZeroTrustPolicyVersion({
      database,
      organizationId: identity.organizationId,
      userId: identity.userId,
      policyId,
      versionId: body.versionId,
      auditContext: { requestId },
    });
    return json({ success: true, data }, 200, requestId);
  } catch (error) {
    return scopedError(error, requestId);
  }
}

export async function handlePolicyRollback({ request, database, identity, requestId, policyId } = {}) {
  try {
    const body = await readJson(request);
    const data = await rollbackZeroTrustPolicy({
      database,
      organizationId: identity.organizationId,
      userId: identity.userId,
      policyId,
      targetVersionId: body.targetVersionId || body.versionId,
      auditContext: { requestId },
    });
    return json({ success: true, data }, 200, requestId);
  } catch (error) {
    return scopedError(error, requestId);
  }
}

export async function handleDecisionList({ request, database, identity, requestId } = {}) {
  try {
    const filters = applyActiveFirewallScope(identity, searchParams(request));
    const data = await listPolicyDecisions({ database, organizationId: identity.organizationId, filters });
    return json({ success: true, data }, 200, requestId);
  } catch (error) {
    return scopedError(error, requestId);
  }
}

export async function handlePolicySimulation({ request, database, identity, requestId } = {}) {
  try {
    const body = await readJson(request);
    const input = applyActiveFirewallScope(identity, body);
    const data = await simulateZeroTrustPolicy({
      database,
      organizationId: identity.organizationId,
      userId: identity.userId,
      input,
      auditContext: { requestId },
    });
    return json({ success: true, data }, 200, requestId);
  } catch (error) {
    return scopedError(error, requestId);
  }
}

export async function handleEmergencyBypassList({ request, database, identity, requestId } = {}) {
  try {
    const filters = applyActiveFirewallScope(identity, searchParams(request));
    const data = await listEmergencyBypasses({ database, organizationId: identity.organizationId, filters });
    return json({ success: true, data }, 200, requestId);
  } catch (error) {
    return scopedError(error, requestId);
  }
}

export async function handleEmergencyBypassCreate({ request, database, identity, requestId } = {}) {
  try {
    const body = await readJson(request);
    const input = applyActiveFirewallScope(identity, body);
    const data = await createEmergencyBypass({
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
