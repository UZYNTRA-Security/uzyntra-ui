import "server-only";

import { PERMISSIONS } from "../rbac/catalog.js";
import { errorResponse, json, jsonError, readJson, requirePermission, searchParams } from "../alerts/api.js";
import {
  createCredentialProtection,
  createProtectionListEntry,
  createProtectionRule,
  createRateLimitPolicy,
  listCredentialProtection,
  listEnforcementEvents,
  listProtectionList,
  listProtectionRules,
  listRateLimitPolicies,
  simulateAdaptiveProtection,
} from "./index.js";

export async function requireProtectionPermission({ database, request, operation, method }) {
  const permission =
    operation === "events"
      ? PERMISSIONS.ENFORCEMENT_EVENTS_READ
      : operation === "simulate"
        ? PERMISSIONS.POLICY_SIMULATION_RUN
        : operation === "rate-limits"
          ? method === "GET"
            ? PERMISSIONS.PROTECTION_READ
            : PERMISSIONS.RATE_LIMITS_MANAGE
          : operation === "blocklists"
            ? method === "GET"
              ? PERMISSIONS.PROTECTION_READ
              : PERMISSIONS.BLOCKLISTS_MANAGE
            : operation === "allowlists"
              ? method === "GET"
                ? PERMISSIONS.PROTECTION_READ
                : PERMISSIONS.ALLOWLISTS_MANAGE
              : operation === "credential-protection"
                ? method === "GET"
                  ? PERMISSIONS.PROTECTION_READ
                  : PERMISSIONS.CREDENTIAL_PROTECTION_MANAGE
                : method === "GET"
                  ? PERMISSIONS.PROTECTION_READ
                  : PERMISSIONS.PROTECTION_MANAGE;

  return requirePermission({
    database,
    request,
    permission,
    route: `adaptive-protection/${operation}`,
    method,
  });
}

export async function handleProtectionList({ request, database, identity, requestId } = {}) {
  try {
    const filters = applyActiveFirewallScope(identity, searchParams(request));
    const data = await listProtectionRules({ database, organizationId: identity.organizationId, filters });
    return json({ success: true, data }, 200, requestId);
  } catch (error) {
    return scopedError(error, requestId);
  }
}

export async function handleProtectionCreate({ request, database, identity, requestId } = {}) {
  try {
    const body = await readJson(request);
    const input = applyActiveFirewallScope(identity, body);
    const data = await createProtectionRule({
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

export async function handleEnforcementEvents({ request, database, identity, requestId } = {}) {
  try {
    const filters = applyActiveFirewallScope(identity, searchParams(request));
    const data = await listEnforcementEvents({ database, organizationId: identity.organizationId, filters });
    return json({ success: true, data }, 200, requestId);
  } catch (error) {
    return scopedError(error, requestId);
  }
}

export async function handleProtectionSimulation({ request, database, identity, requestId } = {}) {
  try {
    const body = await readJson(request);
    const input = applyActiveFirewallScope(identity, body);
    const data = await simulateAdaptiveProtection({
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

export async function handleRateLimitList({ request, database, identity, requestId } = {}) {
  try {
    const filters = applyActiveFirewallScope(identity, searchParams(request));
    const data = await listRateLimitPolicies({ database, organizationId: identity.organizationId, filters });
    return json({ success: true, data }, 200, requestId);
  } catch (error) {
    return scopedError(error, requestId);
  }
}

export async function handleRateLimitCreate({ request, database, identity, requestId } = {}) {
  try {
    const body = await readJson(request);
    const input = applyActiveFirewallScope(identity, body);
    const data = await createRateLimitPolicy({
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

export async function handleProtectionListRead({ request, database, identity, requestId, listType } = {}) {
  try {
    const filters = applyActiveFirewallScope(identity, searchParams(request));
    const data = await listProtectionList({ database, organizationId: identity.organizationId, listType, filters });
    return json({ success: true, data }, 200, requestId);
  } catch (error) {
    return scopedError(error, requestId);
  }
}

export async function handleProtectionListCreate({ request, database, identity, requestId, listType } = {}) {
  try {
    const body = await readJson(request);
    const input = applyActiveFirewallScope(identity, body);
    const data = await createProtectionListEntry({
      database,
      organizationId: identity.organizationId,
      userId: identity.userId,
      listType,
      input,
      auditContext: { requestId },
    });
    return json({ success: true, data }, 201, requestId);
  } catch (error) {
    return scopedError(error, requestId);
  }
}

export async function handleCredentialProtectionList({ request, database, identity, requestId } = {}) {
  try {
    const filters = applyActiveFirewallScope(identity, searchParams(request));
    const data = await listCredentialProtection({ database, organizationId: identity.organizationId, filters });
    return json({ success: true, data }, 200, requestId);
  } catch (error) {
    return scopedError(error, requestId);
  }
}

export async function handleCredentialProtectionCreate({ request, database, identity, requestId } = {}) {
  try {
    const body = await readJson(request);
    const input = applyActiveFirewallScope(identity, body);
    const data = await createCredentialProtection({
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
