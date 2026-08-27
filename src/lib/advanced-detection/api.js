import "server-only";

import { PERMISSIONS } from "../rbac/catalog.js";
import { errorResponse, json, jsonError, readJson, requirePermission, searchParams } from "../alerts/api.js";
import {
  createDetectorFeedback,
  getRiskAnalysis,
  listCorrelationEvents,
  listDetectionFindings,
  listDetectorConfigurations,
  upsertDetectorConfiguration,
} from "./index.js";

export async function handleAdvancedDetectionList({
  request,
  database,
  operation,
  identity,
  requestId,
} = {}) {
  try {
    const filters = applyActiveFirewallScope(identity, searchParams(request));
    const data =
      operation === "detections"
        ? await listDetectionFindings({ database, organizationId: identity.organizationId, filters })
        : operation === "correlations"
          ? await listCorrelationEvents({ database, organizationId: identity.organizationId, filters })
          : operation === "risk"
            ? await getRiskAnalysis({ database, organizationId: identity.organizationId, filters })
            : await listDetectorConfigurations({ database, organizationId: identity.organizationId, filters });

    return json({ success: true, data }, 200, requestId);
  } catch (error) {
    if (/firewall scope/i.test(error?.message || "")) {
      return jsonError("Forbidden", 403, requestId);
    }
    return errorResponse(error, requestId);
  }
}

export async function handleDetectorConfigurationUpsert({
  request,
  database,
  identity,
  requestId,
} = {}) {
  try {
    const body = await readJson(request);
    const input = applyActiveFirewallScope(identity, body);
    const data = await upsertDetectorConfiguration({
      database,
      organizationId: identity.organizationId,
      userId: identity.userId,
      input,
      auditContext: { requestId },
    });
    return json({ success: true, data }, 200, requestId);
  } catch (error) {
    if (/firewall scope/i.test(error?.message || "")) {
      return jsonError("Forbidden", 403, requestId);
    }
    return errorResponse(error, requestId);
  }
}

export async function handleDetectorFeedbackCreate({
  request,
  database,
  identity,
  requestId,
} = {}) {
  try {
    const body = await readJson(request);
    const input = applyActiveFirewallScope(identity, body);
    const data = await createDetectorFeedback({
      database,
      organizationId: identity.organizationId,
      userId: identity.userId,
      input,
      auditContext: { requestId },
    });
    return json({ success: true, data }, 201, requestId);
  } catch (error) {
    if (/firewall scope/i.test(error?.message || "")) {
      return jsonError("Forbidden", 403, requestId);
    }
    return errorResponse(error, requestId);
  }
}

export async function requireAdvancedDetectionPermission({ database, request, operation, method }) {
  const permission =
    operation === "risk"
      ? PERMISSIONS.METRICS_READ
      : operation === "rules" || operation === "feedback"
        ? method === "GET"
          ? PERMISSIONS.ALERTS_READ
          : PERMISSIONS.ALERTS_MANAGE
        : PERMISSIONS.EVENTS_READ;

  return requirePermission({
    database,
    request,
    permission,
    route: `advanced-detection/${operation}`,
    method,
  });
}

function applyActiveFirewallScope(identity, input = {}) {
  if (!identity?.activeFirewallInstanceId) return { ...input };
  if (input.firewallInstanceId && input.firewallInstanceId !== identity.activeFirewallInstanceId) {
    throw new Error("firewall scope is not available");
  }
  return { ...input, firewallInstanceId: identity.activeFirewallInstanceId };
}
