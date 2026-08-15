import "server-only";

import { db } from "../../db/client.js";
import {
  getAuthorizationContext,
  hasPermission,
  recordAuthorizationDecision,
} from "../authz/index.js";
import { PERMISSIONS } from "../rbac/catalog.js";
import { listApiInventoryRoutes } from "./index.js";

export async function handleApiInventoryRequest({
  request,
  database = db(),
  identity,
  resolveIdentity,
  authorizationContext,
  queryInventory = listApiInventoryRoutes,
} = {}) {
  const requestId = crypto.randomUUID();
  const currentIdentity =
    identity === undefined ? await resolveIdentity?.(database) : identity;
  if (!currentIdentity) {
    return jsonError("Unauthorized", 401, requestId);
  }

  const authzContext =
    authorizationContext === undefined
      ? await getAuthorizationContext({
          database,
          userId: currentIdentity.userId,
          organizationId: currentIdentity.organizationId,
        })
      : authorizationContext;

  if (!hasPermission(authzContext, PERMISSIONS.EVENTS_READ)) {
    recordInventoryAuthzDecision({
      result: "denied",
      identity: currentIdentity,
      permission: PERMISSIONS.EVENTS_READ,
      requestId,
    });
    return jsonError("Forbidden", 403, requestId);
  }

  try {
    const filters = Object.fromEntries(new URL(request.url).searchParams.entries());
    if (currentIdentity.activeFirewallInstanceId) {
      if (
        filters.firewallInstanceId &&
        filters.firewallInstanceId !== currentIdentity.activeFirewallInstanceId
      ) {
        return jsonError("Forbidden", 403, requestId);
      }
      filters.firewallInstanceId = currentIdentity.activeFirewallInstanceId;
    }

    const result = await queryInventory({
      database,
      organizationId: currentIdentity.organizationId,
      filters,
    });

    recordInventoryAuthzDecision({
      result: "allowed",
      identity: currentIdentity,
      permission: PERMISSIONS.EVENTS_READ,
      requestId,
    });

    return json({ success: true, data: result }, 200, requestId);
  } catch (error) {
    console.error("API inventory query failed", error);
    const status = /filter/i.test(error?.message || "") ? 400 : 500;
    return jsonError(status === 400 ? "invalid api inventory query" : "api inventory unavailable", status, requestId);
  }
}

function recordInventoryAuthzDecision({ result, identity, permission, requestId }) {
  recordAuthorizationDecision({
    result,
    userId: identity.userId,
    organizationId: identity.organizationId,
    route: "api-inventory",
    method: "GET",
    permission,
    requestId,
  });
}

function json(data, status, requestId) {
  return Response.json(data, {
    status,
    headers: {
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "x-request-id": requestId,
    },
  });
}

function jsonError(error, status, requestId) {
  return json({ error }, status, requestId);
}
