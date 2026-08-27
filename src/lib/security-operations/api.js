import "server-only";

import { db } from "../../db/client.js";
import {
  getAuthorizationContext,
  hasPermission,
  recordAuthorizationDecision,
} from "../authz/index.js";
import { PERMISSIONS } from "../rbac/catalog.js";
import {
  getNotificationHealth,
  getSecurityDashboard,
  getSecurityMetrics,
  getSecurityPosture,
  getSecurityTrends,
  getTopThreats,
  listNotificationDeliveries,
} from "./query.js";

const ROUTES = Object.freeze({
  dashboard: {
    route: "security/dashboard",
    permissions: [PERMISSIONS.METRICS_READ, PERMISSIONS.ALERTS_READ, PERMISSIONS.INCIDENTS_READ],
    query: getSecurityDashboard,
  },
  metrics: {
    route: "security/metrics",
    permissions: [PERMISSIONS.METRICS_READ],
    query: getSecurityMetrics,
  },
  trends: {
    route: "security/trends",
    permissions: [PERMISSIONS.METRICS_READ],
    query: getSecurityTrends,
  },
  posture: {
    route: "security/posture",
    permissions: [PERMISSIONS.METRICS_READ, PERMISSIONS.EVENTS_READ],
    query: getSecurityPosture,
  },
  topThreats: {
    route: "security/top-threats",
    permissions: [PERMISSIONS.EVENTS_READ],
    query: getTopThreats,
  },
  notificationDeliveries: {
    route: "security/notification-deliveries",
    permissions: [PERMISSIONS.ALERTS_READ, PERMISSIONS.INCIDENTS_READ],
    query: listNotificationDeliveries,
  },
  notificationHealth: {
    route: "security/notification-health",
    permissions: [PERMISSIONS.ALERTS_READ, PERMISSIONS.INCIDENTS_READ],
    query: getNotificationHealth,
  },
});

export async function handleSecurityOperationRequest({
  request,
  operation,
  database = db(),
  identity,
  resolveIdentity,
  authorizationContext,
  queryOperation,
} = {}) {
  const config = ROUTES[operation];
  const requestId = crypto.randomUUID();
  if (!config) return jsonError("Not found", 404, requestId);

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

  if (!hasAnyPermission(authzContext, config.permissions)) {
    recordDecision({
      result: "denied",
      identity: currentIdentity,
      route: config.route,
      permission: config.permissions.join("|"),
      requestId,
    });
    return jsonError("Forbidden", 403, requestId);
  }

  try {
    const filters = scopedFilters(request, currentIdentity);
    const query = queryOperation || config.query;
    const data = await query({
      database,
      organizationId: currentIdentity.organizationId,
      filters,
    });

    recordDecision({
      result: "allowed",
      identity: currentIdentity,
      route: config.route,
      permission: config.permissions.join("|"),
      requestId,
    });

    return json({ success: true, data }, 200, requestId);
  } catch (error) {
    const status = statusForError(error);
    if (status !== 403) {
      console.error(`Security operation ${config.route} failed`, error);
    }
    return jsonError(
      status === 403
        ? "Forbidden"
        : status === 400
          ? "invalid security operation query"
          : "security operation unavailable",
      status,
      requestId,
    );
  }
}

export function securityOperationConfig(operation) {
  return ROUTES[operation] || null;
}

function scopedFilters(request, identity) {
  const filters = Object.fromEntries(new URL(request.url).searchParams.entries());
  if (identity.activeFirewallInstanceId) {
    if (
      filters.firewallInstanceId &&
      filters.firewallInstanceId !== identity.activeFirewallInstanceId
    ) {
      throw new Error("Forbidden firewall scope");
    }
    filters.firewallInstanceId = identity.activeFirewallInstanceId;
  }
  return filters;
}

function hasAnyPermission(authzContext, permissions = []) {
  return permissions.some((permission) => hasPermission(authzContext, permission));
}

function recordDecision({ result, identity, route, permission, requestId }) {
  recordAuthorizationDecision({
    result,
    userId: identity.userId,
    organizationId: identity.organizationId,
    route,
    method: "GET",
    permission,
    requestId,
  });
}

function statusForError(error) {
  const message = error?.message || "";
  if (/forbidden/i.test(message)) return 403;
  if (/filter|date|status|bucket|limit|offset|cursor/i.test(message)) return 400;
  return 500;
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
