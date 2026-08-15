import "server-only";

import { db } from "../../db/client.js";
import {
  getAuthorizationContext,
  hasPermission,
  recordAuthorizationDecision,
} from "../authz/index.js";
import { PERMISSIONS } from "../rbac/catalog.js";
import { getSecurityEventAnalytics, listSecurityEvents } from "./query.js";

export async function handleSecurityEventsRequest({
  request,
  database = db(),
  identity,
  resolveIdentity,
  authorizationContext,
  querySecurityEvents = listSecurityEvents,
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
    recordSecurityEventAuthzDecision({
      result: "denied",
      identity: currentIdentity,
      route: "security-events",
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
    const result = await querySecurityEvents({
      database,
      organizationId: currentIdentity.organizationId,
      filters,
    });

    recordSecurityEventAuthzDecision({
      result: "allowed",
      identity: currentIdentity,
      route: "security-events",
      permission: PERMISSIONS.EVENTS_READ,
      requestId,
    });

    return json(
      {
        success: true,
        data: {
          items: result.items.map(presentSecurityEvent),
          pageInfo: result.pageInfo,
          filters: result.filters,
        },
      },
      200,
      requestId,
    );
  } catch (error) {
    console.error("Security event query failed", error);
    return jsonError(statusForQueryError(error) === 400 ? "invalid security event query" : "security event query unavailable", statusForQueryError(error), requestId);
  }
}

export async function handleSecurityEventAnalyticsRequest({
  request,
  database = db(),
  identity,
  resolveIdentity,
  authorizationContext,
  queryAnalytics = getSecurityEventAnalytics,
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

  if (!hasPermission(authzContext, PERMISSIONS.METRICS_READ)) {
    recordSecurityEventAuthzDecision({
      result: "denied",
      identity: currentIdentity,
      route: "security-events/analytics",
      permission: PERMISSIONS.METRICS_READ,
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
    const analytics = await queryAnalytics({
      database,
      organizationId: currentIdentity.organizationId,
      filters,
    });

    recordSecurityEventAuthzDecision({
      result: "allowed",
      identity: currentIdentity,
      route: "security-events/analytics",
      permission: PERMISSIONS.METRICS_READ,
      requestId,
    });

    return json({ success: true, data: analytics }, 200, requestId);
  } catch (error) {
    console.error("Security event analytics query failed", error);
    const status = statusForQueryError(error);
    return jsonError(
      status === 400 ? "invalid security event analytics query" : "security event analytics unavailable",
      status,
      requestId,
    );
  }
}

function presentSecurityEvent(event) {
  return {
    id: event.id,
    firewallInstanceId: event.firewallInstanceId,
    eventType: event.eventType,
    attackType: event.attackType,
    severity: event.severity,
    sourceIp: event.sourceIp,
    requestPath: event.requestPath,
    httpMethod: event.httpMethod,
    userAgent: event.userAgent,
    country: event.country,
    confidence: event.confidence,
    detectorId: event.detectorId,
    detectorIds: event.detectorIds || [],
    score: event.score,
    apiRouteId: event.apiRouteId,
    anomalyType: event.anomalyType,
    actionTaken: event.actionTaken,
    requestId: event.requestId,
    rawMetadata: event.rawMetadata || {},
    occurredAt: event.occurredAt,
    receivedAt: event.receivedAt,
  };
}

function recordSecurityEventAuthzDecision({ result, identity, route, permission, requestId }) {
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

function statusForQueryError(error) {
  return /filter|cursor|date/i.test(error?.message || "") ? 400 : 500;
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
