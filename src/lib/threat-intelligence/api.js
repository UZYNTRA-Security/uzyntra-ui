import "server-only";

import { PERMISSIONS } from "../rbac/catalog.js";
import { errorResponse, json, readJson, requirePermission, searchParams } from "../alerts/api.js";
import {
  getThreatIntelligenceOverview,
  listThreatIndicators,
  listThreatMatches,
  listThreatSources,
  reviewThreatIndicator,
  upsertThreatIndicator,
} from "./index.js";

export async function requireThreatIntelPermission({ database, request, operation, method }) {
  const permission =
    method === "GET"
      ? operation === "overview"
        ? PERMISSIONS.METRICS_READ
        : PERMISSIONS.EVENTS_READ
      : PERMISSIONS.ALERTS_MANAGE;

  return requirePermission({
    database,
    request,
    permission,
    route: `threat-intelligence/${operation}`,
    method,
  });
}

export async function handleThreatIntelRead({
  request,
  database,
  identity,
  requestId,
  operation,
} = {}) {
  try {
    const filters = searchParams(request);
    const data =
      operation === "overview"
        ? await getThreatIntelligenceOverview({ database, organizationId: identity.organizationId, filters })
        : operation === "indicators"
          ? await listThreatIndicators({ database, organizationId: identity.organizationId, filters })
          : operation === "matches"
            ? await listThreatMatches({ database, organizationId: identity.organizationId, filters })
            : await listThreatSources({ database, organizationId: identity.organizationId, filters });

    return json({ success: true, data }, 200, requestId);
  } catch (error) {
    return errorResponse(error, requestId);
  }
}

export async function handleThreatIndicatorCreate({
  request,
  database,
  identity,
  requestId,
} = {}) {
  try {
    const input = await readJson(request);
    const data = await upsertThreatIndicator({
      database,
      organizationId: identity.organizationId,
      userId: identity.userId,
      input,
      auditContext: { requestId },
    });
    return json({ success: true, data }, 201, requestId);
  } catch (error) {
    return errorResponse(error, requestId);
  }
}

export async function handleThreatIndicatorReview({
  request,
  database,
  identity,
  requestId,
} = {}) {
  try {
    const input = await readJson(request);
    const data = await reviewThreatIndicator({
      database,
      organizationId: identity.organizationId,
      userId: identity.userId,
      input,
      auditContext: { requestId },
    });
    return json({ success: true, data }, 200, requestId);
  } catch (error) {
    return errorResponse(error, requestId);
  }
}
