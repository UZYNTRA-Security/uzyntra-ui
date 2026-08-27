import "server-only";

import { errorResponse, json, readJson, requirePermission, searchParams } from "../alerts/api.js";
import { PERMISSIONS } from "../rbac/catalog.js";
import {
  buildSecurityContext,
  createAiMessage,
  createAiSession,
  explainSecurityContext,
  generateAiReport,
  listAiMessages,
  listAiReports,
  listAiSessions,
  submitAiFeedback,
} from "./index.js";

export async function requireAiPermission({ database, request, operation, method }) {
  return requirePermission({
    database,
    request,
    permission: permissionFor(operation, method),
    route: `ai/${operation}`,
    method,
  });
}

export async function handleAiSessions({ request, database, identity, requestId, method }) {
  try {
    const data =
      method === "GET"
        ? await listAiSessions({ database, organizationId: identity.organizationId, userId: identity.userId, filters: searchParams(request) })
        : await createAiSession({
            database,
            organizationId: identity.organizationId,
            userId: identity.userId,
            input: await readJson(request),
            auditContext: { requestId },
          });
    return json({ success: true, data }, method === "GET" ? 200 : 201, requestId);
  } catch (error) {
    return errorResponse(error, requestId);
  }
}

export async function handleAiMessages({ request, database, identity, requestId, method }) {
  try {
    const data =
      method === "GET"
        ? await listAiMessages({ database, organizationId: identity.organizationId, filters: searchParams(request) })
        : await createAiMessage({
            database,
            organizationId: identity.organizationId,
            userId: identity.userId,
            input: await readJson(request),
            auditContext: { requestId },
          });
    return json({ success: true, data }, method === "GET" ? 200 : 201, requestId);
  } catch (error) {
    return errorResponse(error, requestId);
  }
}

export async function handleAiExplain({ request, database, identity, requestId }) {
  try {
    const data = await explainSecurityContext({
      database,
      organizationId: identity.organizationId,
      userId: identity.userId,
      input: await readJson(request),
      auditContext: { requestId },
    });
    return json({ success: true, data }, 200, requestId);
  } catch (error) {
    return errorResponse(error, requestId);
  }
}

export async function handleAiReports({ request, database, identity, requestId, method }) {
  try {
    const data =
      method === "GET"
        ? await listAiReports({ database, organizationId: identity.organizationId, filters: searchParams(request) })
        : await generateAiReport({
            database,
            organizationId: identity.organizationId,
            userId: identity.userId,
            input: await readJson(request),
            auditContext: { requestId },
          });
    return json({ success: true, data }, method === "GET" ? 200 : 201, requestId);
  } catch (error) {
    return errorResponse(error, requestId);
  }
}

export async function handleAiContext({ request, database, identity, requestId }) {
  try {
    const data = await buildSecurityContext({
      database,
      organizationId: identity.organizationId,
      filters: searchParams(request),
    });
    return json({ success: true, data }, 200, requestId);
  } catch (error) {
    return errorResponse(error, requestId);
  }
}

export async function handleAiFeedback({ request, database, identity, requestId }) {
  try {
    const data = await submitAiFeedback({
      database,
      organizationId: identity.organizationId,
      userId: identity.userId,
      input: await readJson(request),
      auditContext: { requestId },
    });
    return json({ success: true, data }, 201, requestId);
  } catch (error) {
    return errorResponse(error, requestId);
  }
}

function permissionFor(operation, method) {
  if (operation === "sessions") return method === "GET" ? PERMISSIONS.AI_READ : PERMISSIONS.AI_MANAGE;
  if (operation === "messages") return method === "GET" ? PERMISSIONS.AI_READ : PERMISSIONS.AI_ANALYZE;
  if (operation === "explain" || operation === "context") return PERMISSIONS.AI_ANALYZE;
  if (operation === "reports") return method === "GET" ? PERMISSIONS.AI_REPORTS_READ : PERMISSIONS.AI_REPORTS_GENERATE;
  if (operation === "feedback") return PERMISSIONS.AI_ANALYZE;
  return PERMISSIONS.AI_READ;
}
