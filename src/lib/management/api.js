import "server-only";

import { db } from "../../db/client.js";
import { getAuthenticatedContext } from "../auth/context.js";
import { getAuthorizationContext, hasPermission } from "../authz/index.js";

export async function requireManagementPermission(request, permission, { database = db() } = {}) {
  const context = await getAuthenticatedContext({ database });
  if (!context) {
    return { error: jsonError("Unauthorized", 401) };
  }

  const authorizationContext = await getAuthorizationContext({
    database,
    userId: context.userId,
    organizationId: context.organizationId,
  });

  if (!hasPermission(authorizationContext, permission)) {
    return { error: jsonError("Forbidden", 403) };
  }

  return {
    database,
    context,
    auditContext: buildAuditContext(request, context),
    authorizationContext,
  };
}

export async function requireAuthenticatedManagement(request, { database = db() } = {}) {
  const context = await getAuthenticatedContext({ database });
  if (!context) {
    return { error: jsonError("Unauthorized", 401) };
  }

  return { database, context, auditContext: buildAuditContext(request, context) };
}

export async function readJson(request) {
  const contentType = request.headers.get("content-type");
  if (contentType && !contentType.toLowerCase().startsWith("application/json")) {
    return { error: jsonError("content-type must be application/json", 415) };
  }

  try {
    return { data: await request.json() };
  } catch {
    return { error: jsonError("invalid json body", 400) };
  }
}

export function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

export function jsonError(error, status) {
  return json({ error }, status);
}

export function routeError(error) {
  const message = error?.message || "request failed";
  const status = /forbidden|not available|last owner/i.test(message) ? 403 : 400;
  return jsonError(status === 403 ? message : "invalid request", status);
}

function buildAuditContext(request, context) {
  return {
    userId: context.userId,
    requestId: crypto.randomUUID(),
    ipAddress: clientIp(request.headers),
    userAgent: userAgent(request.headers),
  };
}

function clientIp(headersList) {
  const forwardedFor = headersList.get("x-forwarded-for");
  if (forwardedFor) {
    return safeString(forwardedFor.split(",")[0], 45);
  }

  return safeString(headersList.get("x-real-ip"), 45);
}

function userAgent(headersList) {
  return safeString(headersList.get("user-agent"), 1024);
}

function safeString(value, maxLength) {
  return (
    String(value || "")
      .replace(/[^\x20-\x7E]/g, "")
      .trim()
      .slice(0, maxLength) || null
  );
}
