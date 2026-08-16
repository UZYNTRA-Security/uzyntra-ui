import "server-only";

import { db } from "../../db/client.js";
import { contextIdentity, getAuthenticatedContext } from "../auth/context.js";
import { getAuthorizationContext, hasPermission, recordAuthorizationDecision } from "../authz/index.js";

export async function requirePermission({
  database = db(),
  request,
  permission,
  route,
  method,
} = {}) {
  const requestId = crypto.randomUUID();
  const identity = contextIdentity(await getAuthenticatedContext({ database }));
  if (!identity) {
    return { response: jsonError("Unauthorized", 401, requestId) };
  }

  const authz = await getAuthorizationContext({
    database,
    userId: identity.userId,
    organizationId: identity.organizationId,
  });

  if (!hasPermission(authz, permission)) {
    recordAuthorizationDecision({
      result: "denied",
      userId: identity.userId,
      organizationId: identity.organizationId,
      route,
      method,
      permission,
      requestId,
    });
    return { response: jsonError("Forbidden", 403, requestId) };
  }

  recordAuthorizationDecision({
    result: "allowed",
    userId: identity.userId,
    organizationId: identity.organizationId,
    route,
    method,
    permission,
    requestId,
  });

  return { identity, requestId, database };
}

export async function readJson(request, maxBytes = 128 * 1024) {
  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > maxBytes) throw new Error("request body too large");
  const text = await request.text();
  if (new TextEncoder().encode(text).length > maxBytes) throw new Error("request body too large");
  return text ? JSON.parse(text) : {};
}

export function searchParams(request) {
  return Object.fromEntries(new URL(request.url).searchParams.entries());
}

export function json(data, status = 200, requestId) {
  return Response.json(data, {
    status,
    headers: {
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      ...(requestId ? { "x-request-id": requestId } : {}),
    },
  });
}

export function jsonError(error, status, requestId) {
  return json({ error }, status, requestId);
}

export function errorResponse(error, requestId) {
  const message = error?.message || "request failed";
  const status = /not found/i.test(message)
    ? 404
    : /invalid|required|unsupported|blocked|large|syntax/i.test(message)
      ? 400
      : 500;
  return jsonError(status === 500 ? "request unavailable" : message, status, requestId);
}
