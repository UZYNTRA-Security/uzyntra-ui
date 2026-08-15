import { contextIdentity, getAuthenticatedContext } from "../../../../lib/auth/context.js";
import {
  getAuthorizationContext,
  getFirewallAuthorizationContext,
  hasFirewallPermission,
  hasPermission,
  recordAuthorizationDecision,
} from "../../../../lib/authz/index.js";
import {
  isFirewallScopedAdminPermission,
  requiredPermissionForAdminRoute,
} from "../../../../lib/authz/routes.js";

const DEFAULT_ADMIN_URL = "http://127.0.0.1:9090";
const FORWARDED_HEADERS = ["accept", "content-type"];
const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;
const AUDIT_SOURCE = "uzyntra-ui-bff";
const SAFE_METHODS = new Set(["GET", "HEAD"]);
const JSON_METHODS = new Set(["POST"]);
const ROUTES = [
  route("GET", /^metrics$/, "metrics.read"),
  route("GET", /^events\/recent$/, "events.recent", ["limit", "offset"]),
  route("GET", /^events\/search$/, "events.search", [
    "source_ip",
    "rule_id",
    "severity",
    "method",
    "path_contains",
    "limit",
    "offset",
  ]),
  route("GET", /^mitigations\/active$/, "mitigations.active"),
  route("GET", /^audits\/recent$/, "audits.recent", ["limit", "offset"]),
  route("GET", /^reputations$/, "reputations.list"),
  route("GET", /^policy\/effective$/, "policy.effective"),
  route("POST", /^mitigations\/unblock\/[A-Za-z0-9.:%_-]+$/, "mitigations.unblock"),
  route("POST", /^mitigations\/block$/, "mitigations.block"),
  route("POST", /^reputations\/reset\/[A-Za-z0-9.:%_-]+$/, "reputations.reset"),
  route("POST", /^policy\/rules\/set$/, "policy.rules.set"),
  route("POST", /^policy\/routes\/upsert$/, "policy.routes.upsert"),
  route("POST", /^policy\/routes\/delete$/, "policy.routes.delete"),
  route("POST", /^policy\/rate-limits\/upsert$/, "policy.rate_limits.upsert"),
  route("POST", /^policy\/rate-limits\/delete$/, "policy.rate_limits.delete"),
  route("GET", /^policy\/export$/, "policy.export"),
  route("POST", /^policy\/import$/, "policy.import"),
  route("GET", /^policy\/bundles$/, "policy.bundles"),
  route("POST", /^policy\/bundles\/save$/, "policy.bundles.save"),
  route("POST", /^policy\/bundles\/restore$/, "policy.bundles.restore"),
  route("GET", /^policy\/diff\/latest$/, "policy.diff.latest"),
  route("GET", /^policy\/route-behavior-overrides$/, "policy.route_behavior_overrides"),
  route(
    "POST",
    /^policy\/route-behavior-overrides\/upsert$/,
    "policy.route_behavior_overrides.upsert",
  ),
  route(
    "POST",
    /^policy\/route-behavior-overrides\/delete$/,
    "policy.route_behavior_overrides.delete",
  ),
];

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

function route(method, pattern, auditAction, queryParams = []) {
  return {
    method,
    pattern,
    auditAction,
    queryParams: new Set(queryParams),
  };
}

function jsonError(error, status) {
  return Response.json(
    { error },
    {
      status,
      headers: {
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
      },
    },
  );
}

function adminBaseUrl() {
  const rawUrl = (process.env.FIREWALL_ADMIN_URL || DEFAULT_ADMIN_URL).replace(/\/+$/, "");
  const url = new URL(rawUrl);

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("invalid admin URL protocol");
  }

  if (url.username || url.password) {
    throw new Error("admin URL must not contain credentials");
  }

  return rawUrl;
}

function adminToken() {
  return process.env.FIREWALL_ADMIN_TOKEN;
}

function maxBodyBytes() {
  const configured = Number(process.env.BFF_MAX_BODY_BYTES || DEFAULT_MAX_BODY_BYTES);
  return Number.isFinite(configured) && configured > 0
    ? Math.min(configured, DEFAULT_MAX_BODY_BYTES)
    : DEFAULT_MAX_BODY_BYTES;
}

function timeoutMs() {
  const configured = Number(process.env.BFF_ADMIN_TIMEOUT_MS || DEFAULT_TIMEOUT_MS);
  return Number.isFinite(configured) && configured > 0
    ? Math.min(configured, 30_000)
    : DEFAULT_TIMEOUT_MS;
}

function sanitizeHeaderValue(value, fallback = "unknown") {
  const cleaned = String(value || "")
    .replace(/[^\x20-\x7E]/g, "")
    .trim()
    .slice(0, 160);
  return cleaned || fallback;
}

function requestId() {
  return crypto.randomUUID();
}

function clientSource(request) {
  const forwardedFor = request.headers.get("x-forwarded-for");
  if (forwardedFor) {
    return sanitizeHeaderValue(forwardedFor.split(",")[0]);
  }

  return sanitizeHeaderValue(request.headers.get("x-real-ip"));
}

async function authenticatedIdentity() {
  try {
    return contextIdentity(await getAuthenticatedContext());
  } catch (error) {
    console.error("BFF session resolution failed", error);
    return null;
  }
}

function setAuditHeaders(headers, request, routeConfig, pathSegments, identity, permission, id) {
  headers.set("x-admin-actor", sanitizeHeaderValue(`user:${identity.userId}`));
  headers.set("x-admin-audit-source", AUDIT_SOURCE);
  headers.set("x-admin-audit-request-id", id);
  headers.set("x-admin-audit-user-id", sanitizeHeaderValue(identity.userId));
  headers.set("x-admin-audit-organization-id", sanitizeHeaderValue(identity.organizationId));
  headers.set("x-admin-audit-session-id", sanitizeHeaderValue(identity.sessionId));
  if (identity.activeFirewallInstanceId) {
    headers.set("x-admin-audit-firewall-instance-id", sanitizeHeaderValue(identity.activeFirewallInstanceId));
  }
  headers.set("x-admin-audit-permission", sanitizeHeaderValue(permission));
  headers.set("x-admin-audit-action", routeConfig.auditAction);
  headers.set("x-admin-audit-route", sanitizeHeaderValue(pathKey(pathSegments)));
  headers.set("x-admin-audit-method", request.method);
  headers.set("x-admin-audit-client", clientSource(request));
  return id;
}

function buildAdminUrl(pathSegments, searchParams) {
  const path = pathSegments.map(encodeURIComponent).join("/");
  const url = new URL(`/v1/admin/${path}`, adminBaseUrl());
  searchParams.forEach((value, key) => url.searchParams.append(key, value));
  return url;
}

function pathKey(pathSegments) {
  return pathSegments.join("/");
}

function matchedRoute(method, pathSegments) {
  const key = pathKey(pathSegments);
  return ROUTES.find((item) => item.method === method && item.pattern.test(key));
}

function validateQuery(routeConfig, searchParams) {
  for (const [key, value] of searchParams) {
    if (!routeConfig.queryParams.has(key)) {
      return `query parameter '${key}' is not allowed`;
    }

    if (value.length > 256) {
      return `query parameter '${key}' is too long`;
    }
  }

  return null;
}

function validateSameOriginWrite(request) {
  if (SAFE_METHODS.has(request.method)) {
    return true;
  }

  const origin = request.headers.get("origin");
  if (!origin) {
    return true;
  }

  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

function validateContentType(request) {
  if (!JSON_METHODS.has(request.method)) {
    return true;
  }

  const contentType = request.headers.get("content-type");
  return !contentType || contentType.toLowerCase().startsWith("application/json");
}

async function readRequestBody(request) {
  if (SAFE_METHODS.has(request.method)) {
    return undefined;
  }

  const contentLength = Number(request.headers.get("content-length") || 0);
  const limit = maxBodyBytes();
  if (contentLength > limit) {
    return { error: jsonError("request body too large", 413) };
  }

  const body = await request.text();
  if (new TextEncoder().encode(body).length > limit) {
    return { error: jsonError("request body too large", 413) };
  }

  return { body };
}

async function proxyAdminRequest(request, context) {
  const { path = [] } = await context.params;
  const incomingUrl = new URL(request.url);
  const requestPathKey = pathKey(path);
  const routeConfig = matchedRoute(request.method, path);
  const headers = new Headers();
  const auditRequestId = requestId();

  if (!routeConfig) {
    return jsonError("admin route is not allowed", 404);
  }

  const queryError = validateQuery(routeConfig, incomingUrl.searchParams);
  if (queryError) {
    return jsonError(queryError, 400);
  }

  if (!validateSameOriginWrite(request)) {
    return jsonError("cross-origin admin write rejected", 403);
  }

  if (!validateContentType(request)) {
    return jsonError("content-type must be application/json", 415);
  }

  const identity = await authenticatedIdentity();
  if (!identity) {
    return jsonError("Unauthorized", 401);
  }

  const requiredPermission = requiredPermissionForAdminRoute(request.method, requestPathKey);
  if (!requiredPermission) {
    return jsonError("admin route permission is not configured", 500);
  }

  let authorizationContext;
  try {
    authorizationContext = await resolveAdminAuthorizationContext(identity, requiredPermission);
  } catch (error) {
    console.error("BFF authorization context resolution failed", error);
    return jsonError("authorization unavailable", 500);
  }

  if (!isAdminPermissionAllowed(authorizationContext, identity, requiredPermission)) {
    recordAuthorizationDecision({
      result: "denied",
      userId: identity.userId,
      organizationId: identity.organizationId,
      route: requestPathKey,
      method: request.method,
      permission: requiredPermission,
      requestId: auditRequestId,
    });
    return jsonError("Forbidden", 403);
  }

  recordAuthorizationDecision({
    result: "allowed",
    userId: identity.userId,
    organizationId: identity.organizationId,
    route: requestPathKey,
    method: request.method,
    permission: requiredPermission,
    requestId: auditRequestId,
  });

  FORWARDED_HEADERS.forEach((name) => {
    const value = request.headers.get(name);
    if (value) {
      headers.set(name, value);
    }
  });

  const token = adminToken();
  if (!token) {
    return jsonError("FIREWALL_ADMIN_TOKEN is not configured on the Next.js server", 500);
  }

  headers.set("x-admin-token", token);
  setAuditHeaders(headers, request, routeConfig, path, identity, requiredPermission, auditRequestId);

  const bodyResult = await readRequestBody(request);
  if (bodyResult?.error) {
    return bodyResult.error;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs());

  let response;
  try {
    response = await fetch(buildAdminUrl(path, incomingUrl.searchParams), {
      method: request.method,
      headers,
      body: bodyResult?.body,
      cache: "no-store",
      signal: controller.signal,
    });
  } catch {
    return jsonError("admin backend unavailable", 502);
  } finally {
    clearTimeout(timeout);
  }

  const responseHeaders = new Headers();
  const contentType = response.headers.get("content-type");
  if (contentType) {
    responseHeaders.set("content-type", contentType);
  }
  responseHeaders.set("cache-control", "no-store");
  responseHeaders.set("x-content-type-options", "nosniff");
  responseHeaders.set("x-admin-audit-request-id", auditRequestId);

  return new Response(await response.arrayBuffer(), {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders,
  });
}

async function resolveAdminAuthorizationContext(identity, requiredPermission) {
  if (isFirewallScopedAdminPermission(requiredPermission)) {
    if (!identity.activeFirewallInstanceId) {
      return null;
    }

    return getFirewallAuthorizationContext({
      userId: identity.userId,
      organizationId: identity.organizationId,
      firewallInstanceId: identity.activeFirewallInstanceId,
    });
  }

  return getAuthorizationContext({
    userId: identity.userId,
    organizationId: identity.organizationId,
  });
}

function isAdminPermissionAllowed(context, identity, permission) {
  if (isFirewallScopedAdminPermission(permission)) {
    return hasFirewallPermission(context, identity.activeFirewallInstanceId, permission);
  }

  return hasPermission(context, permission);
}

export const GET = proxyAdminRequest;
export const POST = proxyAdminRequest;
