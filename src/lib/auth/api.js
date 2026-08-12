import "server-only";

import crypto from "node:crypto";

export const AUTH_ERROR = "Invalid credentials";
export const LOGIN_LOCK_THRESHOLD = 5;
export const LOGIN_LOCK_SECONDS = 15 * 60;

export function authJson(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

export function authError(error = AUTH_ERROR, status = 401) {
  return authJson({ error }, status);
}

export async function readJson(request) {
  const contentType = request.headers.get("content-type");
  if (contentType && !contentType.toLowerCase().startsWith("application/json")) {
    return { error: authError("content-type must be application/json", 415) };
  }

  try {
    return { data: await request.json() };
  } catch {
    return { error: authError("invalid json body", 400) };
  }
}

export function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

export function clientIp(headersList) {
  const forwardedFor = headersList.get("x-forwarded-for");
  if (forwardedFor) {
    return forwardedFor.split(",")[0].trim().slice(0, 45);
  }

  return String(headersList.get("x-real-ip") || "").trim().slice(0, 45) || null;
}

export function userAgent(headersList) {
  return (
    String(headersList.get("user-agent") || "")
      .replace(/[^\x20-\x7E]/g, "")
      .trim()
      .slice(0, 1024) || null
  );
}

export function isLocked(credential, now = new Date()) {
  return credential?.lockedUntil && new Date(credential.lockedUntil).getTime() > now.getTime();
}

export function nextFailedCredentialState(credential, now = new Date()) {
  const previousLockExpired =
    credential?.lockedUntil && new Date(credential.lockedUntil).getTime() <= now.getTime();
  const failedAttempts = (previousLockExpired ? 0 : Number(credential?.failedAttempts || 0)) + 1;
  const lockedUntil =
    failedAttempts >= LOGIN_LOCK_THRESHOLD
      ? new Date(now.getTime() + LOGIN_LOCK_SECONDS * 1000)
      : null;

  return { failedAttempts, lockedUntil };
}

export function validateSameOriginWrite(request) {
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

export function recordAuthAuditEvent({
  action,
  result,
  actorId,
  email,
  requestId,
  ipAddress,
  userAgent,
  reason,
}) {
  console.info(
    JSON.stringify({
      source: "uzyntra-auth-api",
      action,
      result,
      actorId: actorId || null,
      email: email ? redactEmail(email) : null,
      requestId: requestId || null,
      ipAddress: ipAddress || null,
      userAgent: userAgent || null,
      reason: reason || null,
      timestamp: new Date().toISOString(),
    }),
  );
}

export function requestId() {
  return crypto.randomUUID();
}

function redactEmail(email) {
  const [local, domain] = String(email).split("@");
  if (!local || !domain) {
    return "redacted";
  }

  return `${local.slice(0, 2)}***@${domain}`;
}
