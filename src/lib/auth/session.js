import "server-only";

import crypto from "node:crypto";
import { and, eq, gt, isNull } from "drizzle-orm";
import { db } from "../../db/client.js";
import { sessions } from "../../db/schema.js";

export const SESSION_TOKEN_BYTES = 32;
export const DEFAULT_SESSION_TIMEOUT_SECONDS = 28_800;
export const MIN_SESSION_TIMEOUT_SECONDS = 300;
export const MAX_SESSION_TIMEOUT_SECONDS = 2_592_000;

export function generateSessionToken() {
  return crypto.randomBytes(SESSION_TOKEN_BYTES).toString("base64url");
}

export function hashSessionToken(token) {
  if (typeof token !== "string" || !token) {
    throw new Error("session token is required");
  }

  return crypto.createHmac("sha256", sessionSecret()).update(token, "utf8").digest("base64url");
}

export function sessionExpiresAt(timeoutSeconds = DEFAULT_SESSION_TIMEOUT_SECONDS, now = new Date()) {
  const seconds = clampSessionTimeout(timeoutSeconds);
  return new Date(now.getTime() + seconds * 1000);
}

export async function createSession({
  database = db(),
  userId,
  organizationId,
  activeFirewallInstanceId,
  expiresAt = sessionExpiresAt(),
  ipAddress,
  userAgent,
  now = new Date(),
} = {}) {
  if (!userId || !organizationId) {
    throw new Error("userId and organizationId are required");
  }

  const token = generateSessionToken();
  const tokenHash = hashSessionToken(token);
  const [session] = await database
    .insert(sessions)
    .values({
      userId,
      organizationId,
      activeFirewallInstanceId: activeFirewallInstanceId || null,
      tokenHash,
      expiresAt,
      lastSeenAt: now,
      ipAddress: normalizeIpAddress(ipAddress),
      userAgent: normalizeUserAgent(userAgent),
    })
    .returning();

  return { token, tokenHash, session };
}

export async function updateSessionOrganization({
  database = db(),
  sessionId,
  organizationId,
  now = new Date(),
} = {}) {
  if (!sessionId || !organizationId) {
    throw new Error("sessionId and organizationId are required");
  }

  const [session] = await database
    .update(sessions)
    .set({ organizationId, activeFirewallInstanceId: null, lastSeenAt: now })
    .where(and(eq(sessions.id, sessionId), isNull(sessions.revokedAt), gt(sessions.expiresAt, now)))
    .returning();

  return session || null;
}

export async function updateSessionActiveFirewall({
  database = db(),
  sessionId,
  firewallInstanceId,
  now = new Date(),
} = {}) {
  if (!sessionId) {
    throw new Error("sessionId is required");
  }

  const [session] = await database
    .update(sessions)
    .set({ activeFirewallInstanceId: firewallInstanceId || null, lastSeenAt: now })
    .where(and(eq(sessions.id, sessionId), isNull(sessions.revokedAt), gt(sessions.expiresAt, now)))
    .returning();

  return session || null;
}

export async function getActiveSessionByToken(token, { database = db(), now = new Date() } = {}) {
  const tokenHash = hashSessionToken(token);
  const [session] = await database
    .select()
    .from(sessions)
    .where(
      and(
        eq(sessions.tokenHash, tokenHash),
        isNull(sessions.revokedAt),
        gt(sessions.expiresAt, now),
      ),
    )
    .limit(1);

  return session || null;
}

export async function touchSession(sessionId, { database = db(), now = new Date() } = {}) {
  if (!sessionId) {
    throw new Error("sessionId is required");
  }

  const [session] = await database
    .update(sessions)
    .set({ lastSeenAt: now })
    .where(and(eq(sessions.id, sessionId), isNull(sessions.revokedAt), gt(sessions.expiresAt, now)))
    .returning();

  return session || null;
}

export async function revokeSessionById(sessionId, { database = db(), now = new Date() } = {}) {
  if (!sessionId) {
    throw new Error("sessionId is required");
  }

  const [session] = await database
    .update(sessions)
    .set({ revokedAt: now })
    .where(and(eq(sessions.id, sessionId), isNull(sessions.revokedAt)))
    .returning();

  return session || null;
}

export async function revokeSessionByToken(token, { database = db(), now = new Date() } = {}) {
  const tokenHash = hashSessionToken(token);
  const [session] = await database
    .update(sessions)
    .set({ revokedAt: now })
    .where(and(eq(sessions.tokenHash, tokenHash), isNull(sessions.revokedAt)))
    .returning();

  return session || null;
}

export async function revokeUserSessions(
  userId,
  { database = db(), organizationId, now = new Date() } = {},
) {
  if (!userId) {
    throw new Error("userId is required");
  }

  const predicates = [eq(sessions.userId, userId), isNull(sessions.revokedAt)];
  if (organizationId) {
    predicates.push(eq(sessions.organizationId, organizationId));
  }

  return database
    .update(sessions)
    .set({ revokedAt: now })
    .where(and(...predicates))
    .returning();
}

export function isSessionActive(session, now = new Date()) {
  if (!session || session.revokedAt) {
    return false;
  }

  return new Date(session.expiresAt).getTime() > now.getTime();
}

export function sessionCookieName() {
  return process.env.NODE_ENV === "production" ? "__Host-uzyntra_session" : "uzyntra_session";
}

export function sessionCookieOptions(expiresAt) {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    expires: expiresAt,
  };
}

export function expiredSessionCookieOptions() {
  return {
    ...sessionCookieOptions(new Date(0)),
    maxAge: 0,
  };
}

function clampSessionTimeout(timeoutSeconds) {
  const seconds = Number(timeoutSeconds);
  if (!Number.isFinite(seconds)) {
    return DEFAULT_SESSION_TIMEOUT_SECONDS;
  }

  return Math.min(
    Math.max(Math.trunc(seconds), MIN_SESSION_TIMEOUT_SECONDS),
    MAX_SESSION_TIMEOUT_SECONDS,
  );
}

function normalizeIpAddress(value) {
  if (!value) {
    return null;
  }

  return String(value).trim().slice(0, 45) || null;
}

function normalizeUserAgent(value) {
  if (!value) {
    return null;
  }

  return String(value).replace(/[^\x20-\x7E]/g, "").trim().slice(0, 1024) || null;
}

function sessionSecret() {
  const secret = process.env.AUTH_SESSION_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("AUTH_SESSION_SECRET must be at least 32 characters");
  }

  return secret;
}
