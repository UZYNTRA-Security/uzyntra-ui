import "server-only";

import crypto from "node:crypto";

const TOKEN_BYTES = 32;

export function generateOneTimeToken(prefix) {
  if (!prefix || !/^[a-z][a-z0-9_]*$/i.test(prefix)) {
    throw new Error("token prefix is invalid");
  }

  return `${prefix}_${crypto.randomBytes(TOKEN_BYTES).toString("base64url")}`;
}

export function hashOneTimeToken(token) {
  if (typeof token !== "string" || !token) {
    throw new Error("token is required");
  }

  return crypto
    .createHmac("sha256", managementTokenSecret())
    .update(token, "utf8")
    .digest("base64url");
}

export function safeString(value, maxLength) {
  return (
    String(value || "")
      .replace(/[^\x20-\x7E]/g, "")
      .trim()
      .slice(0, maxLength) || null
  );
}

export function normalizeEmail(value) {
  return safeString(value, 320)?.toLowerCase() || null;
}

export function boundedLimit(value, fallback = 50, max = 100) {
  const limit = Number(value || fallback);
  return Number.isFinite(limit) && limit > 0 ? Math.min(Math.trunc(limit), max) : fallback;
}

function managementTokenSecret() {
  const secret = process.env.AUTH_MANAGEMENT_TOKEN_SECRET || process.env.AUTH_SESSION_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("AUTH_MANAGEMENT_TOKEN_SECRET must be at least 32 characters");
  }

  return secret;
}
