import "server-only";

import crypto from "node:crypto";
import { and, eq, isNull } from "drizzle-orm";
import { db } from "../../db/client.js";
import { apiKeys, serviceAccounts } from "../../db/schema.js";
import {
  AUDIT_EVENT_TYPES,
  AUDIT_RESULTS,
  AUDIT_SEVERITIES,
  createAuditEvent,
} from "../audit/index.js";

export const API_KEY_PREFIX = "uz_live";
export const API_KEY_SECRET_BYTES = 32;
export const API_KEY_PREFIX_BYTES = 6;
export const API_KEY_STATUSES = Object.freeze({
  ACTIVE: "active",
  REVOKED: "revoked",
  EXPIRED: "expired",
  DISABLED: "disabled",
  DELETED: "deleted",
});

export function generateApiKey() {
  const prefixId = crypto.randomBytes(API_KEY_PREFIX_BYTES).toString("hex");
  const secret = crypto.randomBytes(API_KEY_SECRET_BYTES).toString("hex");
  const keyPrefix = `${API_KEY_PREFIX}_${prefixId}`;

  return {
    plaintextKey: `${keyPrefix}_${secret}`,
    keyPrefix,
  };
}

export function hashApiKey(plaintextKey) {
  if (typeof plaintextKey !== "string" || !plaintextKey) {
    throw new Error("API key is required");
  }

  return crypto.createHmac("sha256", apiKeySecret()).update(plaintextKey, "utf8").digest("base64url");
}

export function verifyApiKey(plaintextKey, storedApiKey, now = new Date()) {
  if (!isApiKeyUsable(storedApiKey, now)) {
    return false;
  }

  const presentedHash = hashApiKey(plaintextKey);
  return timingSafeEqual(presentedHash, storedApiKey.keyHash);
}

export function isApiKeyUsable(storedApiKey, now = new Date()) {
  if (!storedApiKey) {
    return false;
  }

  if (storedApiKey.status !== API_KEY_STATUSES.ACTIVE || storedApiKey.revokedAt || storedApiKey.deletedAt) {
    return false;
  }

  if (storedApiKey.expiresAt && new Date(storedApiKey.expiresAt).getTime() <= now.getTime()) {
    return false;
  }

  return true;
}

export function apiKeyPrefixFromPlaintext(plaintextKey) {
  const match = /^uz_live_([A-Fa-f0-9]+)_([A-Fa-f0-9]+)$/.exec(String(plaintextKey || ""));
  if (!match) {
    return null;
  }

  return `${API_KEY_PREFIX}_${match[1]}`;
}

export async function authenticateServiceAccountApiKey({
  database = db(),
  plaintextKey,
  now = new Date(),
} = {}) {
  const keyPrefix = apiKeyPrefixFromPlaintext(plaintextKey);
  if (!keyPrefix) {
    return null;
  }

  const [identity] = await database
    .select({
      apiKey: apiKeys,
      serviceAccount: serviceAccounts,
    })
    .from(apiKeys)
    .innerJoin(serviceAccounts, eq(serviceAccounts.id, apiKeys.serviceAccountId))
    .where(
      and(
        eq(apiKeys.keyPrefix, keyPrefix),
        eq(serviceAccounts.status, "active"),
        isNull(serviceAccounts.deletedAt),
      ),
    )
    .limit(1);

  if (!identity?.apiKey || !identity?.serviceAccount) {
    return null;
  }

  if (!verifyApiKey(plaintextKey, identity.apiKey, now)) {
    return null;
  }

  if (
    !identity.apiKey.serviceAccountId ||
    identity.apiKey.organizationId !== identity.serviceAccount.organizationId
  ) {
    return null;
  }

  return {
    apiKey: identity.apiKey,
    serviceAccount: identity.serviceAccount,
    organizationId: identity.apiKey.organizationId,
    serviceAccountId: identity.serviceAccount.id,
    apiKeyId: identity.apiKey.id,
  };
}

export async function createApiKey({
  database = db(),
  organizationId,
  serviceAccountId,
  name,
  expiresAt,
  auditContext,
} = {}) {
  if (!organizationId || !name) {
    throw new Error("organizationId and name are required");
  }

  const { plaintextKey, keyPrefix } = generateApiKey();
  const keyHash = hashApiKey(plaintextKey);
  const [created] = await database
    .insert(apiKeys)
    .values({
      organizationId,
      serviceAccountId: serviceAccountId || null,
      name,
      keyPrefix,
      keyHash,
      status: API_KEY_STATUSES.ACTIVE,
      expiresAt: expiresAt || null,
    })
    .returning();

  await recordApiKeyAudit(database, AUDIT_EVENT_TYPES.API_KEY_CREATED, created, auditContext);

  return {
    plaintextKey,
    apiKey: publicApiKey(created),
  };
}

export async function revokeApiKey({
  database = db(),
  apiKeyId,
  auditContext,
  now = new Date(),
} = {}) {
  if (!apiKeyId) {
    throw new Error("apiKeyId is required");
  }

  const [revoked] = await database
    .update(apiKeys)
    .set({
      status: API_KEY_STATUSES.REVOKED,
      revokedAt: now,
    })
    .where(eq(apiKeys.id, apiKeyId))
    .returning();

  if (revoked) {
    await recordApiKeyAudit(database, AUDIT_EVENT_TYPES.API_KEY_REVOKED, revoked, auditContext);
  }

  return revoked ? publicApiKey(revoked) : null;
}

export async function expireApiKey({ database = db(), apiKeyId } = {}) {
  if (!apiKeyId) {
    throw new Error("apiKeyId is required");
  }

  const [expired] = await database
    .update(apiKeys)
    .set({ status: API_KEY_STATUSES.EXPIRED })
    .where(eq(apiKeys.id, apiKeyId))
    .returning();

  return expired ? publicApiKey(expired) : null;
}

export async function rotateApiKey({
  database = db(),
  apiKeyId,
  replacementName,
  auditContext,
  now = new Date(),
} = {}) {
  if (!apiKeyId) {
    throw new Error("apiKeyId is required");
  }

  const [existing] = await database.select().from(apiKeys).where(eq(apiKeys.id, apiKeyId)).limit(1);
  if (!existing) {
    return null;
  }

  const replacement = await createApiKey({
    database,
    organizationId: existing.organizationId,
    serviceAccountId: existing.serviceAccountId,
    name: replacementName || `${existing.name} replacement`,
    expiresAt: existing.expiresAt,
    auditContext,
  });
  await revokeApiKey({ database, apiKeyId, auditContext, now });
  await recordApiKeyAudit(database, AUDIT_EVENT_TYPES.API_KEY_ROTATED, existing, auditContext, {
    replacementKeyPrefix: replacement.apiKey.keyPrefix,
  });

  return replacement;
}

export function publicApiKey(apiKey) {
  if (!apiKey) {
    return null;
  }

  const { keyHash, ...safeApiKey } = apiKey;
  return safeApiKey;
}

async function recordApiKeyAudit(database, eventType, apiKey, auditContext, metadata = {}) {
  await createAuditEvent({
    database,
    eventType,
    action: eventType,
    result: AUDIT_RESULTS.SUCCESS,
    severity: AUDIT_SEVERITIES.INFO,
    organizationId: apiKey.organizationId,
    serviceAccountId: apiKey.serviceAccountId,
    resourceType: "api_key",
    resourceId: apiKey.id,
    requestId: auditContext?.requestId,
    userId: auditContext?.userId,
    ipAddress: auditContext?.ipAddress,
    userAgent: auditContext?.userAgent,
    metadata: {
      keyPrefix: apiKey.keyPrefix,
      ...metadata,
    },
  });
}

function timingSafeEqual(left, right) {
  if (typeof right !== "string" || !right) {
    return false;
  }

  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function apiKeySecret() {
  const secret = process.env.AUTH_API_KEY_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("AUTH_API_KEY_SECRET must be at least 32 characters");
  }

  return secret;
}
