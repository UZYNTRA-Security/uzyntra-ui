import "server-only";

import crypto from "node:crypto";
import { and, eq, gt, isNull } from "drizzle-orm";
import { db } from "../../db/client.js";
import {
  mfaChallenges,
  mfaMethods,
  organizationSettings,
  recoveryCodes,
} from "../../db/schema.js";
import {
  IDENTITY_AUDIT_EVENT_TYPES,
  recordIdentityAuditEvent,
  sanitizeIdentityMetadata,
} from "../identity/index.js";
import { safeString } from "../management/tokens.js";
import { createSession, sessionExpiresAt } from "./session.js";

export const MFA_METHOD_TYPES = Object.freeze({
  TOTP: "totp",
  WEBAUTHN: "webauthn",
  RECOVERY_CODES: "recovery_codes",
});

export const MFA_METHOD_STATUSES = Object.freeze({
  PENDING: "pending",
  ACTIVE: "active",
  DISABLED: "disabled",
  DELETED: "deleted",
});

export const MFA_CHALLENGE_STATUSES = Object.freeze({
  PENDING: "pending",
  SUCCEEDED: "succeeded",
  FAILED: "failed",
  EXPIRED: "expired",
});

export const MFA_AUDIT_EVENTS = Object.freeze({
  ENABLED: "mfa.enabled",
  DISABLED: "mfa.disabled",
  CHALLENGE_CREATED: "mfa.challenge.created",
  CHALLENGE_SUCCESS: "mfa.challenge.success",
  CHALLENGE_FAILED: "mfa.challenge.failed",
  RECOVERY_USED: "mfa.recovery.used",
});

export const MFA_CHALLENGE_TTL_SECONDS = 300;
export const TOTP_PERIOD_SECONDS = 30;
export const TOTP_DIGITS = 6;
export const RECOVERY_CODE_COUNT = 10;
export const RECOVERY_CODE_BYTES = 9;

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const SECRET_FORMAT = "uzyntra.mfa.secret.v1";
const IV_BYTES = 12;

export function mfaChallengeIdCookieName() {
  return "uzyntra_mfa_challenge";
}

export function mfaChallengeTokenCookieName() {
  return "uzyntra_mfa_challenge_token";
}

export function mfaCookieOptions(expiresAt) {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    expires: expiresAt,
  };
}

export function expiredMfaCookieOptions() {
  return {
    ...mfaCookieOptions(new Date(0)),
    maxAge: 0,
  };
}

export async function completePrimaryAuthentication({
  database = db(),
  userId,
  organizationId,
  settings = null,
  ipAddress,
  userAgent,
  requestId,
  now = new Date(),
} = {}) {
  const requirement = await getMfaRequirement({
    database,
    userId,
    organizationId,
    settings,
  });

  if (requirement.required) {
    const challenge = await createMfaChallenge({
      database,
      userId,
      organizationId,
      challengeType: "login",
      methodId: requirement.preferredMethodId,
      ipAddress,
      userAgent,
      requestId,
      now,
      metadata: { reason: requirement.reason },
    });

    return {
      mfaRequired: true,
      challenge,
      methods: requirement.methods.map(publicMfaMethod),
    };
  }

  const expiresAt = sessionExpiresAt(settings?.sessionTimeoutSeconds, now);
  const { token, session } = await createSession({
    database,
    userId,
    organizationId,
    expiresAt,
    ipAddress,
    userAgent,
    now,
  });

  return {
    mfaRequired: false,
    token,
    session,
  };
}

export async function getMfaRequirement({
  database = db(),
  userId,
  organizationId,
  settings = null,
} = {}) {
  if (!userId || !organizationId) {
    throw new Error("userId and organizationId are required");
  }

  const [activeMethods, loadedSettings] = await Promise.all([
    listActiveMfaMethods({ database, userId, organizationId }),
    settings
      ? Promise.resolve(settings)
      : database
          .select()
          .from(organizationSettings)
          .where(eq(organizationSettings.organizationId, organizationId))
          .limit(1)
          .then((rows) => rows[0] || null),
  ]);

  const hasActiveMethod = activeMethods.length > 0;
  const orgRequiresMfa = Boolean(loadedSettings?.mfaRequired);

  return {
    required: hasActiveMethod || orgRequiresMfa,
    reason: hasActiveMethod ? "user_enabled" : orgRequiresMfa ? "organization_required" : "not_required",
    methods: activeMethods,
    preferredMethodId: activeMethods[0]?.id || null,
  };
}

export async function listMfaMethods({ database = db(), userId, organizationId } = {}) {
  if (!userId || !organizationId) {
    throw new Error("userId and organizationId are required");
  }

  const methods = await database
    .select()
    .from(mfaMethods)
    .where(
      and(
        eq(mfaMethods.userId, userId),
        eq(mfaMethods.organizationId, organizationId),
        isNull(mfaMethods.deletedAt),
      ),
    )
    .limit(50);

  return methods.map(publicMfaMethod);
}

export async function listActiveMfaMethods({ database = db(), userId, organizationId } = {}) {
  const methods = await database
    .select()
    .from(mfaMethods)
    .where(
      and(
        eq(mfaMethods.userId, userId),
        eq(mfaMethods.organizationId, organizationId),
        eq(mfaMethods.status, MFA_METHOD_STATUSES.ACTIVE),
        isNull(mfaMethods.deletedAt),
      ),
    )
    .limit(20);

  return methods;
}

export async function enrollTotpMethod({
  database = db(),
  organizationId,
  userId,
  displayName = "Authenticator app",
  issuer = "UZYNTRA",
  accountName,
  auditContext = {},
} = {}) {
  const secret = generateTotpSecret();
  const encrypted = sealMfaSecret(secret);
  const [method] = await database
    .insert(mfaMethods)
    .values({
      organizationId,
      userId,
      methodType: MFA_METHOD_TYPES.TOTP,
      displayName: safeString(displayName, 160) || "Authenticator app",
      status: MFA_METHOD_STATUSES.PENDING,
      secretCiphertext: encrypted,
      deviceMetadata: { issuer },
    })
    .returning();

  await recordMfaAudit({
    database,
    eventType: IDENTITY_AUDIT_EVENT_TYPES.MFA_CHALLENGE_CREATED,
    action: "mfa.totp.enrollment.created",
    organizationId,
    userId,
    actorUserId: auditContext.userId || userId,
    requestId: auditContext.requestId,
    ipAddress: auditContext.ipAddress,
    userAgent: auditContext.userAgent,
    metadata: { methodType: MFA_METHOD_TYPES.TOTP },
  });

  return {
    method: publicMfaMethod(method),
    secret,
    otpauthUri: totpProvisioningUri({
      secret,
      issuer,
      accountName: accountName || userId,
    }),
  };
}

export async function verifyTotpEnrollment({
  database = db(),
  organizationId,
  userId,
  methodId,
  code,
  auditContext = {},
  now = new Date(),
} = {}) {
  const method = await getOwnedMfaMethod({ database, organizationId, userId, methodId });
  if (!method || method.methodType !== MFA_METHOD_TYPES.TOTP) {
    throw new Error("mfa method is not available");
  }

  const secret = openMfaSecret(method.secretCiphertext);
  if (!verifyTotpCode({ secret, code, now })) {
    await recordMfaAudit({
      database,
      eventType: IDENTITY_AUDIT_EVENT_TYPES.MFA_CHALLENGE_FAILED,
      action: MFA_AUDIT_EVENTS.CHALLENGE_FAILED,
      organizationId,
      userId,
      actorUserId: auditContext.userId || userId,
      requestId: auditContext.requestId,
      ipAddress: auditContext.ipAddress,
      userAgent: auditContext.userAgent,
      result: "failure",
      metadata: { methodType: MFA_METHOD_TYPES.TOTP, reason: "invalid_totp" },
    });
    throw new Error("mfa verification failed");
  }

  const [updated] = await database
    .update(mfaMethods)
    .set({
      status: MFA_METHOD_STATUSES.ACTIVE,
      verifiedAt: now,
      enabledAt: now,
      lastUsedAt: now,
      updatedAt: now,
    })
    .where(eq(mfaMethods.id, method.id))
    .returning();

  await recordMfaAudit({
    database,
    eventType: IDENTITY_AUDIT_EVENT_TYPES.MFA_ENABLED,
    action: MFA_AUDIT_EVENTS.ENABLED,
    organizationId,
    userId,
    actorUserId: auditContext.userId || userId,
    requestId: auditContext.requestId,
    ipAddress: auditContext.ipAddress,
    userAgent: auditContext.userAgent,
    metadata: { methodType: MFA_METHOD_TYPES.TOTP },
  });

  return publicMfaMethod(updated);
}

export async function disableMfaMethod({
  database = db(),
  organizationId,
  userId,
  methodId,
  auditContext = {},
  now = new Date(),
} = {}) {
  const method = await getOwnedMfaMethod({ database, organizationId, userId, methodId });
  if (!method) {
    throw new Error("mfa method is not available");
  }

  const [updated] = await database
    .update(mfaMethods)
    .set({
      status: MFA_METHOD_STATUSES.DISABLED,
      disabledAt: now,
      updatedAt: now,
    })
    .where(eq(mfaMethods.id, method.id))
    .returning();

  await recordMfaAudit({
    database,
    eventType: IDENTITY_AUDIT_EVENT_TYPES.MFA_DISABLED,
    action: MFA_AUDIT_EVENTS.DISABLED,
    organizationId,
    userId,
    actorUserId: auditContext.userId || userId,
    requestId: auditContext.requestId,
    ipAddress: auditContext.ipAddress,
    userAgent: auditContext.userAgent,
    metadata: { methodType: method.methodType },
  });

  return publicMfaMethod(updated);
}

export async function generateRecoveryCodes({
  database = db(),
  organizationId,
  userId,
  auditContext = {},
} = {}) {
  const plaintextCodes = Array.from({ length: RECOVERY_CODE_COUNT }, () => generateRecoveryCode());

  return database.transaction(async (tx) => {
    const [method] = await tx
      .insert(mfaMethods)
      .values({
        organizationId,
        userId,
        methodType: MFA_METHOD_TYPES.RECOVERY_CODES,
        displayName: "Recovery codes",
        status: MFA_METHOD_STATUSES.ACTIVE,
        verifiedAt: new Date(),
        enabledAt: new Date(),
      })
      .returning();

    await tx.insert(recoveryCodes).values(
      plaintextCodes.map((code) => ({
        organizationId,
        userId,
        methodId: method.id,
        codeHash: hashMfaValue(code),
      })),
    );

    await recordMfaAudit({
      database: tx,
      eventType: IDENTITY_AUDIT_EVENT_TYPES.MFA_ENABLED,
      action: "mfa.recovery_codes.generated",
      organizationId,
      userId,
      actorUserId: auditContext.userId || userId,
      requestId: auditContext.requestId,
      ipAddress: auditContext.ipAddress,
      userAgent: auditContext.userAgent,
      metadata: { methodType: MFA_METHOD_TYPES.RECOVERY_CODES, count: plaintextCodes.length },
    });

    return {
      method: publicMfaMethod(method),
      recoveryCodes: plaintextCodes,
    };
  });
}

export async function createMfaChallenge({
  database = db(),
  organizationId,
  userId,
  methodId = null,
  challengeType = "login",
  ipAddress,
  userAgent,
  requestId,
  metadata = {},
  now = new Date(),
} = {}) {
  const challengeToken = randomToken(32);
  const expiresAt = new Date(now.getTime() + MFA_CHALLENGE_TTL_SECONDS * 1000);
  const [challenge] = await database
    .insert(mfaChallenges)
    .values({
      organizationId,
      userId,
      methodId,
      challengeType,
      challengeHash: hashMfaValue(challengeToken),
      status: MFA_CHALLENGE_STATUSES.PENDING,
      expiresAt,
      ipAddress,
      userAgent,
      metadata: sanitizeIdentityMetadata(metadata),
    })
    .returning();

  await recordMfaAudit({
    database,
    eventType: IDENTITY_AUDIT_EVENT_TYPES.MFA_CHALLENGE_CREATED,
    action: MFA_AUDIT_EVENTS.CHALLENGE_CREATED,
    organizationId,
    userId,
    actorUserId: userId,
    requestId,
    ipAddress,
    userAgent,
    metadata: { challengeType, methodId: methodId || null },
  });

  return {
    id: challenge.id,
    token: challengeToken,
    expiresAt,
  };
}

export async function verifyMfaChallengeAndCreateSession({
  database = db(),
  challengeId,
  challengeToken,
  methodId = null,
  code,
  recoveryCode,
  ipAddress,
  userAgent,
  requestId,
  now = new Date(),
} = {}) {
  if (!challengeId || !challengeToken) {
    throw new Error("mfa challenge is required");
  }

  const [challenge] = await database
    .select()
    .from(mfaChallenges)
    .where(
      and(
        eq(mfaChallenges.id, challengeId),
        eq(mfaChallenges.challengeHash, hashMfaValue(challengeToken)),
        eq(mfaChallenges.status, MFA_CHALLENGE_STATUSES.PENDING),
        gt(mfaChallenges.expiresAt, now),
      ),
    )
    .limit(1);

  if (!challenge || challenge.attemptCount >= challenge.maxAttempts) {
    throw new Error("mfa challenge is invalid");
  }

  const methods = await listActiveMfaMethods({
    database,
    organizationId: challenge.organizationId,
    userId: challenge.userId,
  });
  const selectedMethod =
    methods.find((method) => method.id === (methodId || challenge.methodId)) ||
    methods.find((method) => method.methodType === MFA_METHOD_TYPES.TOTP) ||
    methods[0];

  const verified = recoveryCode
    ? await verifyRecoveryCode({ database, challenge, recoveryCode, now })
    : await verifyMfaMethodCode({ method: selectedMethod, code, now });

  if (!verified) {
    await database
      .update(mfaChallenges)
      .set({
        attemptCount: Number(challenge.attemptCount || 0) + 1,
        status:
          Number(challenge.attemptCount || 0) + 1 >= Number(challenge.maxAttempts || 5)
            ? MFA_CHALLENGE_STATUSES.FAILED
            : MFA_CHALLENGE_STATUSES.PENDING,
        updatedAt: now,
      })
      .where(eq(mfaChallenges.id, challenge.id));

    await recordMfaAudit({
      database,
      eventType: IDENTITY_AUDIT_EVENT_TYPES.MFA_CHALLENGE_FAILED,
      action: MFA_AUDIT_EVENTS.CHALLENGE_FAILED,
      organizationId: challenge.organizationId,
      userId: challenge.userId,
      actorUserId: challenge.userId,
      requestId,
      ipAddress,
      userAgent,
      result: "failure",
      metadata: { reason: "invalid_code" },
    });

    throw new Error("mfa verification failed");
  }

  await database
    .update(mfaChallenges)
    .set({
      status: MFA_CHALLENGE_STATUSES.SUCCEEDED,
      succeededAt: now,
      consumedAt: now,
      updatedAt: now,
    })
    .where(eq(mfaChallenges.id, challenge.id));

  if (selectedMethod) {
    await database
      .update(mfaMethods)
      .set({ lastUsedAt: now, updatedAt: now })
      .where(eq(mfaMethods.id, selectedMethod.id));
  }

  await recordMfaAudit({
    database,
    eventType: IDENTITY_AUDIT_EVENT_TYPES.MFA_CHALLENGE_SUCCESS,
    action: MFA_AUDIT_EVENTS.CHALLENGE_SUCCESS,
    organizationId: challenge.organizationId,
    userId: challenge.userId,
    actorUserId: challenge.userId,
    requestId,
    ipAddress,
    userAgent,
    metadata: { methodType: recoveryCode ? MFA_METHOD_TYPES.RECOVERY_CODES : selectedMethod?.methodType },
  });

  const [settings] = await database
    .select()
    .from(organizationSettings)
    .where(eq(organizationSettings.organizationId, challenge.organizationId))
    .limit(1);
  const expiresAt = sessionExpiresAt(settings?.sessionTimeoutSeconds, now);
  return createSession({
    database,
    userId: challenge.userId,
    organizationId: challenge.organizationId,
    expiresAt,
    ipAddress,
    userAgent,
    now,
  });
}

export async function createWebAuthnRegistrationChallenge({
  database = db(),
  organizationId,
  userId,
  ipAddress,
  userAgent,
  requestId,
} = {}) {
  return createMfaChallenge({
    database,
    organizationId,
    userId,
    challengeType: "registration",
    ipAddress,
    userAgent,
    requestId,
    metadata: { methodType: MFA_METHOD_TYPES.WEBAUTHN },
  });
}

export async function registerWebAuthnCredential({
  database = db(),
  organizationId,
  userId,
  credentialId,
  publicKey,
  signCount = 0,
  displayName = "Passkey",
  deviceMetadata = {},
  auditContext = {},
  now = new Date(),
} = {}) {
  const credentialIdHash = hashMfaValue(requiredString(credentialId, "credentialId"));
  const [method] = await database
    .insert(mfaMethods)
    .values({
      organizationId,
      userId,
      methodType: MFA_METHOD_TYPES.WEBAUTHN,
      displayName: safeString(displayName, 160) || "Passkey",
      status: MFA_METHOD_STATUSES.ACTIVE,
      verifiedAt: now,
      enabledAt: now,
      credentialIdHash,
      publicKey: requiredString(publicKey, "publicKey"),
      signCount: Math.max(0, Math.trunc(Number(signCount) || 0)),
      deviceMetadata: sanitizeIdentityMetadata(deviceMetadata),
    })
    .returning();

  await recordMfaAudit({
    database,
    eventType: IDENTITY_AUDIT_EVENT_TYPES.MFA_ENABLED,
    action: "mfa.webauthn.registered",
    organizationId,
    userId,
    actorUserId: auditContext.userId || userId,
    requestId: auditContext.requestId,
    ipAddress: auditContext.ipAddress,
    userAgent: auditContext.userAgent,
    metadata: { methodType: MFA_METHOD_TYPES.WEBAUTHN },
  });

  return publicMfaMethod(method);
}

export async function verifyRecoveryCode({ database = db(), challenge, recoveryCode, now = new Date() } = {}) {
  const codeHash = hashMfaValue(requiredString(recoveryCode, "recoveryCode"));
  const [stored] = await database
    .select()
    .from(recoveryCodes)
    .where(
      and(
        eq(recoveryCodes.organizationId, challenge.organizationId),
        eq(recoveryCodes.userId, challenge.userId),
        eq(recoveryCodes.codeHash, codeHash),
        eq(recoveryCodes.status, "active"),
      ),
    )
    .limit(1);

  if (!stored) {
    return false;
  }

  await database
    .update(recoveryCodes)
    .set({ status: "used", usedAt: now })
    .where(eq(recoveryCodes.id, stored.id));

  await recordMfaAudit({
    database,
    eventType: IDENTITY_AUDIT_EVENT_TYPES.MFA_RECOVERY_USED,
    action: MFA_AUDIT_EVENTS.RECOVERY_USED,
    organizationId: challenge.organizationId,
    userId: challenge.userId,
    actorUserId: challenge.userId,
    metadata: { methodType: MFA_METHOD_TYPES.RECOVERY_CODES },
  });

  return true;
}

export function generateTotpSecret(bytes = 20) {
  return base32Encode(crypto.randomBytes(bytes));
}

export function totpProvisioningUri({ secret, issuer = "UZYNTRA", accountName } = {}) {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(accountName || "user")}`;
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: "SHA1",
    digits: String(TOTP_DIGITS),
    period: String(TOTP_PERIOD_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

export function generateTotpCode({ secret, now = new Date(), period = TOTP_PERIOD_SECONDS } = {}) {
  const counter = Math.floor(now.getTime() / 1000 / period);
  return hotp({ secret, counter });
}

export function verifyTotpCode({ secret, code, now = new Date(), window = 1 } = {}) {
  const normalized = String(code || "").replace(/\s+/g, "");
  if (!/^\d{6}$/.test(normalized)) {
    return false;
  }

  const counter = Math.floor(now.getTime() / 1000 / TOTP_PERIOD_SECONDS);
  for (let offset = -window; offset <= window; offset += 1) {
    const expected = hotp({ secret, counter: counter + offset });
    if (timingSafeEqualString(expected, normalized)) {
      return true;
    }
  }

  return false;
}

export function sealMfaSecret(plaintext, { key = mfaEncryptionKey() } = {}) {
  const secret = requiredString(plaintext, "mfa secret");
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    format: SECRET_FORMAT,
    keyVersion: "v1",
    iv: iv.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    tag: tag.toString("base64url"),
  };
}

export function openMfaSecret(sealed, { key = mfaEncryptionKey() } = {}) {
  if (!sealed || sealed.format !== SECRET_FORMAT || sealed.keyVersion !== "v1") {
    throw new Error("mfa secret format is unsupported");
  }

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(sealed.iv, "base64url"),
  );
  decipher.setAuthTag(Buffer.from(sealed.tag, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(sealed.ciphertext, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}

export function generateRecoveryCode() {
  let raw = "";
  while (raw.length < 12) {
    raw += crypto.randomBytes(RECOVERY_CODE_BYTES).toString("base64url").replace(/[^A-Za-z0-9]/g, "");
  }
  raw = raw.slice(0, 12);
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`.toUpperCase();
}

export function hashMfaValue(value) {
  return crypto.createHmac("sha256", mfaHashSecret()).update(requiredString(value, "mfa value"), "utf8").digest("base64url");
}

export function publicMfaMethod(method = {}) {
  return {
    id: method.id,
    organizationId: method.organizationId,
    userId: method.userId,
    methodType: method.methodType,
    displayName: method.displayName,
    status: method.status,
    verifiedAt: method.verifiedAt || null,
    enabledAt: method.enabledAt || null,
    disabledAt: method.disabledAt || null,
    lastUsedAt: method.lastUsedAt || null,
    deviceMetadata: method.deviceMetadata || {},
  };
}

async function getOwnedMfaMethod({ database, organizationId, userId, methodId } = {}) {
  const [method] = await database
    .select()
    .from(mfaMethods)
    .where(
      and(
        eq(mfaMethods.id, methodId),
        eq(mfaMethods.organizationId, organizationId),
        eq(mfaMethods.userId, userId),
        isNull(mfaMethods.deletedAt),
      ),
    )
    .limit(1);

  return method || null;
}

async function verifyMfaMethodCode({ method, code, now = new Date() } = {}) {
  if (!method || method.status !== MFA_METHOD_STATUSES.ACTIVE) {
    return false;
  }

  if (method.methodType === MFA_METHOD_TYPES.TOTP) {
    return verifyTotpCode({ secret: openMfaSecret(method.secretCiphertext), code, now });
  }

  return false;
}

async function recordMfaAudit({
  database,
  eventType,
  action,
  result = "success",
  organizationId,
  userId,
  actorUserId,
  requestId,
  ipAddress,
  userAgent,
  metadata,
} = {}) {
  return recordIdentityAuditEvent({
    database,
    eventType,
    action,
    result,
    organizationId,
    userId,
    actorUserId,
    requestId,
    ipAddress,
    userAgent,
    metadata,
  });
}

function hotp({ secret, counter } = {}) {
  const key = base32Decode(secret);
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac("sha1", key).update(buffer).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(binary % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, "0");
}

function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = "";

  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

function base32Decode(value) {
  const text = String(value || "").replace(/=+$/g, "").toUpperCase();
  let bits = 0;
  let current = 0;
  const bytes = [];

  for (const char of text) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) {
      throw new Error("totp secret is invalid");
    }
    current = (current << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((current >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

function mfaEncryptionKey() {
  const raw = process.env.AUTH_MFA_SECRET_ENCRYPTION_KEY || process.env.INTEGRATION_SECRET_ENCRYPTION_KEY;
  if (!raw) {
    throw new Error("AUTH_MFA_SECRET_ENCRYPTION_KEY is required");
  }

  const key =
    raw.length === 64 && /^[a-f0-9]+$/i.test(raw)
      ? Buffer.from(raw, "hex")
      : Buffer.from(raw, "base64");

  if (key.length !== 32) {
    throw new Error("AUTH_MFA_SECRET_ENCRYPTION_KEY must decode to 32 bytes");
  }

  return key;
}

function mfaHashSecret() {
  const secret = process.env.AUTH_API_KEY_SECRET || process.env.AUTH_SESSION_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("AUTH_API_KEY_SECRET or AUTH_SESSION_SECRET must be at least 32 characters");
  }
  return secret;
}

function randomToken(bytes) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function timingSafeEqualString(left, right) {
  const a = Buffer.from(String(left), "utf8");
  const b = Buffer.from(String(right), "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function requiredString(value, label) {
  const text = safeString(value, 4096);
  if (!text) {
    throw new Error(`${label} is required`);
  }
  return text;
}
