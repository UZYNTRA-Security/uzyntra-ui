import "server-only";

import crypto from "node:crypto";
import { and, eq, isNull, or } from "drizzle-orm";
import { db } from "../../db/client.js";
import {
  externalIdentities,
  identityAuditEvents,
  identityProviders,
  organizationMemberships,
  users,
  verifiedEmailIdentities,
} from "../../db/schema.js";
import { AUDIT_RESULTS } from "../audit/index.js";
import { normalizeEmail, safeString } from "../management/tokens.js";

export const IDENTITY_PROVIDER_TYPES = Object.freeze({
  PASSWORD: "password",
  GOOGLE: "google",
  GITHUB: "github",
  OIDC: "oidc",
  SAML: "saml",
});

export const IDENTITY_PROVIDER_STATUSES = Object.freeze({
  ACTIVE: "active",
  DISABLED: "disabled",
  DELETED: "deleted",
});

export const EXTERNAL_IDENTITY_STATUSES = Object.freeze({
  ACTIVE: "active",
  UNLINKED: "unlinked",
  DISABLED: "disabled",
  DELETED: "deleted",
});

export const VERIFIED_EMAIL_STATUSES = Object.freeze({
  ACTIVE: "active",
  REVOKED: "revoked",
  EXPIRED: "expired",
});

export const IDENTITY_AUDIT_EVENT_TYPES = Object.freeze({
  IDENTITY_CREATED: "identity.created",
  IDENTITY_LINKED: "identity.linked",
  IDENTITY_UNLINKED: "identity.unlinked",
  IDENTITY_PROVIDER_CHANGED: "identity.provider.changed",
  IDENTITY_VERIFICATION_UPDATED: "identity.verification.updated",
  OAUTH_LOGIN_STARTED: "oauth.login.started",
  OAUTH_LOGIN_COMPLETED: "oauth.login.completed",
  OAUTH_LOGIN_FAILED: "oauth.login.failed",
  OAUTH_IDENTITY_LINKED: "oauth.identity.linked",
  OAUTH_IDENTITY_CREATED: "oauth.identity.created",
  MFA_ENABLED: "mfa.enabled",
  MFA_DISABLED: "mfa.disabled",
  MFA_CHALLENGE_CREATED: "mfa.challenge.created",
  MFA_CHALLENGE_SUCCESS: "mfa.challenge.success",
  MFA_CHALLENGE_FAILED: "mfa.challenge.failed",
  MFA_RECOVERY_USED: "mfa.recovery.used",
  SSO_LOGIN_STARTED: "sso.login.started",
  SSO_LOGIN_COMPLETED: "sso.login.completed",
  SSO_LOGIN_FAILED: "sso.login.failed",
  SSO_PROVIDER_CREATED: "sso.provider.created",
  SSO_PROVIDER_UPDATED: "sso.provider.updated",
  SSO_POLICY_CHANGED: "sso.policy.changed",
  SCIM_USER_CREATED: "scim.user.created",
  SCIM_USER_UPDATED: "scim.user.updated",
  SCIM_USER_DEACTIVATED: "scim.user.deactivated",
  SCIM_GROUP_SYNCED: "scim.group.synced",
  SCIM_SYNC_STARTED: "scim.sync.started",
  SCIM_SYNC_COMPLETED: "scim.sync.completed",
  SCIM_SYNC_FAILED: "scim.sync.failed",
  IDENTITY_RISK_DETECTED: "identity.risk.detected",
  IDENTITY_REVIEW_CREATED: "identity.review.created",
  IDENTITY_REVIEW_COMPLETED: "identity.review.completed",
  IDENTITY_ACCOUNT_FLAGGED: "identity.account.flagged",
  IDENTITY_POLICY_CHANGED: "identity.policy.changed",
  IDENTITY_REPORT_GENERATED: "identity.report.generated",
  IDENTITY_RECOVERY_REQUESTED: "identity.recovery.requested",
  IDENTITY_RECOVERY_COMPLETED: "identity.recovery.completed",
  BREAK_GLASS_ADMIN_CREATED: "identity.break_glass.created",
  BREAK_GLASS_ADMIN_ACTIVATED: "identity.break_glass.activated",
  BREAK_GLASS_ADMIN_REVOKED: "identity.break_glass.revoked",
});

const PROVIDER_TYPES = Object.freeze(Object.values(IDENTITY_PROVIDER_TYPES));
const PROVIDER_STATUSES = Object.freeze(Object.values(IDENTITY_PROVIDER_STATUSES));
const EXTERNAL_STATUSES = Object.freeze(Object.values(EXTERNAL_IDENTITY_STATUSES));
const EMAIL_STATUSES = Object.freeze(Object.values(VERIFIED_EMAIL_STATUSES));
const AUDIT_EVENT_TYPES = Object.freeze(Object.values(IDENTITY_AUDIT_EVENT_TYPES));

export const DEFAULT_IDENTITY_PROVIDERS = Object.freeze([
  defaultProvider("password", IDENTITY_PROVIDER_TYPES.PASSWORD, "Password", "active"),
  defaultProvider("google", IDENTITY_PROVIDER_TYPES.GOOGLE, "Google", "disabled"),
  defaultProvider("github", IDENTITY_PROVIDER_TYPES.GITHUB, "GitHub", "disabled"),
  defaultProvider("oidc", IDENTITY_PROVIDER_TYPES.OIDC, "OpenID Connect", "disabled"),
  defaultProvider("saml", IDENTITY_PROVIDER_TYPES.SAML, "SAML", "disabled"),
]);

export async function listIdentityProviders({
  database = db(),
  organizationId = null,
  includeDeleted = false,
} = {}) {
  const filters = [or(isNull(identityProviders.organizationId))];
  if (organizationId) {
    filters[0] = or(
      isNull(identityProviders.organizationId),
      eq(identityProviders.organizationId, organizationId),
    );
  }
  if (!includeDeleted) {
    filters.push(or(eq(identityProviders.status, "active"), eq(identityProviders.status, "disabled")));
  }

  const providers = await database
    .select()
    .from(identityProviders)
    .where(and(...filters))
    .orderBy(identityProviders.providerType, identityProviders.providerKey)
    .limit(100);

  return providers.map(publicIdentityProvider);
}

export async function getIdentityStatus({ database = db(), organizationId, userId } = {}) {
  if (!organizationId || !userId) {
    throw new Error("organizationId and userId are required");
  }

  const [linkedIdentities, verifiedEmails] = await Promise.all([
    database
      .select({
        id: externalIdentities.id,
        providerId: externalIdentities.providerId,
        providerKey: identityProviders.providerKey,
        providerType: identityProviders.providerType,
        providerDisplayName: identityProviders.displayName,
        providerEmail: externalIdentities.providerEmail,
        emailVerified: externalIdentities.emailVerified,
        status: externalIdentities.status,
        linkedAt: externalIdentities.linkedAt,
        lastSeenAt: externalIdentities.lastSeenAt,
      })
      .from(externalIdentities)
      .innerJoin(identityProviders, eq(identityProviders.id, externalIdentities.providerId))
      .where(
        and(
          eq(externalIdentities.organizationId, organizationId),
          eq(externalIdentities.userId, userId),
          eq(externalIdentities.status, EXTERNAL_IDENTITY_STATUSES.ACTIVE),
          isNull(externalIdentities.deletedAt),
        ),
      )
      .limit(50),
    database
      .select({
        id: verifiedEmailIdentities.id,
        email: verifiedEmailIdentities.email,
        verificationSource: verifiedEmailIdentities.verificationSource,
        status: verifiedEmailIdentities.status,
        verifiedAt: verifiedEmailIdentities.verifiedAt,
        expiresAt: verifiedEmailIdentities.expiresAt,
      })
      .from(verifiedEmailIdentities)
      .where(
        and(
          eq(verifiedEmailIdentities.organizationId, organizationId),
          eq(verifiedEmailIdentities.userId, userId),
          eq(verifiedEmailIdentities.status, VERIFIED_EMAIL_STATUSES.ACTIVE),
        ),
      )
      .limit(50),
  ]);

  return {
    userId,
    organizationId,
    linkedIdentities: linkedIdentities.map(publicExternalIdentity),
    verifiedEmails,
  };
}

export async function ensureDefaultIdentityProviders({
  database = db(),
  auditContext = {},
} = {}) {
  const created = [];

  for (const provider of DEFAULT_IDENTITY_PROVIDERS) {
    const [upserted] = await database
      .insert(identityProviders)
      .values({ ...provider, isSystem: true })
      .onConflictDoUpdate({
        target: identityProviders.providerKey,
        targetWhere: isNull(identityProviders.organizationId),
        set: {
          displayName: provider.displayName,
          providerType: provider.providerType,
          updatedAt: new Date(),
        },
      })
      .returning();

    created.push(publicIdentityProvider(upserted));
  }

  await recordIdentityAuditEvent({
    database,
    eventType: IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_PROVIDER_CHANGED,
    action: "identity.providers.ensure_defaults",
    result: AUDIT_RESULTS.SUCCESS,
    actorUserId: auditContext.userId,
    requestId: auditContext.requestId,
    ipAddress: auditContext.ipAddress,
    userAgent: auditContext.userAgent,
    metadata: { providerKeys: created.map((provider) => provider.providerKey) },
  });

  return created;
}

export async function findExternalIdentity({
  database = db(),
  providerId,
  externalSubjectId,
} = {}) {
  if (!providerId || !externalSubjectId) {
    throw new Error("providerId and externalSubjectId are required");
  }

  const externalSubjectHash = hashIdentityValue(externalSubjectId);
  const [identity] = await database
    .select()
    .from(externalIdentities)
    .where(
      and(
        eq(externalIdentities.providerId, providerId),
        eq(externalIdentities.externalSubjectHash, externalSubjectHash),
        eq(externalIdentities.status, EXTERNAL_IDENTITY_STATUSES.ACTIVE),
        isNull(externalIdentities.deletedAt),
      ),
    )
    .limit(1);

  return identity ? publicExternalIdentity(identity) : null;
}

export async function linkExternalIdentity({
  database = db(),
  organizationId,
  userId,
  providerId,
  externalSubjectId,
  providerEmail,
  emailVerified = false,
  metadata = {},
  auditContext = {},
} = {}) {
  const input = normalizeExternalIdentityInput({
    organizationId,
    userId,
    providerId,
    externalSubjectId,
    providerEmail,
    emailVerified,
    metadata,
  });

  return database.transaction(async (tx) => {
    const [membership] = await tx
      .select({ id: organizationMemberships.id })
      .from(organizationMemberships)
      .innerJoin(users, eq(users.id, organizationMemberships.userId))
      .where(
        and(
          eq(organizationMemberships.organizationId, input.organizationId),
          eq(organizationMemberships.userId, input.userId),
          eq(organizationMemberships.status, "active"),
          eq(users.status, "active"),
          isNull(users.deletedAt),
        ),
      )
      .limit(1);

    if (!membership) {
      throw new Error("identity user is not available in organization");
    }

    const [provider] = await tx
      .select()
      .from(identityProviders)
      .where(
        and(
          eq(identityProviders.id, input.providerId),
          or(isNull(identityProviders.organizationId), eq(identityProviders.organizationId, input.organizationId)),
          eq(identityProviders.status, IDENTITY_PROVIDER_STATUSES.ACTIVE),
          isNull(identityProviders.deletedAt),
        ),
      )
      .limit(1);

    if (!provider) {
      throw new Error("identity provider is not available");
    }

    const duplicate = await findExternalIdentity({
      database: tx,
      providerId: input.providerId,
      externalSubjectId,
    });

    if (duplicate && duplicate.userId !== input.userId) {
      throw new Error("external identity is already linked");
    }

    const [linked] = await tx
      .insert(externalIdentities)
      .values({
        organizationId: input.organizationId,
        userId: input.userId,
        providerId: input.providerId,
        externalSubjectHash: input.externalSubjectHash,
        providerEmail: input.providerEmail,
        providerEmailHash: input.providerEmailHash,
        emailVerified: input.emailVerified,
        metadata: input.metadata,
      })
      .onConflictDoUpdate({
        target: [externalIdentities.providerId, externalIdentities.externalSubjectHash],
        set: {
          organizationId: input.organizationId,
          userId: input.userId,
          providerEmail: input.providerEmail,
          providerEmailHash: input.providerEmailHash,
          emailVerified: input.emailVerified,
          status: EXTERNAL_IDENTITY_STATUSES.ACTIVE,
          unlinkedAt: null,
          lastSeenAt: new Date(),
          updatedAt: new Date(),
        },
      })
      .returning();

    if (input.providerEmail && input.emailVerified) {
      await tx
        .insert(verifiedEmailIdentities)
        .values({
          organizationId: input.organizationId,
          userId: input.userId,
          email: input.providerEmail,
          emailHash: input.providerEmailHash,
          sourceProviderId: input.providerId,
          verificationSource: provider.providerType,
          status: VERIFIED_EMAIL_STATUSES.ACTIVE,
        })
        .onConflictDoUpdate({
          target: [verifiedEmailIdentities.organizationId, verifiedEmailIdentities.emailHash],
          set: {
            userId: input.userId,
            sourceProviderId: input.providerId,
            verificationSource: provider.providerType,
            status: VERIFIED_EMAIL_STATUSES.ACTIVE,
            verifiedAt: new Date(),
            updatedAt: new Date(),
          },
        });
    }

    await recordIdentityAuditEvent({
      database: tx,
      organizationId: input.organizationId,
      userId: input.userId,
      actorUserId: auditContext.userId || input.userId,
      providerId: input.providerId,
      externalIdentityId: linked.id,
      eventType: IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_LINKED,
      action: IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_LINKED,
      result: AUDIT_RESULTS.SUCCESS,
      requestId: auditContext.requestId,
      ipAddress: auditContext.ipAddress,
      userAgent: auditContext.userAgent,
      metadata: {
        providerKey: provider.providerKey,
        providerType: provider.providerType,
        emailVerified: input.emailVerified,
      },
    });

    return publicExternalIdentity(linked);
  });
}

export async function recordIdentityAuditEvent({
  database = db(),
  eventType,
  action,
  result,
  organizationId = null,
  userId = null,
  actorUserId = null,
  providerId = null,
  externalIdentityId = null,
  ipAddress = null,
  userAgent = null,
  requestId = null,
  metadata = {},
} = {}) {
  const event = normalizeIdentityAuditEvent({
    eventType,
    action,
    result,
    organizationId,
    userId,
    actorUserId,
    providerId,
    externalIdentityId,
    ipAddress,
    userAgent,
    requestId,
    metadata,
  });

  const [created] = await database.insert(identityAuditEvents).values(event).returning();
  return created;
}

export function normalizeIdentityProvider(input = {}) {
  const providerType = normalizeEnum(input.providerType, PROVIDER_TYPES, "identity provider type");
  const providerKey = normalizeProviderKey(input.providerKey || providerType);
  const status = normalizeEnum(
    input.status || IDENTITY_PROVIDER_STATUSES.DISABLED,
    PROVIDER_STATUSES,
    "identity provider status",
  );
  const displayName = safeString(input.displayName || providerKey, 160);

  if (!displayName) {
    throw new Error("identity provider displayName is required");
  }

  return {
    organizationId: input.organizationId || null,
    providerKey,
    providerType,
    displayName,
    status,
    issuer: safeString(input.issuer, 255),
    clientId: safeString(input.clientId, 255),
    scopes: normalizeScopes(input.scopes),
    allowedDomains: normalizeDomains(input.allowedDomains),
    configurationRef: safeString(input.configurationRef, 160),
    secretRef: safeString(input.secretRef, 160),
    authorizationEndpoint: safeUrl(input.authorizationEndpoint),
    tokenEndpoint: safeUrl(input.tokenEndpoint),
    userInfoEndpoint: safeUrl(input.userInfoEndpoint),
    configuration: sanitizeIdentityMetadata(input.configuration),
    isSystem: Boolean(input.isSystem),
    createdByUserId: input.createdByUserId || null,
  };
}

export function normalizeExternalIdentityInput(input = {}) {
  const organizationId = requiredString(input.organizationId, "organizationId");
  const userId = requiredString(input.userId, "userId");
  const providerId = requiredString(input.providerId, "providerId");
  const externalSubjectId = requiredString(input.externalSubjectId, "externalSubjectId");
  const providerEmail = normalizeEmail(input.providerEmail);

  return {
    organizationId,
    userId,
    providerId,
    externalSubjectHash: hashIdentityValue(externalSubjectId),
    providerEmail,
    providerEmailHash: providerEmail ? hashIdentityValue(providerEmail) : null,
    emailVerified: Boolean(input.emailVerified),
    status: normalizeEnum(
      input.status || EXTERNAL_IDENTITY_STATUSES.ACTIVE,
      EXTERNAL_STATUSES,
      "external identity status",
    ),
    metadata: sanitizeIdentityMetadata(input.metadata),
  };
}

export function normalizeVerifiedEmailIdentity(input = {}) {
  const email = normalizeEmail(input.email);
  if (!email) {
    throw new Error("email is required");
  }

  return {
    organizationId: requiredString(input.organizationId, "organizationId"),
    userId: requiredString(input.userId, "userId"),
    email,
    emailHash: hashIdentityValue(email),
    sourceProviderId: input.sourceProviderId || null,
    verificationSource: normalizeEnum(
      input.verificationSource || IDENTITY_PROVIDER_TYPES.PASSWORD,
      [...PROVIDER_TYPES, "manual"],
      "verification source",
    ),
    status: normalizeEnum(
      input.status || VERIFIED_EMAIL_STATUSES.ACTIVE,
      EMAIL_STATUSES,
      "verified email status",
    ),
    expiresAt: input.expiresAt || null,
    metadata: sanitizeIdentityMetadata(input.metadata),
  };
}

export function normalizeIdentityAuditEvent(input = {}) {
  const eventType = normalizeEnum(input.eventType, AUDIT_EVENT_TYPES, "identity audit event type");
  const result = normalizeEnum(input.result, Object.values(AUDIT_RESULTS), "identity audit result");
  const action = safeString(input.action || eventType, 160);
  if (!action) {
    throw new Error("identity audit action is required");
  }

  return {
    organizationId: input.organizationId || null,
    userId: input.userId || null,
    actorUserId: input.actorUserId || null,
    providerId: input.providerId || null,
    externalIdentityId: input.externalIdentityId || null,
    eventType,
    action,
    result,
    ipAddress: safeString(input.ipAddress, 45),
    userAgent: safeString(input.userAgent, 1024),
    requestId: safeString(input.requestId, 160),
    metadata: sanitizeIdentityMetadata(input.metadata),
  };
}

export function hashIdentityValue(value) {
  const text = requiredString(value, "identity value");
  return crypto.createHmac("sha256", identityHashSecret()).update(text, "utf8").digest("base64url");
}

export function publicIdentityProvider(provider = {}) {
  return {
    id: provider.id,
    organizationId: provider.organizationId || null,
    providerKey: provider.providerKey,
    providerType: provider.providerType,
    displayName: provider.displayName,
    status: provider.status,
    issuer: provider.issuer || null,
    clientId: provider.clientId ? maskClientId(provider.clientId) : null,
    scopes: Array.isArray(provider.scopes) ? provider.scopes : [],
    allowedDomains: Array.isArray(provider.allowedDomains) ? provider.allowedDomains : [],
    configurationRef: provider.configurationRef || null,
    secretRef: provider.secretRef ? maskClientId(provider.secretRef) : null,
    authorizationEndpoint: provider.authorizationEndpoint || null,
    tokenEndpoint: provider.tokenEndpoint || null,
    userInfoEndpoint: provider.userInfoEndpoint || null,
    isSystem: Boolean(provider.isSystem),
    createdAt: provider.createdAt || null,
    updatedAt: provider.updatedAt || null,
  };
}

export function publicExternalIdentity(identity = {}) {
  return {
    id: identity.id,
    organizationId: identity.organizationId,
    userId: identity.userId,
    providerId: identity.providerId,
    providerKey: identity.providerKey || null,
    providerType: identity.providerType || null,
    providerDisplayName: identity.providerDisplayName || null,
    providerEmail: identity.providerEmail || null,
    emailVerified: Boolean(identity.emailVerified),
    status: identity.status,
    linkedAt: identity.linkedAt || null,
    lastSeenAt: identity.lastSeenAt || null,
  };
}

export function sanitizeIdentityMetadata(metadata = {}) {
  if (metadata == null) {
    return {};
  }
  if (Array.isArray(metadata) || typeof metadata !== "object") {
    throw new Error("identity metadata must be an object");
  }

  const clean = JSON.parse(JSON.stringify(metadata));
  const unsafe = firstSensitivePath(clean);
  if (unsafe) {
    throw new Error(`identity metadata contains sensitive field: ${unsafe}`);
  }

  return clean;
}

function defaultProvider(providerKey, providerType, displayName, status) {
  return Object.freeze(
    normalizeIdentityProvider({
      providerKey,
      providerType,
      displayName,
      status,
      isSystem: true,
    }),
  );
}

function normalizeProviderKey(value) {
  const key = safeString(value, 80)?.toLowerCase().replace(/[^a-z0-9_-]/g, "_");
  if (!key || !/^[a-z][a-z0-9_-]*$/.test(key)) {
    throw new Error("identity provider key is invalid");
  }
  return key;
}

function normalizeScopes(value) {
  if (value == null) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new Error("identity provider scopes must be an array");
  }
  return value.map((scope) => safeString(scope, 80)).filter(Boolean).slice(0, 20);
}

function normalizeDomains(value) {
  if (value == null) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new Error("identity provider domains must be an array");
  }

  const domains = value
    .map((domain) => safeString(domain, 255)?.toLowerCase().replace(/^\*@/, ""))
    .filter(Boolean)
    .map((domain) => domain.replace(/^@/, ""));

  for (const domain of domains) {
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(domain) || domain.includes("..")) {
      throw new Error("identity provider domain is invalid");
    }
  }

  return [...new Set(domains)].slice(0, 50);
}

function safeUrl(value) {
  const text = safeString(value, 2048);
  if (!text) {
    return null;
  }

  try {
    const url = new URL(text);
    if (url.protocol !== "https:") {
      throw new Error("identity provider url must use https");
    }
    return url.toString();
  } catch {
    throw new Error("identity provider url is invalid");
  }
}

function normalizeEnum(value, allowed, label) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!allowed.includes(normalized)) {
    throw new Error(`${label} is invalid`);
  }
  return normalized;
}

function requiredString(value, label) {
  const text = safeString(value, 512);
  if (!text) {
    throw new Error(`${label} is required`);
  }
  return text;
}

function identityHashSecret() {
  const secret = process.env.AUTH_API_KEY_SECRET || process.env.AUTH_SESSION_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error("AUTH_API_KEY_SECRET or AUTH_SESSION_SECRET must be at least 32 characters");
  }
  return secret;
}

function firstSensitivePath(value, path = []) {
  if (!value || typeof value !== "object") {
    return null;
  }

  for (const [key, child] of Object.entries(value)) {
    const currentPath = [...path, key];
    if (isSensitiveKey(key)) {
      return currentPath.join(".");
    }

    const nested = firstSensitivePath(child, currentPath);
    if (nested) {
      return nested;
    }
  }

  return null;
}

function isSensitiveKey(key) {
  return /password|secret|token|cookie|authorization|private[_-]?key|session[_-]?id|client[_-]?secret|assertion|refresh[_-]?token|access[_-]?token|code/i.test(
    key,
  );
}

function maskClientId(value) {
  const clientId = String(value || "");
  if (clientId.length <= 8) {
    return clientId ? "****" : null;
  }
  return `${clientId.slice(0, 4)}...${clientId.slice(-4)}`;
}
