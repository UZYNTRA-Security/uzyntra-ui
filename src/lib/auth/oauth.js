import "server-only";

import crypto from "node:crypto";
import { and, asc, eq, gt, isNull } from "drizzle-orm";
import { db } from "../../db/client.js";
import {
  externalIdentities,
  identityProviders,
  oauthLoginAttempts,
  organizationMemberships,
  organizationSettings,
  organizations,
  users,
} from "../../db/schema.js";
import {
  IDENTITY_AUDIT_EVENT_TYPES,
  IDENTITY_PROVIDER_STATUSES,
  findExternalIdentity,
  hashIdentityValue,
  linkExternalIdentity,
  recordIdentityAuditEvent,
} from "../identity/index.js";
import { createOrganizationForUser } from "../management/organizations.js";
import { normalizeEmail, safeString } from "../management/tokens.js";
import { completePrimaryAuthentication } from "./mfa.js";

export const OAUTH_STATE_BYTES = 32;
export const OAUTH_PKCE_BYTES = 48;
export const OAUTH_ATTEMPT_TTL_SECONDS = 600;

export const OAUTH_AUDIT_EVENTS = Object.freeze({
  LOGIN_STARTED: "oauth.login.started",
  LOGIN_COMPLETED: "oauth.login.completed",
  LOGIN_FAILED: "oauth.login.failed",
  IDENTITY_LINKED: "oauth.identity.linked",
  IDENTITY_CREATED: "oauth.identity.created",
});

export const OAUTH_PROVIDER_DEFINITIONS = Object.freeze({
  google: Object.freeze({
    providerKey: "google",
    providerType: "google",
    displayName: "Google",
    clientIdEnv: "GOOGLE_CLIENT_ID",
    clientSecretEnv: "GOOGLE_CLIENT_SECRET",
    scopes: Object.freeze(["openid", "email", "profile"]),
    authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenEndpoint: "https://oauth2.googleapis.com/token",
    userInfoEndpoint: "https://openidconnect.googleapis.com/v1/userinfo",
  }),
  github: Object.freeze({
    providerKey: "github",
    providerType: "github",
    displayName: "GitHub",
    clientIdEnv: "GITHUB_CLIENT_ID",
    clientSecretEnv: "GITHUB_CLIENT_SECRET",
    scopes: Object.freeze(["read:user", "user:email"]),
    authorizationEndpoint: "https://github.com/login/oauth/authorize",
    tokenEndpoint: "https://github.com/login/oauth/access_token",
    userInfoEndpoint: "https://api.github.com/user",
    emailsEndpoint: "https://api.github.com/user/emails",
  }),
});

export function oauthStateCookieName(providerKey) {
  return `uzyntra_oauth_${normalizeProviderKey(providerKey)}_state`;
}

export function oauthPkceCookieName(providerKey) {
  return `uzyntra_oauth_${normalizeProviderKey(providerKey)}_pkce`;
}

export function oauthCookieOptions(expiresAt) {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    expires: expiresAt,
  };
}

export function expiredOAuthCookieOptions() {
  return {
    ...oauthCookieOptions(new Date(0)),
    maxAge: 0,
  };
}

export async function startOAuthLogin({
  database = db(),
  providerKey,
  requestUrl,
  redirectPath = "/",
  ipAddress,
  userAgent,
  requestId,
  now = new Date(),
  env = process.env,
} = {}) {
  const provider = await getEnabledOAuthProvider({ database, providerKey });
  const runtime = oauthRuntimeConfig(provider.providerKey, provider, env);
  if (!runtime.configured) {
    throw new Error("oauth provider is not configured");
  }

  const state = randomUrlToken(OAUTH_STATE_BYTES);
  const codeVerifier = randomUrlToken(OAUTH_PKCE_BYTES);
  const codeChallenge = pkceChallenge(codeVerifier);
  const expiresAt = new Date(now.getTime() + OAUTH_ATTEMPT_TTL_SECONDS * 1000);
  const callbackUrl = oauthCallbackUrl(requestUrl, provider.providerKey);
  const safeRedirectPath = normalizeRedirectPath(redirectPath);

  const [attempt] = await database
    .insert(oauthLoginAttempts)
    .values({
      providerId: provider.id,
      stateHash: hashIdentityValue(state),
      pkceVerifierHash: hashIdentityValue(codeVerifier),
      redirectPath: safeRedirectPath,
      status: "pending",
      expiresAt,
      ipAddress,
      userAgent,
      metadata: { providerKey: provider.providerKey },
    })
    .returning();

  await recordIdentityAuditEvent({
    database,
    providerId: provider.id,
    eventType: IDENTITY_AUDIT_EVENT_TYPES.OAUTH_LOGIN_STARTED,
    action: OAUTH_AUDIT_EVENTS.LOGIN_STARTED,
    result: "success",
    ipAddress,
    userAgent,
    requestId,
    metadata: { providerKey: provider.providerKey },
  });

  return {
    provider: publicOAuthProvider(provider, runtime),
    attemptId: attempt.id,
    state,
    codeVerifier,
    expiresAt,
    authorizationUrl: buildAuthorizationUrl({
      runtime,
      state,
      codeChallenge,
      redirectUri: callbackUrl,
    }),
  };
}

export async function completeOAuthCallback({
  database = db(),
  providerKey,
  requestUrl,
  state,
  stateCookie,
  codeVerifier,
  authorizationCode,
  ipAddress,
  userAgent,
  requestId,
  now = new Date(),
  fetchImpl = fetch,
  env = process.env,
} = {}) {
  const normalizedProviderKey = normalizeProviderKey(providerKey);
  if (!state || !stateCookie || state !== stateCookie) {
    await recordOAuthFailure({ database, providerKey: normalizedProviderKey, reason: "invalid_state", ipAddress, userAgent, requestId });
    throw new Error("oauth state is invalid");
  }
  if (!codeVerifier || !authorizationCode) {
    await recordOAuthFailure({ database, providerKey: normalizedProviderKey, reason: "invalid_callback", ipAddress, userAgent, requestId });
    throw new Error("oauth callback is invalid");
  }

  const provider = await getEnabledOAuthProvider({ database, providerKey: normalizedProviderKey });
  const runtime = oauthRuntimeConfig(provider.providerKey, provider, env);
  if (!runtime.configured) {
    throw new Error("oauth provider is not configured");
  }

  const stateHash = hashIdentityValue(state);
  const verifierHash = hashIdentityValue(codeVerifier);
  const codeHash = hashIdentityValue(authorizationCode);

  const [attempt] = await database
    .select()
    .from(oauthLoginAttempts)
    .where(
      and(
        eq(oauthLoginAttempts.providerId, provider.id),
        eq(oauthLoginAttempts.stateHash, stateHash),
        eq(oauthLoginAttempts.pkceVerifierHash, verifierHash),
        eq(oauthLoginAttempts.status, "pending"),
        gt(oauthLoginAttempts.expiresAt, now),
      ),
    )
    .limit(1);

  if (!attempt) {
    await recordOAuthFailure({ database, providerId: provider.id, providerKey: provider.providerKey, reason: "state_replay_or_expired", ipAddress, userAgent, requestId });
    throw new Error("oauth callback is invalid");
  }

  const [replayed] = await database
    .select({ id: oauthLoginAttempts.id })
    .from(oauthLoginAttempts)
    .where(eq(oauthLoginAttempts.authorizationCodeHash, codeHash))
    .limit(1);

  if (replayed) {
    await failOAuthAttempt({ database, attemptId: attempt.id, codeHash, now });
    await recordOAuthFailure({ database, providerId: provider.id, providerKey: provider.providerKey, reason: "callback_replay", ipAddress, userAgent, requestId });
    throw new Error("oauth callback is invalid");
  }

  const tokens = await exchangeAuthorizationCode({
    runtime,
    authorizationCode,
    codeVerifier,
    redirectUri: oauthCallbackUrl(requestUrl, provider.providerKey),
    fetchImpl,
  });
  const profile = await fetchOAuthProfile({ runtime, tokens, fetchImpl });
  const resolved = await resolveOAuthIdentity({
    database,
    provider,
    profile,
    auditContext: { requestId, ipAddress, userAgent },
    now,
  });

  await database
    .update(oauthLoginAttempts)
    .set({
      authorizationCodeHash: codeHash,
      status: "completed",
      consumedAt: now,
      updatedAt: now,
    })
    .where(eq(oauthLoginAttempts.id, attempt.id));

  await recordIdentityAuditEvent({
    database,
    organizationId: resolved.organizationId,
    userId: resolved.user.id,
    actorUserId: resolved.user.id,
    providerId: provider.id,
    externalIdentityId: resolved.externalIdentity.id,
    eventType: IDENTITY_AUDIT_EVENT_TYPES.OAUTH_LOGIN_COMPLETED,
    action: OAUTH_AUDIT_EVENTS.LOGIN_COMPLETED,
    result: "success",
    ipAddress,
    userAgent,
    requestId,
    metadata: {
      providerKey: provider.providerKey,
      createdUser: resolved.createdUser,
      linkedIdentity: resolved.linkedIdentity,
    },
  });

  const authResult = await completePrimaryAuthentication({
    database,
    userId: resolved.user.id,
    organizationId: resolved.organizationId,
    settings: resolved.settings,
    ipAddress,
    userAgent,
    requestId,
    now,
  });

  return {
    ...authResult,
    redirectPath: attempt.redirectPath || "/",
    user: publicOAuthUser(resolved.user),
    provider: publicOAuthProvider(provider, runtime),
    createdUser: resolved.createdUser,
    linkedIdentity: resolved.linkedIdentity,
  };
}

export async function resolveOAuthIdentity({
  database = db(),
  provider,
  profile,
  auditContext = {},
  now = new Date(),
} = {}) {
  const normalized = normalizeOAuthProfile(provider.providerKey, profile);
  if (!normalized.email || !normalized.emailVerified) {
    throw new Error("verified provider email is required");
  }

  const existingExternal = await findExternalIdentity({
    database,
    providerId: provider.id,
    externalSubjectId: normalized.subject,
  });

  if (existingExternal) {
    const [membership] = await firstActiveMembership(database, existingExternal.userId);
    if (!membership) {
      throw new Error("linked identity has no active organization");
    }

    const [user] = await database
      .select()
      .from(users)
      .where(and(eq(users.id, existingExternal.userId), eq(users.status, "active"), isNull(users.deletedAt)))
      .limit(1);

    if (!user) {
      throw new Error("linked identity user is not active");
    }

    await database
      .update(externalIdentities)
      .set({ lastSeenAt: now, updatedAt: now })
      .where(eq(externalIdentities.id, existingExternal.id));

    return {
      user,
      organizationId: membership.organization.id,
      settings: membership.settings,
      externalIdentity: existingExternal,
      createdUser: false,
      linkedIdentity: false,
    };
  }

  const emailHash = hashIdentityValue(normalized.email);
  const [existingUser] = await database
    .select()
    .from(users)
    .where(and(eq(users.email, normalized.email), isNull(users.deletedAt)))
    .limit(1);

  if (existingUser && existingUser.status !== "active") {
    throw new Error("user is not active");
  }

  if (existingUser && !normalized.emailVerified) {
    throw new Error("verified provider email is required");
  }

  if (existingUser) {
    const [membership] = await firstActiveMembership(database, existingUser.id);
    if (!membership) {
      throw new Error("existing user has no active organization");
    }

    const linked = await linkExternalIdentity({
      database,
      organizationId: membership.organization.id,
      userId: existingUser.id,
      providerId: provider.id,
      externalSubjectId: normalized.subject,
      providerEmail: normalized.email,
      emailVerified: true,
      metadata: { providerKey: provider.providerKey, emailHash },
      auditContext: { ...auditContext, userId: existingUser.id },
    });

    return {
      user: existingUser,
      organizationId: membership.organization.id,
      settings: membership.settings,
      externalIdentity: linked,
      createdUser: false,
      linkedIdentity: true,
    };
  }

  const [createdUser] = await database
    .insert(users)
    .values({
      email: normalized.email,
      status: "active",
      emailVerifiedAt: now,
      lastLoginAt: now,
    })
    .returning();

  const orgName = `${normalized.email.split("@")[0] || "User"} Workspace`;
  const createdOrg = await createOrganizationForUser({
    database,
    userId: createdUser.id,
    name: orgName,
    slug: uniqueSlugFromEmail(normalized.email),
    auditContext: { ...auditContext, userId: createdUser.id },
  });

  const linked = await linkExternalIdentity({
    database,
    organizationId: createdOrg.organization.id,
    userId: createdUser.id,
    providerId: provider.id,
    externalSubjectId: normalized.subject,
    providerEmail: normalized.email,
    emailVerified: true,
    metadata: { providerKey: provider.providerKey, emailHash },
    auditContext: { ...auditContext, userId: createdUser.id },
  });

  await recordIdentityAuditEvent({
    database,
    organizationId: createdOrg.organization.id,
    userId: createdUser.id,
    actorUserId: createdUser.id,
    providerId: provider.id,
    externalIdentityId: linked.id,
    eventType: IDENTITY_AUDIT_EVENT_TYPES.OAUTH_IDENTITY_CREATED,
    action: OAUTH_AUDIT_EVENTS.IDENTITY_CREATED,
    result: "success",
    requestId: auditContext.requestId,
    ipAddress: auditContext.ipAddress,
    userAgent: auditContext.userAgent,
    metadata: { providerKey: provider.providerKey },
  });

  return {
    user: createdUser,
    organizationId: createdOrg.organization.id,
    settings: null,
    externalIdentity: linked,
    createdUser: true,
    linkedIdentity: true,
  };
}

export function buildAuthorizationUrl({ runtime, state, codeChallenge, redirectUri } = {}) {
  const url = new URL(runtime.authorizationEndpoint);
  url.searchParams.set("client_id", runtime.clientId);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("state", state);
  url.searchParams.set("scope", runtime.scopes.join(" "));
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");

  if (runtime.providerKey === "google") {
    url.searchParams.set("access_type", "offline");
    url.searchParams.set("prompt", "select_account");
  }

  return url.toString();
}

export async function exchangeAuthorizationCode({
  runtime,
  authorizationCode,
  codeVerifier,
  redirectUri,
  fetchImpl = fetch,
} = {}) {
  const body = new URLSearchParams({
    client_id: runtime.clientId,
    client_secret: runtime.clientSecret,
    code: authorizationCode,
    code_verifier: codeVerifier,
    grant_type: "authorization_code",
    redirect_uri: redirectUri,
  });

  const response = await fetchImpl(runtime.tokenEndpoint, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/x-www-form-urlencoded",
    },
    body,
  });

  const payload = await safeJson(response);
  if (!response.ok || !payload?.access_token) {
    throw new Error("oauth token exchange failed");
  }

  return {
    accessToken: payload.access_token,
    tokenType: payload.token_type || "Bearer",
    expiresIn: payload.expires_in || null,
  };
}

export async function fetchOAuthProfile({ runtime, tokens, fetchImpl = fetch } = {}) {
  const userResponse = await fetchImpl(runtime.userInfoEndpoint, {
    headers: {
      accept: "application/json",
      authorization: `${tokens.tokenType || "Bearer"} ${tokens.accessToken}`,
    },
  });
  const userPayload = await safeJson(userResponse);
  if (!userResponse.ok) {
    throw new Error("oauth profile lookup failed");
  }

  if (runtime.providerKey !== "github" || userPayload.email) {
    return userPayload;
  }

  const emailResponse = await fetchImpl(runtime.emailsEndpoint, {
    headers: {
      accept: "application/json",
      authorization: `${tokens.tokenType || "Bearer"} ${tokens.accessToken}`,
    },
  });
  const emailPayload = await safeJson(emailResponse);
  if (!emailResponse.ok || !Array.isArray(emailPayload)) {
    return userPayload;
  }

  const primary = emailPayload.find((email) => email.primary && email.verified) || emailPayload.find((email) => email.verified);
  return {
    ...userPayload,
    email: primary?.email || userPayload.email,
    email_verified: Boolean(primary?.verified || userPayload.email),
  };
}

export function normalizeOAuthProfile(providerKey, profile = {}) {
  const key = normalizeProviderKey(providerKey);
  if (key === "google") {
    return {
      subject: safeString(profile.sub, 255),
      email: normalizeEmail(profile.email),
      emailVerified: profile.email_verified === true || profile.email_verified === "true",
      displayName: safeString(profile.name, 160),
    };
  }

  if (key === "github") {
    return {
      subject: safeString(profile.id, 255),
      email: normalizeEmail(profile.email),
      emailVerified: profile.email_verified !== false && Boolean(profile.email),
      displayName: safeString(profile.name || profile.login, 160),
    };
  }

  throw new Error("oauth provider is not supported");
}

export function oauthRuntimeConfig(providerKey, provider = {}, env = process.env) {
  const definition = OAUTH_PROVIDER_DEFINITIONS[normalizeProviderKey(providerKey)];
  if (!definition) {
    throw new Error("oauth provider is not supported");
  }

  const clientId = env[definition.clientIdEnv] || provider.clientId || "";
  const clientSecret = env[definition.clientSecretEnv] || "";
  const scopes = Array.isArray(provider.scopes) && provider.scopes.length > 0 ? provider.scopes : definition.scopes;

  return {
    providerKey: definition.providerKey,
    providerType: definition.providerType,
    displayName: provider.displayName || definition.displayName,
    clientId,
    clientSecret,
    scopes: [...scopes],
    authorizationEndpoint: provider.authorizationEndpoint || definition.authorizationEndpoint,
    tokenEndpoint: provider.tokenEndpoint || definition.tokenEndpoint,
    userInfoEndpoint: provider.userInfoEndpoint || definition.userInfoEndpoint,
    emailsEndpoint: definition.emailsEndpoint,
    configured: Boolean(clientId && clientSecret),
  };
}

export function pkceChallenge(codeVerifier) {
  return crypto.createHash("sha256").update(codeVerifier, "utf8").digest("base64url");
}

export function randomUrlToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

export function oauthCallbackUrl(requestUrl, providerKey) {
  const url = new URL(requestUrl || "http://localhost:3000");
  return `${url.origin}/api/auth/oauth/${encodeURIComponent(normalizeProviderKey(providerKey))}/callback`;
}

export function normalizeRedirectPath(value) {
  const path = safeString(value, 255) || "/";
  if (!path.startsWith("/") || path.startsWith("//")) {
    return "/";
  }
  return path;
}

async function getEnabledOAuthProvider({ database, providerKey } = {}) {
  const normalizedProviderKey = normalizeProviderKey(providerKey);
  const [provider] = await database
    .select()
    .from(identityProviders)
    .where(
      and(
        eq(identityProviders.providerKey, normalizedProviderKey),
        eq(identityProviders.status, IDENTITY_PROVIDER_STATUSES.ACTIVE),
        isNull(identityProviders.organizationId),
        isNull(identityProviders.deletedAt),
      ),
    )
    .limit(1);

  if (!provider || !OAUTH_PROVIDER_DEFINITIONS[provider.providerKey]) {
    throw new Error("oauth provider is not available");
  }

  return provider;
}

async function firstActiveMembership(database, userId) {
  return database
    .select({
      membership: organizationMemberships,
      organization: organizations,
      settings: organizationSettings,
    })
    .from(organizationMemberships)
    .innerJoin(organizations, eq(organizations.id, organizationMemberships.organizationId))
    .leftJoin(
      organizationSettings,
      eq(organizationSettings.organizationId, organizationMemberships.organizationId),
    )
    .where(
      and(
        eq(organizationMemberships.userId, userId),
        eq(organizationMemberships.status, "active"),
        eq(organizations.status, "active"),
        isNull(organizations.deletedAt),
      ),
    )
    .orderBy(asc(organizationMemberships.createdAt))
    .limit(1);
}

async function failOAuthAttempt({ database, attemptId, codeHash = null, now = new Date() } = {}) {
  const changes = { status: "failed", consumedAt: now, updatedAt: now };
  if (codeHash) {
    changes.authorizationCodeHash = codeHash;
  }

  await database.update(oauthLoginAttempts).set(changes).where(eq(oauthLoginAttempts.id, attemptId));
}

async function recordOAuthFailure({
  database,
  providerId = null,
  providerKey,
  reason,
  ipAddress,
  userAgent,
  requestId,
} = {}) {
  await recordIdentityAuditEvent({
    database,
    providerId,
    eventType: IDENTITY_AUDIT_EVENT_TYPES.OAUTH_LOGIN_FAILED,
    action: OAUTH_AUDIT_EVENTS.LOGIN_FAILED,
    result: "failure",
    ipAddress,
    userAgent,
    requestId,
    metadata: { providerKey, reason },
  }).catch(() => null);
}

function publicOAuthProvider(provider, runtime) {
  return {
    id: provider.id,
    providerKey: provider.providerKey,
    providerType: provider.providerType,
    displayName: provider.displayName || runtime.displayName,
    configured: runtime.configured,
  };
}

function publicOAuthUser(user = {}) {
  return {
    id: user.id,
    email: user.email,
    status: user.status,
  };
}

function normalizeProviderKey(value) {
  const key = safeString(value, 80)?.toLowerCase();
  if (!key || !OAUTH_PROVIDER_DEFINITIONS[key]) {
    throw new Error("oauth provider is not supported");
  }
  return key;
}

function uniqueSlugFromEmail(email) {
  const local = String(email).split("@")[0] || "user";
  const base = local.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "user";
  return `${base}-${crypto.randomBytes(4).toString("hex")}`;
}

async function safeJson(response) {
  try {
    return await response.json();
  } catch {
    return null;
  }
}
