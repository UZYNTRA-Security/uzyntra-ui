import "server-only";

import crypto from "node:crypto";
import { and, eq, gt, isNotNull, isNull, or } from "drizzle-orm";
import { db } from "../../db/client.js";
import {
  externalIdentities,
  identityProviders,
  organizationMemberships,
  organizationSettings,
  organizations,
  ssoLoginAttempts,
  users,
} from "../../db/schema.js";
import {
  EXTERNAL_IDENTITY_STATUSES,
  IDENTITY_AUDIT_EVENT_TYPES,
  IDENTITY_PROVIDER_STATUSES,
  IDENTITY_PROVIDER_TYPES,
  findExternalIdentity,
  hashIdentityValue,
  linkExternalIdentity,
  normalizeIdentityProvider,
  publicIdentityProvider,
  recordIdentityAuditEvent,
  sanitizeIdentityMetadata,
} from "../identity/index.js";
import { normalizeEmail, safeString } from "../management/tokens.js";
import { completePrimaryAuthentication } from "./mfa.js";
import { pkceChallenge, randomUrlToken } from "./oauth.js";

export const SSO_FLOW_TYPES = Object.freeze({
  SAML: "saml",
  OIDC: "oidc",
});

export const SSO_ATTEMPT_STATUSES = Object.freeze({
  PENDING: "pending",
  COMPLETED: "completed",
  FAILED: "failed",
  EXPIRED: "expired",
});

export const SSO_AUDIT_EVENTS = Object.freeze({
  LOGIN_STARTED: "sso.login.started",
  LOGIN_COMPLETED: "sso.login.completed",
  LOGIN_FAILED: "sso.login.failed",
  PROVIDER_CREATED: "sso.provider.created",
  PROVIDER_UPDATED: "sso.provider.updated",
  POLICY_CHANGED: "sso.policy.changed",
});

export const SSO_ATTEMPT_TTL_SECONDS = 600;

export function ssoStateCookieName(flowType, providerKey) {
  return `uzyntra_sso_${normalizeSsoFlow(flowType)}_${normalizeProviderKey(providerKey)}_state`;
}

export function ssoPkceCookieName(providerKey) {
  return `uzyntra_sso_oidc_${normalizeProviderKey(providerKey)}_pkce`;
}

export function ssoCookieOptions(expiresAt) {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    expires: expiresAt,
  };
}

export function expiredSsoCookieOptions() {
  return {
    ...ssoCookieOptions(new Date(0)),
    maxAge: 0,
  };
}

export async function listEnterpriseSsoProviders({
  database = db(),
  organizationId,
  includeDeleted = false,
} = {}) {
  if (!organizationId) {
    throw new Error("organizationId is required");
  }

  const filters = [
    eq(identityProviders.organizationId, organizationId),
    or(
      eq(identityProviders.providerType, IDENTITY_PROVIDER_TYPES.SAML),
      eq(identityProviders.providerType, IDENTITY_PROVIDER_TYPES.OIDC),
    ),
  ];
  if (!includeDeleted) {
    filters.push(isNull(identityProviders.deletedAt));
  }

  const providers = await database
    .select()
    .from(identityProviders)
    .where(and(...filters))
    .limit(50);

  return providers.map(publicEnterpriseSsoProvider);
}

export async function createEnterpriseSsoProvider({
  database = db(),
  organizationId,
  createdByUserId = null,
  providerKey,
  providerType,
  displayName,
  status = IDENTITY_PROVIDER_STATUSES.DISABLED,
  issuer,
  clientId = null,
  allowedDomains = [],
  authorizationEndpoint = null,
  tokenEndpoint = null,
  userInfoEndpoint = null,
  configuration = {},
  configurationRef = null,
  secretRef = null,
  auditContext = {},
} = {}) {
  const normalizedType = normalizeSsoFlow(providerType);
  const provider = normalizeIdentityProvider({
    organizationId,
    providerKey,
    providerType: normalizedType,
    displayName,
    status,
    issuer,
    clientId,
    scopes:
      normalizedType === SSO_FLOW_TYPES.OIDC
        ? configuration.scopes || ["openid", "email", "profile"]
        : [],
    allowedDomains,
    authorizationEndpoint,
    tokenEndpoint,
    userInfoEndpoint,
    configuration: sanitizeSsoConfiguration(configuration),
    configurationRef,
    secretRef,
    createdByUserId,
  });

  const [existing] = await database
    .select({ id: identityProviders.id })
    .from(identityProviders)
    .where(
      and(
        eq(identityProviders.organizationId, organizationId),
        eq(identityProviders.providerKey, provider.providerKey),
      ),
    )
    .limit(1);

  const [created] = await database
    .insert(identityProviders)
    .values(provider)
    .onConflictDoUpdate({
      target: [identityProviders.organizationId, identityProviders.providerKey],
      set: {
        providerType: provider.providerType,
        displayName: provider.displayName,
        status: provider.status,
        issuer: provider.issuer,
        clientId: provider.clientId,
        scopes: provider.scopes,
        allowedDomains: provider.allowedDomains,
        authorizationEndpoint: provider.authorizationEndpoint,
        tokenEndpoint: provider.tokenEndpoint,
        userInfoEndpoint: provider.userInfoEndpoint,
        configuration: provider.configuration,
        configurationRef: provider.configurationRef,
        secretRef: provider.secretRef,
        updatedAt: new Date(),
        deletedAt: null,
      },
    })
    .returning();

  await recordIdentityAuditEvent({
    database,
    organizationId,
    actorUserId: auditContext.userId || createdByUserId,
    providerId: created.id,
    eventType: existing
      ? IDENTITY_AUDIT_EVENT_TYPES.SSO_PROVIDER_UPDATED
      : IDENTITY_AUDIT_EVENT_TYPES.SSO_PROVIDER_CREATED,
    action: existing ? SSO_AUDIT_EVENTS.PROVIDER_UPDATED : SSO_AUDIT_EVENTS.PROVIDER_CREATED,
    result: "success",
    requestId: auditContext.requestId,
    ipAddress: auditContext.ipAddress,
    userAgent: auditContext.userAgent,
    metadata: {
      providerKey: created.providerKey,
      providerType: created.providerType,
      allowedDomains: created.allowedDomains || [],
    },
  });

  return publicEnterpriseSsoProvider(created);
}

export async function startSamlLogin({
  database = db(),
  providerKey,
  requestUrl,
  redirectPath = "/",
  ipAddress,
  userAgent,
  requestId,
  now = new Date(),
} = {}) {
  const provider = await getEnabledEnterpriseProvider({
    database,
    providerKey,
    providerType: SSO_FLOW_TYPES.SAML,
  });
  const state = randomUrlToken(32);
  const expiresAt = new Date(now.getTime() + SSO_ATTEMPT_TTL_SECONDS * 1000);
  const acsUrl = ssoCallbackUrl(requestUrl, SSO_FLOW_TYPES.SAML, provider.providerKey);
  const samlRequest = buildSamlAuthnRequest({
    issuer: provider.configuration?.spEntityId || new URL(requestUrl).origin,
    acsUrl,
    destination: provider.authorizationEndpoint || provider.configuration?.singleSignOnUrl,
    requestId: `_${crypto.randomUUID()}`,
    now,
  });

  const [attempt] = await database
    .insert(ssoLoginAttempts)
    .values({
      organizationId: provider.organizationId,
      providerId: provider.id,
      flowType: SSO_FLOW_TYPES.SAML,
      stateHash: hashIdentityValue(state),
      redirectPath: normalizeRedirectPath(redirectPath),
      status: SSO_ATTEMPT_STATUSES.PENDING,
      expiresAt,
      ipAddress,
      userAgent,
      metadata: { providerKey: provider.providerKey, flowType: SSO_FLOW_TYPES.SAML },
    })
    .returning();

  await recordSsoAudit({
    database,
    provider,
    eventType: IDENTITY_AUDIT_EVENT_TYPES.SSO_LOGIN_STARTED,
    action: SSO_AUDIT_EVENTS.LOGIN_STARTED,
    result: "success",
    requestId,
    ipAddress,
    userAgent,
    metadata: { flowType: SSO_FLOW_TYPES.SAML, attemptId: attempt.id },
  });

  const redirectUrl = new URL(provider.authorizationEndpoint || provider.configuration?.singleSignOnUrl);
  redirectUrl.searchParams.set("SAMLRequest", Buffer.from(samlRequest, "utf8").toString("base64"));
  redirectUrl.searchParams.set("RelayState", state);

  return {
    provider: publicEnterpriseSsoProvider(provider),
    state,
    expiresAt,
    redirectUrl: redirectUrl.toString(),
  };
}

export async function completeSamlCallback({
  database = db(),
  providerKey,
  requestUrl,
  relayState,
  stateCookie,
  samlResponse,
  ipAddress,
  userAgent,
  requestId,
  now = new Date(),
} = {}) {
  const provider = await getEnabledEnterpriseProvider({
    database,
    providerKey,
    providerType: SSO_FLOW_TYPES.SAML,
  });

  if (!relayState || !stateCookie || relayState !== stateCookie) {
    await recordSsoFailure({ database, provider, reason: "invalid_state", ipAddress, userAgent, requestId });
    throw new Error("sso state is invalid");
  }

  const stateHash = hashIdentityValue(relayState);
  const [attempt] = await database
    .select()
    .from(ssoLoginAttempts)
    .where(
      and(
        eq(ssoLoginAttempts.providerId, provider.id),
        eq(ssoLoginAttempts.stateHash, stateHash),
        eq(ssoLoginAttempts.status, SSO_ATTEMPT_STATUSES.PENDING),
        gt(ssoLoginAttempts.expiresAt, now),
      ),
    )
    .limit(1);

  if (!attempt) {
    await recordSsoFailure({ database, provider, reason: "state_replay_or_expired", ipAddress, userAgent, requestId });
    throw new Error("sso callback is invalid");
  }

  const assertion = parseSamlResponse(samlResponse);
  validateSamlAssertion({ provider, assertion, requestUrl, now });
  const assertionIdHash = hashIdentityValue(assertion.assertionId);

  const [replayed] = await database
    .select({ id: ssoLoginAttempts.id })
    .from(ssoLoginAttempts)
    .where(eq(ssoLoginAttempts.assertionIdHash, assertionIdHash))
    .limit(1);
  if (replayed) {
    await failSsoAttempt({ database, attemptId: attempt.id, now, assertionIdHash });
    await recordSsoFailure({ database, provider, reason: "assertion_replay", ipAddress, userAgent, requestId });
    throw new Error("sso callback is invalid");
  }

  const resolved = await resolveEnterpriseSsoIdentity({
    database,
    provider,
    profile: {
      subject: assertion.subject,
      email: assertion.email,
      emailVerified: true,
      displayName: assertion.displayName,
    },
    auditContext: { requestId, ipAddress, userAgent },
    now,
  });

  await completeSsoAttempt({ database, attemptId: attempt.id, now, assertionIdHash });
  await recordSsoCompletion({ database, provider, resolved, requestId, ipAddress, userAgent });

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
    provider: publicEnterpriseSsoProvider(provider),
    user: publicSsoUser(resolved.user),
    createdUser: resolved.createdUser,
    linkedIdentity: resolved.linkedIdentity,
  };
}

export async function startEnterpriseOidcLogin({
  database = db(),
  providerKey,
  requestUrl,
  redirectPath = "/",
  ipAddress,
  userAgent,
  requestId,
  now = new Date(),
} = {}) {
  const provider = await getEnabledEnterpriseProvider({
    database,
    providerKey,
    providerType: SSO_FLOW_TYPES.OIDC,
  });
  const state = randomUrlToken(32);
  const codeVerifier = randomUrlToken(48);
  const codeChallenge = pkceChallenge(codeVerifier);
  const expiresAt = new Date(now.getTime() + SSO_ATTEMPT_TTL_SECONDS * 1000);
  const redirectUri = ssoCallbackUrl(requestUrl, SSO_FLOW_TYPES.OIDC, provider.providerKey);

  const [attempt] = await database
    .insert(ssoLoginAttempts)
    .values({
      organizationId: provider.organizationId,
      providerId: provider.id,
      flowType: SSO_FLOW_TYPES.OIDC,
      stateHash: hashIdentityValue(state),
      pkceVerifierHash: hashIdentityValue(codeVerifier),
      redirectPath: normalizeRedirectPath(redirectPath),
      status: SSO_ATTEMPT_STATUSES.PENDING,
      expiresAt,
      ipAddress,
      userAgent,
      metadata: { providerKey: provider.providerKey, flowType: SSO_FLOW_TYPES.OIDC },
    })
    .returning();

  await recordSsoAudit({
    database,
    provider,
    eventType: IDENTITY_AUDIT_EVENT_TYPES.SSO_LOGIN_STARTED,
    action: SSO_AUDIT_EVENTS.LOGIN_STARTED,
    result: "success",
    requestId,
    ipAddress,
    userAgent,
    metadata: { flowType: SSO_FLOW_TYPES.OIDC, attemptId: attempt.id },
  });

  return {
    provider: publicEnterpriseSsoProvider(provider),
    state,
    codeVerifier,
    expiresAt,
    authorizationUrl: buildEnterpriseOidcAuthorizationUrl({
      provider,
      state,
      codeChallenge,
      redirectUri,
    }),
  };
}

export async function completeEnterpriseOidcCallback({
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
  const provider = await getEnabledEnterpriseProvider({
    database,
    providerKey,
    providerType: SSO_FLOW_TYPES.OIDC,
  });

  if (!state || !stateCookie || state !== stateCookie || !authorizationCode || !codeVerifier) {
    await recordSsoFailure({ database, provider, reason: "invalid_callback", ipAddress, userAgent, requestId });
    throw new Error("sso callback is invalid");
  }

  const stateHash = hashIdentityValue(state);
  const verifierHash = hashIdentityValue(codeVerifier);
  const codeHash = hashIdentityValue(authorizationCode);
  const [attempt] = await database
    .select()
    .from(ssoLoginAttempts)
    .where(
      and(
        eq(ssoLoginAttempts.providerId, provider.id),
        eq(ssoLoginAttempts.stateHash, stateHash),
        eq(ssoLoginAttempts.pkceVerifierHash, verifierHash),
        eq(ssoLoginAttempts.status, SSO_ATTEMPT_STATUSES.PENDING),
        gt(ssoLoginAttempts.expiresAt, now),
      ),
    )
    .limit(1);

  if (!attempt) {
    await recordSsoFailure({ database, provider, reason: "state_replay_or_expired", ipAddress, userAgent, requestId });
    throw new Error("sso callback is invalid");
  }

  const [replayed] = await database
    .select({ id: ssoLoginAttempts.id })
    .from(ssoLoginAttempts)
    .where(eq(ssoLoginAttempts.authorizationCodeHash, codeHash))
    .limit(1);
  if (replayed) {
    await failSsoAttempt({ database, attemptId: attempt.id, now, codeHash });
    await recordSsoFailure({ database, provider, reason: "callback_replay", ipAddress, userAgent, requestId });
    throw new Error("sso callback is invalid");
  }

  const tokens = await exchangeEnterpriseOidcCode({
    provider,
    authorizationCode,
    codeVerifier,
    redirectUri: ssoCallbackUrl(requestUrl, SSO_FLOW_TYPES.OIDC, provider.providerKey),
    fetchImpl,
    env,
  });
  const profile = normalizeEnterpriseOidcProfile(provider, tokens);
  const resolved = await resolveEnterpriseSsoIdentity({
    database,
    provider,
    profile,
    auditContext: { requestId, ipAddress, userAgent },
    now,
  });

  await completeSsoAttempt({ database, attemptId: attempt.id, now, codeHash });
  await recordSsoCompletion({ database, provider, resolved, requestId, ipAddress, userAgent });

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
    provider: publicEnterpriseSsoProvider(provider),
    user: publicSsoUser(resolved.user),
    createdUser: resolved.createdUser,
    linkedIdentity: resolved.linkedIdentity,
  };
}

export async function resolveEnterpriseSsoIdentity({
  database = db(),
  provider,
  profile,
  auditContext = {},
  now = new Date(),
} = {}) {
  if (!provider?.organizationId) {
    throw new Error("enterprise provider organization is required");
  }

  const normalized = normalizeEnterpriseProfile(profile);
  if (!normalized.email || !normalized.emailVerified) {
    throw new Error("verified enterprise email is required");
  }
  if (!isEmailAllowedForSso(normalized.email, provider.allowedDomains)) {
    throw new Error("enterprise email domain is not allowed");
  }

  const existingExternal = await findExternalIdentity({
    database,
    providerId: provider.id,
    externalSubjectId: normalized.subject,
  });

  if (existingExternal) {
    const [membership] = await activeMembershipForOrganization({
      database,
      organizationId: provider.organizationId,
      userId: existingExternal.userId,
    });
    if (!membership) {
      throw new Error("linked enterprise identity is not available in organization");
    }

    const [user] = await database
      .select()
      .from(users)
      .where(and(eq(users.id, existingExternal.userId), eq(users.status, "active"), isNull(users.deletedAt)))
      .limit(1);
    if (!user) {
      throw new Error("linked enterprise user is not active");
    }

    await database
      .update(externalIdentities)
      .set({ lastSeenAt: now, updatedAt: now })
      .where(eq(externalIdentities.id, existingExternal.id));

    return {
      user,
      organizationId: provider.organizationId,
      settings: membership.settings,
      externalIdentity: existingExternal,
      createdUser: false,
      linkedIdentity: false,
    };
  }

  const [existingUser] = await database
    .select()
    .from(users)
    .where(and(eq(users.email, normalized.email), isNull(users.deletedAt)))
    .limit(1);

  if (existingUser && existingUser.status !== "active") {
    throw new Error("enterprise user is not active");
  }

  const user = existingUser || (await createEnterpriseUser({ database, profile: normalized, now }));
  const [membership] = await ensureEnterpriseMembership({
    database,
    organizationId: provider.organizationId,
    userId: user.id,
  });

  const linked = await linkExternalIdentity({
    database,
    organizationId: provider.organizationId,
    userId: user.id,
    providerId: provider.id,
    externalSubjectId: normalized.subject,
    providerEmail: normalized.email,
    emailVerified: true,
    metadata: {
      providerKey: provider.providerKey,
      providerType: provider.providerType,
      enterpriseDomain: normalized.email.split("@")[1],
    },
    auditContext: { ...auditContext, userId: user.id },
  });

  const [loadedMembership] = membership.settings
    ? [membership]
    : await activeMembershipForOrganization({
        database,
        organizationId: provider.organizationId,
        userId: user.id,
      });

  return {
    user,
    organizationId: provider.organizationId,
    settings: loadedMembership?.settings || null,
    externalIdentity: linked,
    createdUser: !existingUser,
    linkedIdentity: true,
  };
}

export function buildEnterpriseOidcAuthorizationUrl({ provider, state, codeChallenge, redirectUri } = {}) {
  const url = new URL(requiredString(provider.authorizationEndpoint, "authorization endpoint"));
  url.searchParams.set("client_id", requiredString(provider.clientId, "clientId"));
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("state", state);
  url.searchParams.set("scope", normalizeScopes(provider.scopes).join(" "));
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  return url.toString();
}

export function parseSamlResponse(samlResponse) {
  const xml = decodeSamlResponse(samlResponse);
  if (/<!DOCTYPE|<!ENTITY/i.test(xml)) {
    throw new Error("saml response contains unsafe xml");
  }

  const assertionId = matchXmlAttribute(xml, "Assertion", "ID") || matchXmlAttribute(xml, "Response", "ID");
  const issuer = matchXmlText(xml, "Issuer");
  const subject = matchXmlText(xml, "NameID");
  const audience = matchXmlText(xml, "Audience");
  const notBefore = matchXmlAttribute(xml, "Conditions", "NotBefore");
  const notOnOrAfter = matchXmlAttribute(xml, "Conditions", "NotOnOrAfter");
  const email =
    matchSamlAttribute(xml, "email") ||
    matchSamlAttribute(xml, "emailaddress") ||
    matchSamlAttribute(xml, "mail") ||
    subject;
  const displayName = matchSamlAttribute(xml, "name") || matchSamlAttribute(xml, "displayname");

  return {
    assertionId: requiredString(assertionId, "saml assertion id"),
    issuer: requiredString(issuer, "saml issuer"),
    subject: requiredString(subject, "saml subject"),
    audience: requiredString(audience, "saml audience"),
    notBefore: notBefore || null,
    notOnOrAfter: requiredString(notOnOrAfter, "saml expiry"),
    email: normalizeEmail(email),
    displayName: safeString(displayName, 160),
    hasSignature: /<[^>]*(?:ds:)?Signature[\s>]/i.test(xml),
  };
}

export function validateSamlAssertion({ provider, assertion, requestUrl, now = new Date() } = {}) {
  if (provider.issuer && assertion.issuer !== provider.issuer) {
    throw new Error("saml issuer is invalid");
  }

  const expectedAudience = provider.configuration?.spEntityId || new URL(requestUrl || "http://localhost").origin;
  if (assertion.audience !== expectedAudience) {
    throw new Error("saml audience is invalid");
  }

  if (assertion.notBefore && new Date(assertion.notBefore).getTime() > now.getTime() + 60_000) {
    throw new Error("saml assertion is not active");
  }
  if (new Date(assertion.notOnOrAfter).getTime() <= now.getTime()) {
    throw new Error("saml assertion is expired");
  }

  if (provider.configuration?.signatureRequired !== false && !assertion.hasSignature) {
    throw new Error("saml signature is required");
  }

  return true;
}

export function normalizeEnterpriseOidcProfile(provider, tokens = {}) {
  const claims = parseJwtPayload(tokens.idToken);
  if (!claims.sub) {
    throw new Error("oidc subject is required");
  }
  if (provider.issuer && claims.iss !== provider.issuer) {
    throw new Error("oidc issuer is invalid");
  }
  if (provider.clientId && claims.aud !== provider.clientId && !asArray(claims.aud).includes(provider.clientId)) {
    throw new Error("oidc audience is invalid");
  }
  if (Number(claims.exp || 0) * 1000 <= Date.now()) {
    throw new Error("oidc token is expired");
  }
  if (!claims.email_verified) {
    throw new Error("verified enterprise email is required");
  }

  return {
    subject: safeString(claims.sub, 255),
    email: normalizeEmail(claims.email),
    emailVerified: true,
    displayName: safeString(claims.name || claims.preferred_username, 160),
  };
}

export function publicEnterpriseSsoProvider(provider = {}) {
  return {
    ...publicIdentityProvider(provider),
    enterprise: Boolean(provider.organizationId),
    allowedDomains: Array.isArray(provider.allowedDomains) ? provider.allowedDomains : [],
    configurationRef: provider.configurationRef || null,
    secretRef: provider.secretRef ? maskRef(provider.secretRef) : null,
    metadataUrl: provider.configuration?.metadataUrl || null,
    singleSignOnUrl: provider.configuration?.singleSignOnUrl || provider.authorizationEndpoint || null,
    jwksUri: provider.configuration?.jwksUri || null,
  };
}

export function sanitizeSsoConfiguration(configuration = {}) {
  const clean = sanitizeIdentityMetadata(configuration || {});
  if (clean.metadataUrl) clean.metadataUrl = safeHttpsUrl(clean.metadataUrl);
  if (clean.singleSignOnUrl) clean.singleSignOnUrl = safeHttpsUrl(clean.singleSignOnUrl);
  if (clean.jwksUri) clean.jwksUri = safeHttpsUrl(clean.jwksUri);
  if (clean.spEntityId) clean.spEntityId = safeString(clean.spEntityId, 255);
  if (clean.signatureRequired !== undefined) clean.signatureRequired = clean.signatureRequired !== false;
  return clean;
}

export function ssoCallbackUrl(requestUrl, flowType, providerKey) {
  const url = new URL(requestUrl || "http://localhost:3000");
  return `${url.origin}/api/auth/sso/${normalizeSsoFlow(flowType)}/${encodeURIComponent(
    normalizeProviderKey(providerKey),
  )}/callback`;
}

async function getEnabledEnterpriseProvider({ database, providerKey, providerType } = {}) {
  const normalizedProviderKey = normalizeProviderKey(providerKey);
  const normalizedType = normalizeSsoFlow(providerType);
  const [provider] = await database
    .select()
    .from(identityProviders)
    .where(
      and(
        eq(identityProviders.providerKey, normalizedProviderKey),
        eq(identityProviders.providerType, normalizedType),
        eq(identityProviders.status, IDENTITY_PROVIDER_STATUSES.ACTIVE),
        isNotNull(identityProviders.organizationId),
        isNull(identityProviders.deletedAt),
      ),
    )
    .limit(1);

  if (!provider) {
    throw new Error("enterprise sso provider is not available");
  }

  return provider;
}

async function exchangeEnterpriseOidcCode({
  provider,
  authorizationCode,
  codeVerifier,
  redirectUri,
  fetchImpl = fetch,
  env = process.env,
} = {}) {
  const clientSecret = provider.secretRef ? env[provider.secretRef] : "";
  const body = new URLSearchParams({
    client_id: requiredString(provider.clientId, "clientId"),
    code: authorizationCode,
    code_verifier: codeVerifier,
    grant_type: "authorization_code",
    redirect_uri: redirectUri,
  });
  if (clientSecret) {
    body.set("client_secret", clientSecret);
  }

  const response = await fetchImpl(requiredString(provider.tokenEndpoint, "token endpoint"), {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/x-www-form-urlencoded",
    },
    body,
  });
  const payload = await safeJson(response);
  if (!response.ok || !payload?.id_token) {
    throw new Error("enterprise oidc token exchange failed");
  }

  return {
    idToken: payload.id_token,
    accessTokenPresent: Boolean(payload.access_token),
    tokenType: payload.token_type || "Bearer",
    expiresIn: payload.expires_in || null,
  };
}

async function createEnterpriseUser({ database, profile, now }) {
  const [user] = await database
    .insert(users)
    .values({
      email: profile.email,
      status: "active",
      emailVerifiedAt: now,
      lastLoginAt: now,
    })
    .returning();
  return user;
}

async function ensureEnterpriseMembership({ database, organizationId, userId } = {}) {
  const [membership] = await database
    .insert(organizationMemberships)
    .values({ organizationId, userId, status: "active" })
    .onConflictDoUpdate({
      target: [organizationMemberships.organizationId, organizationMemberships.userId],
      set: { status: "active" },
    })
    .returning();

  return [{ membership, settings: null }];
}

function activeMembershipForOrganization({ database, organizationId, userId } = {}) {
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
        eq(organizationMemberships.organizationId, organizationId),
        eq(organizationMemberships.userId, userId),
        eq(organizationMemberships.status, "active"),
        eq(organizations.status, "active"),
        isNull(organizations.deletedAt),
      ),
    )
    .limit(1);
}

async function completeSsoAttempt({ database, attemptId, assertionIdHash = null, codeHash = null, now } = {}) {
  const changes = {
    status: SSO_ATTEMPT_STATUSES.COMPLETED,
    consumedAt: now,
    updatedAt: now,
  };
  if (assertionIdHash) changes.assertionIdHash = assertionIdHash;
  if (codeHash) changes.authorizationCodeHash = codeHash;
  await database.update(ssoLoginAttempts).set(changes).where(eq(ssoLoginAttempts.id, attemptId));
}

async function failSsoAttempt({
  database,
  attemptId,
  assertionIdHash = null,
  codeHash = null,
  now = new Date(),
} = {}) {
  const changes = { status: SSO_ATTEMPT_STATUSES.FAILED, consumedAt: now, updatedAt: now };
  if (assertionIdHash) changes.assertionIdHash = assertionIdHash;
  if (codeHash) changes.authorizationCodeHash = codeHash;
  await database.update(ssoLoginAttempts).set(changes).where(eq(ssoLoginAttempts.id, attemptId));
}

async function recordSsoCompletion({ database, provider, resolved, requestId, ipAddress, userAgent } = {}) {
  await recordSsoAudit({
    database,
    provider,
    userId: resolved.user.id,
    actorUserId: resolved.user.id,
    externalIdentityId: resolved.externalIdentity.id,
    eventType: IDENTITY_AUDIT_EVENT_TYPES.SSO_LOGIN_COMPLETED,
    action: SSO_AUDIT_EVENTS.LOGIN_COMPLETED,
    result: "success",
    requestId,
    ipAddress,
    userAgent,
    metadata: {
      providerKey: provider.providerKey,
      providerType: provider.providerType,
      createdUser: resolved.createdUser,
      linkedIdentity: resolved.linkedIdentity,
    },
  });
}

async function recordSsoFailure({ database, provider, reason, ipAddress, userAgent, requestId } = {}) {
  await recordSsoAudit({
    database,
    provider,
    eventType: IDENTITY_AUDIT_EVENT_TYPES.SSO_LOGIN_FAILED,
    action: SSO_AUDIT_EVENTS.LOGIN_FAILED,
    result: "failure",
    requestId,
    ipAddress,
    userAgent,
    metadata: {
      providerKey: provider?.providerKey,
      providerType: provider?.providerType,
      reason,
    },
  }).catch(() => null);
}

async function recordSsoAudit({
  database,
  provider,
  userId = null,
  actorUserId = null,
  externalIdentityId = null,
  eventType,
  action,
  result,
  requestId,
  ipAddress,
  userAgent,
  metadata = {},
} = {}) {
  return recordIdentityAuditEvent({
    database,
    organizationId: provider?.organizationId || null,
    userId,
    actorUserId,
    providerId: provider?.id || null,
    externalIdentityId,
    eventType,
    action,
    result,
    requestId,
    ipAddress,
    userAgent,
    metadata,
  });
}

function buildSamlAuthnRequest({ issuer, acsUrl, destination, requestId, now }) {
  return [
    `<samlp:AuthnRequest ID="${escapeXml(requestId)}" Version="2.0" IssueInstant="${now.toISOString()}"`,
    ` Destination="${escapeXml(destination)}" AssertionConsumerServiceURL="${escapeXml(acsUrl)}"`,
    ` xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">`,
    `<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${escapeXml(issuer)}</saml:Issuer>`,
    `</samlp:AuthnRequest>`,
  ].join("");
}

function decodeSamlResponse(value) {
  const text = requiredString(value, "saml response");
  try {
    return Buffer.from(text, "base64").toString("utf8");
  } catch {
    throw new Error("saml response is invalid");
  }
}

function matchXmlText(xml, tag) {
  const match = new RegExp(`<[^>]*(?:${tag})[^>]*>([^<]+)</[^>]*(?:${tag})>`, "i").exec(xml);
  return match ? unescapeXml(match[1]) : null;
}

function matchXmlAttribute(xml, tag, attribute) {
  const tagMatch = new RegExp(`<[^>]*(?:${tag})\\b[^>]*>`, "i").exec(xml);
  if (!tagMatch) return null;
  const attrMatch = new RegExp(`${attribute}=["']([^"']+)["']`, "i").exec(tagMatch[0]);
  return attrMatch ? unescapeXml(attrMatch[1]) : null;
}

function matchSamlAttribute(xml, name) {
  const pattern = new RegExp(
    `<[^>]*(?:Attribute)\\b[^>]*(?:Name|FriendlyName)=["'][^"']*${escapeRegex(name)}[^"']*["'][^>]*>[\\s\\S]*?<[^>]*(?:AttributeValue)[^>]*>([^<]+)</[^>]*(?:AttributeValue)>`,
    "i",
  );
  const match = pattern.exec(xml);
  return match ? unescapeXml(match[1]) : null;
}

function parseJwtPayload(token) {
  const parts = String(token || "").split(".");
  if (parts.length < 2) {
    throw new Error("oidc token is invalid");
  }
  try {
    return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    throw new Error("oidc token is invalid");
  }
}

function normalizeEnterpriseProfile(profile = {}) {
  return {
    subject: requiredString(profile.subject, "enterprise subject"),
    email: normalizeEmail(profile.email),
    emailVerified: profile.emailVerified === true,
    displayName: safeString(profile.displayName, 160),
  };
}

function isEmailAllowedForSso(email, allowedDomains = []) {
  const domain = normalizeEmail(email)?.split("@")[1];
  const domains = normalizeDomains(allowedDomains);
  return Boolean(domain && domains.length > 0 && domains.includes(domain));
}

function normalizeScopes(value) {
  return Array.isArray(value) && value.length > 0
    ? value.map((scope) => safeString(scope, 80)).filter(Boolean).slice(0, 20)
    : ["openid", "email", "profile"];
}

function normalizeDomains(value) {
  return Array.isArray(value)
    ? [...new Set(value.map((domain) => safeString(domain, 255)?.toLowerCase()).filter(Boolean))]
    : [];
}

function normalizeSsoFlow(value) {
  const normalized = String(value || "").toLowerCase();
  if (![SSO_FLOW_TYPES.SAML, SSO_FLOW_TYPES.OIDC].includes(normalized)) {
    throw new Error("enterprise sso provider type is invalid");
  }
  return normalized;
}

function normalizeProviderKey(value) {
  const key = safeString(value, 80)?.toLowerCase().replace(/[^a-z0-9_-]/g, "_");
  if (!key || !/^[a-z][a-z0-9_-]*$/.test(key)) {
    throw new Error("enterprise sso provider key is invalid");
  }
  return key;
}

function normalizeRedirectPath(value) {
  const path = safeString(value, 255) || "/";
  return path.startsWith("/") && !path.startsWith("//") ? path : "/";
}

function safeHttpsUrl(value) {
  const text = requiredString(value, "sso url");
  const url = new URL(text);
  if (url.protocol !== "https:") {
    throw new Error("sso url must use https");
  }
  return url.toString();
}

function publicSsoUser(user = {}) {
  return {
    id: user.id,
    email: user.email,
    status: user.status,
  };
}

function asArray(value) {
  return Array.isArray(value) ? value : [value].filter(Boolean);
}

function requiredString(value, label) {
  const text = safeString(value, 4096);
  if (!text) {
    throw new Error(`${label} is required`);
  }
  return text;
}

function escapeXml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function unescapeXml(value) {
  return String(value || "")
    .replace(/&quot;/g, '"')
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

function escapeRegex(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function maskRef(value) {
  const text = String(value || "");
  if (text.length <= 8) return text ? "****" : null;
  return `${text.slice(0, 4)}...${text.slice(-4)}`;
}

async function safeJson(response) {
  try {
    return await response.json();
  } catch {
    return null;
  }
}
