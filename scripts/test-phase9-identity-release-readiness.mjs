import assert from "node:assert/strict";
import { LOGIN_LOCK_THRESHOLD, isLocked, nextFailedCredentialState } from "../src/lib/auth/api.js";
import { completeOAuthCallback, normalizeRedirectPath } from "../src/lib/auth/oauth.js";
import {
  completeEnterpriseOidcCallback,
  completeSamlCallback,
  normalizeEnterpriseOidcProfile,
  parseSamlResponse,
  validateSamlAssertion,
} from "../src/lib/auth/sso.js";
import {
  verifyMfaChallengeAndCreateSession,
  verifyRecoveryCode,
} from "../src/lib/auth/mfa.js";
import {
  createScimToken,
  authenticateScimRequest,
} from "../src/lib/scim/index.js";
import {
  buildIdentitySecurityReport,
  createBreakGlassAdministrator,
} from "../src/lib/identity-hardening/index.js";

process.env.AUTH_API_KEY_SECRET = "0123456789abcdef0123456789abcdef";
process.env.AUTH_SESSION_SECRET = "abcdef0123456789abcdef0123456789";
process.env.AUTH_MFA_SECRET_ENCRYPTION_KEY =
  "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

let credential = { failedAttempts: 0, lockedUntil: null };
for (let attempt = 0; attempt < LOGIN_LOCK_THRESHOLD; attempt += 1) {
  credential = { ...credential, ...nextFailedCredentialState(credential, new Date("2026-09-02T00:00:00.000Z")) };
}
assert.equal(isLocked(credential, new Date("2026-09-02T00:01:00.000Z")), true);
assert.equal(normalizeRedirectPath("https://evil.example.com/callback"), "/");
assert.equal(normalizeRedirectPath("//evil.example.com"), "/");

await assert.rejects(
  () =>
    completeOAuthCallback({
      database: fakeDatabase({
        selectQueue: [[oauthProvider()], []],
      }),
      providerKey: "google",
      requestUrl: "https://console.uzyntra.com/api/auth/oauth/google/callback",
      state: "state-ok",
      stateCookie: "state-ok",
      codeVerifier: "wrong-verifier",
      authorizationCode: "code-1",
      env: { GOOGLE_CLIENT_ID: "id", GOOGLE_CLIENT_SECRET: "secret" },
    }),
  /oauth callback is invalid/,
);

await assert.rejects(
  () =>
    completeOAuthCallback({
      database: fakeDatabase({
        selectQueue: [[oauthProvider()], [oauthAttempt()], [{ id: "replayed" }]],
      }),
      providerKey: "google",
      requestUrl: "https://console.uzyntra.com/api/auth/oauth/google/callback",
      state: "state-ok",
      stateCookie: "state-ok",
      codeVerifier: "verifier-ok",
      authorizationCode: "replayed-code",
      env: { GOOGLE_CLIENT_ID: "id", GOOGLE_CLIENT_SECRET: "secret" },
    }),
  /oauth callback is invalid/,
);

await assert.rejects(
  () =>
    completeMfaReplay({
      selectQueue: [],
      challengeToken: "challenge-token",
      code: "123456",
    }),
  /mfa challenge is invalid/,
);

await assert.rejects(
  () =>
    completeMfaReplay({
      selectQueue: [],
      challengeToken: "expired-token",
      code: "123456",
      now: new Date("2026-09-02T01:00:00.000Z"),
    }),
  /mfa challenge is invalid/,
);

const recoveryWrites = [];
const recoveryChallenge = {
  organizationId: "org-1",
  userId: "user-1",
};
const firstRecoveryUse = await verifyRecoveryCode({
  database: fakeDatabase({
    writes: recoveryWrites,
    selectQueue: [[{ id: "recovery-code-1" }]],
  }),
  challenge: recoveryChallenge,
  recoveryCode: "valid-recovery-code",
});
const secondRecoveryUse = await verifyRecoveryCode({
  database: fakeDatabase({
    selectQueue: [[]],
  }),
  challenge: recoveryChallenge,
  recoveryCode: "valid-recovery-code",
});
assert.equal(firstRecoveryUse, true);
assert.equal(secondRecoveryUse, false);
assert.ok(recoveryWrites.some((write) => write.status === "used"));

assert.throws(
  () =>
    normalizeEnterpriseOidcProfile(enterpriseOidcProvider(), {
      idToken: jwt({
        iss: "https://evil.example.com",
        aud: "acme-client",
        sub: "subject-1",
        email: "user@acme.com",
        email_verified: true,
        exp: Math.floor(Date.now() / 1000) + 600,
      }),
    }),
  /issuer/,
);

assert.throws(
  () =>
    normalizeEnterpriseOidcProfile(enterpriseOidcProvider(), {
      idToken: jwt({
        iss: "https://idp.acme.com",
        aud: "wrong-client",
        sub: "subject-1",
        email: "user@acme.com",
        email_verified: true,
        exp: Math.floor(Date.now() / 1000) + 600,
      }),
    }),
  /audience/,
);

const samlProvider = enterpriseSamlProvider();
const assertion = parseSamlResponse(Buffer.from(samlAssertionXml(), "utf8").toString("base64"));
assert.equal(validateSamlAssertion({ provider: samlProvider, assertion, requestUrl: "https://console.uzyntra.com/login" }), true);
assert.throws(
  () =>
    validateSamlAssertion({
      provider: samlProvider,
      assertion: { ...assertion, audience: "https://evil.example.com" },
      requestUrl: "https://console.uzyntra.com/login",
    }),
  /audience/,
);

await assert.rejects(
  () =>
    completeSamlCallback({
      database: fakeDatabase({
        selectQueue: [[samlProvider], [ssoAttempt({ providerId: samlProvider.id })], [{ id: "replayed-assertion" }]],
      }),
      providerKey: "acme_saml",
      requestUrl: "https://console.uzyntra.com/api/auth/sso/saml/acme_saml/callback",
      relayState: "state-ok",
      stateCookie: "state-ok",
      samlResponse: Buffer.from(samlAssertionXml(), "utf8").toString("base64"),
    }),
  /sso callback is invalid/,
);

await assert.rejects(
  () =>
    completeEnterpriseOidcCallback({
      database: fakeDatabase({
        selectQueue: [[enterpriseOidcProvider()], []],
      }),
      providerKey: "acme_oidc",
      requestUrl: "https://console.uzyntra.com/api/auth/sso/oidc/acme_oidc/callback",
      state: "state-ok",
      stateCookie: "state-ok",
      codeVerifier: "wrong-verifier",
      authorizationCode: "code-1",
      env: { SSO_ENTERPRISE_OIDC_CLIENT_SECRET: "runtime-secret" },
    }),
  /sso callback is invalid/,
);

await assert.rejects(
  () =>
    createScimToken({
      database: fakeDatabase({ selectQueue: [[]] }),
      organizationId: "org-a",
      providerId: "provider-owned-by-org-b",
      name: "Cross tenant token",
    }),
  /scim provider is not available/,
);

const scimAuth = await authenticateScimRequest(
  requestWithBearer("scim_revoked_or_invalid"),
  { database: fakeDatabase({ selectQueue: [[]] }) },
);
assert.equal(scimAuth, null);

await assert.rejects(
  () =>
    createBreakGlassAdministrator({
      database: fakeDatabase(),
      organizationId: "org-1",
      userId: "admin-1",
      reason: "Unsafe break-glass metadata",
      expiresAt: "2026-09-03T00:00:00.000Z",
      metadata: { token: "plain-secret" },
    }),
  /sensitive field/,
);

const report = buildIdentitySecurityReport({
  organizationId: "org-1",
  generatedByUserId: "owner-1",
  window: { since: "2026-09-01T00:00:00.000Z", until: "2026-09-02T00:00:00.000Z" },
  providers: [
    { id: "password-provider", providerKey: "password", providerType: "password", displayName: "Password", status: "active" },
    { id: "google-provider", providerKey: "google", providerType: "google", displayName: "Google", status: "disabled" },
  ],
  security: {
    executive: { identitySecurityScore: 96, riskyIdentities: 0, openAccessReviews: 0, mfaAdoptionRate: 92 },
    mfaAdoption: { adoptionRate: 92, enabledUsers: 23, missingUsers: 2 },
    ssoHealth: { providers: 1, activeProviders: 0, attempts: 0, failures: 0, failureRate: 0 },
    scimHealth: { providers: 1, activeProviders: 0, syncs: 0, failures: 0, running: 0, failureRate: 0 },
    riskyIdentities: [],
    accessReviews: [],
    recentEvents: [
      {
        id: "event-1",
        eventType: "identity.provider.changed",
        category: "governance",
        result: "success",
        severity: "low",
        riskScore: 5,
        action: "monitor",
        metadata: { clientSecret: "must-not-appear" },
      },
    ],
  },
  observability: {
    executive: { loginSuccessRate: 99, loginFailureRate: 1, openRecoveryWorkflows: 0 },
    oauth: { total: 5, failures: 0, failureRate: 0, healthScore: 100, status: "healthy" },
    recovery: { workflows: [], breakGlassAdministrators: [], events: [] },
    reports: [{ id: "report-1", reportType: "identity_evidence", exportFormat: "json", status: "generated", rowCount: 5 }],
  },
});
assert.equal(report.reportType, "identity_security_report");
assert.equal(report.certificationClaims.length, 0);
assert.equal(report.authenticationMethods.password.enabled, true);
assert.equal(report.releaseReadiness.status, "ready_for_validation");
assert.equal(JSON.stringify(report).includes("must-not-appear"), false);
assert.equal(JSON.stringify(report).includes("clientSecret"), false);

console.log("phase 9.8 identity release readiness tests passed");

function completeMfaReplay({ selectQueue, challengeToken, code, now = new Date("2026-09-02T00:00:00.000Z") }) {
  return verifyMfaChallengeAndCreateSession({
    database: fakeDatabase({ selectQueue }),
    challengeId: "challenge-1",
    challengeToken,
    code,
    now,
  });
}

function fakeDatabase({ selectQueue = [], writes = [] } = {}) {
  return {
    select() {
      return chain({ result: () => selectQueue.shift() || [] });
    },
    insert() {
      return {
        values(value) {
          writes.push(value);
          const firstValue = Array.isArray(value) ? value[0] : value;
          return {
            async returning() {
              return [insertResult(firstValue)];
            },
          };
        },
      };
    },
    update() {
      return {
        set(value) {
          writes.push(value);
          return chain({ result: () => [insertResult(value)] });
        },
      };
    },
    transaction(callback) {
      return callback(this);
    },
  };
}

function chain({ result }) {
  return {
    from() {
      return this;
    },
    innerJoin() {
      return this;
    },
    leftJoin() {
      return this;
    },
    where() {
      return this;
    },
    orderBy() {
      return this;
    },
    limit() {
      return this;
    },
    offset() {
      return this;
    },
    async returning() {
      return result();
    },
    then(resolve, reject) {
      return Promise.resolve(result()).then(resolve, reject);
    },
  };
}

function insertResult(value) {
  return {
    id: value.id || "generated-id",
    createdAt: value.createdAt || new Date(),
    updatedAt: value.updatedAt || new Date(),
    ...value,
  };
}

function oauthProvider() {
  return {
    id: "provider-google",
    providerKey: "google",
    providerType: "google",
    displayName: "Google",
    status: "active",
    authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenEndpoint: "https://oauth2.googleapis.com/token",
    userInfoEndpoint: "https://openidconnect.googleapis.com/v1/userinfo",
    scopes: ["openid", "email", "profile"],
    deletedAt: null,
  };
}

function oauthAttempt() {
  return {
    id: "attempt-1",
    providerId: "provider-google",
    status: "pending",
    redirectPath: "/",
    expiresAt: new Date(Date.now() + 600000),
  };
}

function enterpriseOidcProvider() {
  return {
    id: "provider-oidc",
    organizationId: "org-1",
    providerKey: "acme_oidc",
    providerType: "oidc",
    displayName: "Acme OIDC",
    status: "active",
    issuer: "https://idp.acme.com",
    clientId: "acme-client",
    authorizationEndpoint: "https://idp.acme.com/oauth/authorize",
    tokenEndpoint: "https://idp.acme.com/oauth/token",
    userInfoEndpoint: "https://idp.acme.com/userinfo",
    allowedDomains: ["acme.com"],
    scopes: ["openid", "email", "profile"],
    secretRef: "SSO_ENTERPRISE_OIDC_CLIENT_SECRET",
    configuration: {},
  };
}

function enterpriseSamlProvider() {
  return {
    id: "provider-saml",
    organizationId: "org-1",
    providerKey: "acme_saml",
    providerType: "saml",
    displayName: "Acme SAML",
    status: "active",
    issuer: "https://idp.acme.com",
    allowedDomains: ["acme.com"],
    authorizationEndpoint: "https://idp.acme.com/sso",
    configuration: {
      spEntityId: "https://console.uzyntra.com",
      singleSignOnUrl: "https://idp.acme.com/sso",
      signatureRequired: true,
    },
  };
}

function ssoAttempt(overrides = {}) {
  return {
    id: "sso-attempt-1",
    providerId: "provider-saml",
    status: "pending",
    redirectPath: "/",
    expiresAt: new Date(Date.now() + 600000),
    ...overrides,
  };
}

function samlAssertionXml() {
  const expires = new Date(Date.now() + 600000).toISOString();
  return [
    '<Response ID="_response-1" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">',
    '<saml:Assertion ID="_assertion-1">',
    '<saml:Issuer>https://idp.acme.com</saml:Issuer>',
    '<saml:Subject><saml:NameID>enterprise-user-1</saml:NameID></saml:Subject>',
    `<saml:Conditions NotBefore="2020-01-01T00:00:00.000Z" NotOnOrAfter="${expires}">`,
    '<saml:AudienceRestriction><saml:Audience>https://console.uzyntra.com</saml:Audience></saml:AudienceRestriction>',
    "</saml:Conditions>",
    '<saml:AttributeStatement><saml:Attribute Name="email"><saml:AttributeValue>user@acme.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>',
    '<Signature>signed</Signature>',
    "</saml:Assertion>",
    "</Response>",
  ].join("");
}

function jwt(payload) {
  return [
    Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url"),
    Buffer.from(JSON.stringify(payload)).toString("base64url"),
    "",
  ].join(".");
}

function requestWithBearer(token) {
  return {
    headers: {
      get(name) {
        return name.toLowerCase() === "authorization" ? `Bearer ${token}` : null;
      },
    },
  };
}
