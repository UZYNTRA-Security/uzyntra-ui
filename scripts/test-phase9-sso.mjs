import assert from "node:assert/strict";
import {
  AUDIT_EVENT_TYPES,
} from "../src/lib/audit/index.js";
import {
  IDENTITY_AUDIT_EVENT_TYPES,
  hashIdentityValue,
} from "../src/lib/identity/index.js";
import {
  SSO_AUDIT_EVENTS,
  buildEnterpriseOidcAuthorizationUrl,
  completeEnterpriseOidcCallback,
  completeSamlCallback,
  createEnterpriseSsoProvider,
  normalizeEnterpriseOidcProfile,
  parseSamlResponse,
  resolveEnterpriseSsoIdentity,
  sanitizeSsoConfiguration,
  ssoCallbackUrl,
  startEnterpriseOidcLogin,
  startSamlLogin,
  validateSamlAssertion,
} from "../src/lib/auth/sso.js";

process.env.AUTH_API_KEY_SECRET = "0123456789abcdef0123456789abcdef";
process.env.AUTH_SESSION_SECRET = "abcdef0123456789abcdef0123456789";
process.env.AUTH_MFA_SECRET_ENCRYPTION_KEY =
  "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

assert.equal(AUDIT_EVENT_TYPES.SSO_LOGIN_STARTED, "sso.login.started");
assert.equal(AUDIT_EVENT_TYPES.SSO_LOGIN_COMPLETED, "sso.login.completed");
assert.equal(AUDIT_EVENT_TYPES.SSO_LOGIN_FAILED, "sso.login.failed");
assert.equal(AUDIT_EVENT_TYPES.SSO_PROVIDER_CREATED, "sso.provider.created");
assert.equal(AUDIT_EVENT_TYPES.SSO_PROVIDER_UPDATED, "sso.provider.updated");
assert.equal(AUDIT_EVENT_TYPES.SSO_POLICY_CHANGED, "sso.policy.changed");
assert.equal(IDENTITY_AUDIT_EVENT_TYPES.SSO_POLICY_CHANGED, "sso.policy.changed");

assert.throws(
  () => sanitizeSsoConfiguration({ clientSecret: "never-store" }),
  /clientSecret/,
);
assert.throws(
  () => sanitizeSsoConfiguration({ metadataUrl: "http://idp.example.com/metadata" }),
  /https/,
);

const providerWrites = [];
const createdProvider = await createEnterpriseSsoProvider({
  database: fakeDatabase({ writes: providerWrites }),
  organizationId: "org-1",
  createdByUserId: "owner-1",
  providerKey: "Acme SAML",
  providerType: "saml",
  displayName: "Acme SAML",
  status: "active",
  issuer: "https://idp.acme.com",
  allowedDomains: ["Acme.com"],
  authorizationEndpoint: "https://idp.acme.com/sso",
  configuration: {
    metadataUrl: "https://idp.acme.com/metadata",
    singleSignOnUrl: "https://idp.acme.com/sso",
    spEntityId: "https://console.uzyntra.com",
    signatureRequired: true,
  },
  secretRef: "SSO_ACME_PRIVATE_VALUE",
});
assert.equal(createdProvider.providerKey, "acme_saml");
assert.equal(createdProvider.providerType, "saml");
assert.deepEqual(createdProvider.allowedDomains, ["acme.com"]);
assert.equal(createdProvider.secretRef, "SSO_...ALUE");
assert.equal(JSON.stringify(providerWrites).includes("never-store"), false);

const oidcProvider = providerRecord({
  providerKey: "acme_oidc",
  providerType: "oidc",
  issuer: "https://idp.acme.com",
  authorizationEndpoint: "https://idp.acme.com/oauth/authorize",
  tokenEndpoint: "https://idp.acme.com/oauth/token",
  userInfoEndpoint: "https://idp.acme.com/userinfo",
  clientId: "acme-client",
  secretRef: "SSO_ENTERPRISE_OIDC_CLIENT_SECRET",
  scopes: ["openid", "email", "profile"],
  configuration: { jwksUri: "https://idp.acme.com/jwks" },
});
const oidcUrl = new URL(
  buildEnterpriseOidcAuthorizationUrl({
    provider: oidcProvider,
    state: "state-value",
    codeChallenge: "challenge-value",
    redirectUri: "https://console.uzyntra.com/api/auth/sso/oidc/acme_oidc/callback",
  }),
);
assert.equal(oidcUrl.origin, "https://idp.acme.com");
assert.equal(oidcUrl.searchParams.get("client_id"), "acme-client");
assert.equal(oidcUrl.searchParams.get("state"), "state-value");
assert.equal(oidcUrl.searchParams.get("code_challenge_method"), "S256");

const oidcWrites = [];
const oidcStart = await startEnterpriseOidcLogin({
  database: fakeDatabase({ writes: oidcWrites, selectQueue: [[oidcProvider]] }),
  providerKey: "acme_oidc",
  requestUrl: "https://console.uzyntra.com/login",
  redirectPath: "/settings/sso",
});
assert.ok(oidcStart.authorizationUrl.includes("code_challenge="));
assert.equal(JSON.stringify(oidcWrites).includes(oidcStart.codeVerifier), false);
assert.equal(
  ssoCallbackUrl("https://console.uzyntra.com/login", "oidc", "acme_oidc"),
  "https://console.uzyntra.com/api/auth/sso/oidc/acme_oidc/callback",
);

await assert.rejects(
  () =>
    completeEnterpriseOidcCallback({
      database: fakeDatabase({ selectQueue: [[oidcProvider]] }),
      providerKey: "acme_oidc",
      requestUrl: "https://console.uzyntra.com/api/auth/sso/oidc/acme_oidc/callback",
      state: "state-a",
      stateCookie: "state-b",
      codeVerifier: "verifier",
      authorizationCode: "code",
      env: { SSO_ENTERPRISE_OIDC_CLIENT_SECRET: "runtime-secret" },
    }),
  /sso callback is invalid/,
);

assert.throws(
  () =>
    normalizeEnterpriseOidcProfile(oidcProvider, {
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

const parsedOidc = normalizeEnterpriseOidcProfile(oidcProvider, {
  idToken: jwt({
    iss: "https://idp.acme.com",
    aud: "acme-client",
    sub: "subject-1",
    email: "User@Acme.com",
    email_verified: true,
    name: "Acme User",
    exp: Math.floor(Date.now() / 1000) + 600,
  }),
});
assert.equal(parsedOidc.email, "user@acme.com");
assert.equal(parsedOidc.subject, "subject-1");

await assert.rejects(
  () =>
    resolveEnterpriseSsoIdentity({
      database: fakeDatabase({ selectQueue: [] }),
      provider: oidcProvider,
      profile: {
        subject: "subject-evil",
        email: "user@evil.com",
        emailVerified: true,
      },
    }),
  /domain is not allowed/,
);

const samlProvider = providerRecord({
  providerKey: "acme_saml",
  providerType: "saml",
  issuer: "https://idp.acme.com",
  authorizationEndpoint: "https://idp.acme.com/sso",
  allowedDomains: ["acme.com"],
  configuration: {
    singleSignOnUrl: "https://idp.acme.com/sso",
    spEntityId: "https://console.uzyntra.com",
    signatureRequired: true,
  },
});
const samlStartWrites = [];
const samlStart = await startSamlLogin({
  database: fakeDatabase({ writes: samlStartWrites, selectQueue: [[samlProvider]] }),
  providerKey: "acme_saml",
  requestUrl: "https://console.uzyntra.com/login",
});
const samlRedirect = new URL(samlStart.redirectUrl);
assert.equal(samlRedirect.origin, "https://idp.acme.com");
assert.ok(samlRedirect.searchParams.get("SAMLRequest"));
assert.equal(JSON.stringify(samlStartWrites).includes(samlStart.state), false);

const assertionXml = samlAssertionXml({
  assertionId: "_assertion-1",
  issuer: "https://idp.acme.com",
  audience: "https://console.uzyntra.com",
  subject: "enterprise-user-1",
  email: "User@Acme.com",
});
const assertion = parseSamlResponse(Buffer.from(assertionXml, "utf8").toString("base64"));
assert.equal(assertion.subject, "enterprise-user-1");
assert.equal(assertion.email, "user@acme.com");
assert.equal(validateSamlAssertion({ provider: samlProvider, assertion, requestUrl: "https://console.uzyntra.com/login" }), true);

assert.throws(
  () => parseSamlResponse(Buffer.from("<!DOCTYPE foo><Response/>", "utf8").toString("base64")),
  /unsafe xml/,
);
assert.throws(
  () =>
    validateSamlAssertion({
      provider: samlProvider,
      assertion: { ...assertion, issuer: "https://evil.example.com" },
      requestUrl: "https://console.uzyntra.com/login",
    }),
  /issuer/,
);

await assert.rejects(
  () =>
    completeSamlCallback({
      database: fakeDatabase({
        selectQueue: [
          [samlProvider],
          [ssoAttemptRecord({ providerId: samlProvider.id })],
          [{ id: "replayed" }],
        ],
      }),
      providerKey: "acme_saml",
      requestUrl: "https://console.uzyntra.com/api/auth/sso/saml/acme_saml/callback",
      relayState: "state-ok",
      stateCookie: "state-ok",
      samlResponse: Buffer.from(assertionXml, "utf8").toString("base64"),
    }),
  /sso callback is invalid/,
);

const samlWrites = [];
const samlResult = await completeSamlCallback({
  database: fakeDatabase({
    writes: samlWrites,
    selectQueue: [
      [samlProvider],
      [ssoAttemptRecord({ providerId: samlProvider.id })],
      [],
      [externalIdentityRecord()],
      [activeMembership()],
      [{ id: "user-1", email: "user@acme.com", status: "active", deletedAt: null }],
      [],
    ],
  }),
  providerKey: "acme_saml",
  requestUrl: "https://console.uzyntra.com/api/auth/sso/saml/acme_saml/callback",
  relayState: "state-ok",
  stateCookie: "state-ok",
  samlResponse: Buffer.from(assertionXml, "utf8").toString("base64"),
  requestId: "request-1",
});
assert.equal(samlResult.user.email, "user@acme.com");
assert.equal(typeof samlResult.token, "string");
assert.ok(samlWrites.some((write) => write.eventType === SSO_AUDIT_EVENTS.LOGIN_COMPLETED));
assert.ok(samlWrites.some((write) => write.tokenHash));
assert.equal(JSON.stringify(samlWrites).includes("state-ok"), false);
assert.equal(JSON.stringify(samlWrites).includes("enterprise-user-1"), false);

console.log("phase 9 SSO simulation tests passed");

function providerRecord(overrides = {}) {
  return {
    id: overrides.id || `provider-${overrides.providerKey || "sso"}`,
    organizationId: overrides.organizationId || "org-1",
    providerKey: overrides.providerKey || "acme_sso",
    providerType: overrides.providerType || "saml",
    displayName: overrides.displayName || "Acme SSO",
    status: overrides.status || "active",
    issuer: overrides.issuer || "https://idp.acme.com",
    clientId: overrides.clientId || null,
    scopes: overrides.scopes || [],
    allowedDomains: overrides.allowedDomains || ["acme.com"],
    authorizationEndpoint: overrides.authorizationEndpoint || "https://idp.acme.com/sso",
    tokenEndpoint: overrides.tokenEndpoint || null,
    userInfoEndpoint: overrides.userInfoEndpoint || null,
    configuration: overrides.configuration || {},
    configurationRef: overrides.configurationRef || null,
    secretRef: overrides.secretRef || null,
    isSystem: false,
    deletedAt: null,
  };
}

function ssoAttemptRecord({ providerId } = {}) {
  return {
    id: "attempt-1",
    organizationId: "org-1",
    providerId,
    flowType: "saml",
    stateHash: hashIdentityValue("state-ok"),
    status: "pending",
    redirectPath: "/",
    expiresAt: new Date(Date.now() + 60_000),
  };
}

function externalIdentityRecord() {
  return {
    id: "external-1",
    organizationId: "org-1",
    userId: "user-1",
    providerId: "provider-acme_saml",
    providerKey: "acme_saml",
    providerType: "saml",
    status: "active",
  };
}

function activeMembership() {
  return {
    membership: {
      id: "membership-1",
      organizationId: "org-1",
      userId: "user-1",
      status: "active",
    },
    organization: {
      id: "org-1",
      name: "Acme",
      slug: "acme",
      status: "active",
      deletedAt: null,
    },
    settings: {
      organizationId: "org-1",
      sessionTimeoutSeconds: 900,
      mfaRequired: false,
      ssoMode: "optional",
    },
  };
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
            onConflictDoUpdate() {
              return this;
            },
            onConflictDoNothing() {
              return this;
            },
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
          return chain({ result: () => [updateResult(value)] });
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
      return Promise.resolve(result());
    },
    returning() {
      return Promise.resolve(result());
    },
  };
}

function insertResult(value) {
  if (value.tokenHash) {
    return {
      id: "session-1",
      ...value,
      expiresAt: value.expiresAt || new Date(Date.now() + 60_000),
    };
  }
  if (value.providerType) return { id: `provider-${value.providerKey}`, ...value };
  if (value.externalSubjectHash) return { id: "external-1", status: "active", ...value };
  if (value.eventType) return { id: `audit-${value.eventType}`, ...value };
  if (value.stateHash) return { id: "attempt-1", ...value };
  if (value.email) return { id: "user-1", ...value };
  if (value.organizationId && value.userId) return { id: "membership-1", ...value };
  return { id: "inserted-1", ...value };
}

function updateResult(value) {
  return { id: "updated-1", ...value };
}

function jwt(payload) {
  return [
    Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "test-key" })).toString("base64url"),
    Buffer.from(JSON.stringify(payload)).toString("base64url"),
    "signature",
  ].join(".");
}

function samlAssertionXml({ assertionId, issuer, audience, subject, email }) {
  return `
    <samlp:Response ID="_response-1" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
      <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${issuer}</saml:Issuer>
      <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">signature</ds:Signature>
      <saml:Assertion ID="${assertionId}" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml:Subject><saml:NameID>${subject}</saml:NameID></saml:Subject>
        <saml:Conditions NotBefore="2020-01-01T00:00:00.000Z" NotOnOrAfter="2999-01-01T00:00:00.000Z">
          <saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience></saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AttributeStatement>
          <saml:Attribute Name="email"><saml:AttributeValue>${email}</saml:AttributeValue></saml:Attribute>
          <saml:Attribute Name="name"><saml:AttributeValue>Acme User</saml:AttributeValue></saml:Attribute>
        </saml:AttributeStatement>
      </saml:Assertion>
    </samlp:Response>
  `;
}
