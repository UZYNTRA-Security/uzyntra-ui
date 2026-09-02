import assert from "node:assert/strict";
import {
  AUDIT_EVENT_TYPES,
} from "../src/lib/audit/index.js";
import {
  IDENTITY_AUDIT_EVENT_TYPES,
  hashIdentityValue,
  linkExternalIdentity,
} from "../src/lib/identity/index.js";
import {
  OAUTH_AUDIT_EVENTS,
  buildAuthorizationUrl,
  completeOAuthCallback,
  exchangeAuthorizationCode,
  normalizeOAuthProfile,
  oauthCallbackUrl,
  oauthRuntimeConfig,
  pkceChallenge,
  resolveOAuthIdentity,
} from "../src/lib/auth/oauth.js";

process.env.AUTH_API_KEY_SECRET = "0123456789abcdef0123456789abcdef";
process.env.AUTH_SESSION_SECRET = "abcdef0123456789abcdef0123456789";

assert.equal(AUDIT_EVENT_TYPES.OAUTH_LOGIN_STARTED, "oauth.login.started");
assert.equal(AUDIT_EVENT_TYPES.OAUTH_LOGIN_COMPLETED, "oauth.login.completed");
assert.equal(AUDIT_EVENT_TYPES.OAUTH_LOGIN_FAILED, "oauth.login.failed");
assert.equal(AUDIT_EVENT_TYPES.OAUTH_IDENTITY_LINKED, "oauth.identity.linked");
assert.equal(AUDIT_EVENT_TYPES.OAUTH_IDENTITY_CREATED, "oauth.identity.created");
assert.equal(IDENTITY_AUDIT_EVENT_TYPES.OAUTH_LOGIN_COMPLETED, "oauth.login.completed");

const runtime = oauthRuntimeConfig(
  "google",
  {
    providerKey: "google",
    providerType: "google",
    displayName: "Google",
  },
  {
    GOOGLE_CLIENT_ID: "google-client-id",
    GOOGLE_CLIENT_SECRET: "google-client-secret",
  },
);

assert.equal(runtime.configured, true);
assert.deepEqual(runtime.scopes, ["openid", "email", "profile"]);

const challenge = pkceChallenge("verifier-value");
assert.equal(challenge, pkceChallenge("verifier-value"));
assert.notEqual(challenge, "verifier-value");

const authorizationUrl = new URL(
  buildAuthorizationUrl({
    runtime,
    state: "state-value",
    codeChallenge: challenge,
    redirectUri: "https://console.uzyntra.com/api/auth/oauth/google/callback",
  }),
);

assert.equal(authorizationUrl.origin, "https://accounts.google.com");
assert.equal(authorizationUrl.searchParams.get("client_id"), "google-client-id");
assert.equal(authorizationUrl.searchParams.get("state"), "state-value");
assert.equal(authorizationUrl.searchParams.get("code_challenge_method"), "S256");
assert.equal(authorizationUrl.searchParams.get("scope"), "openid email profile");

assert.equal(
  oauthCallbackUrl("https://console.uzyntra.com/login", "github"),
  "https://console.uzyntra.com/api/auth/oauth/github/callback",
);

assert.deepEqual(normalizeOAuthProfile("google", {
  sub: "google-subject",
  email: "User@Example.COM",
  email_verified: true,
}), {
  subject: "google-subject",
  email: "user@example.com",
  emailVerified: true,
  displayName: null,
});

assert.deepEqual(normalizeOAuthProfile("github", {
  id: 12345,
  login: "octo",
  email: "octo@example.com",
}), {
  subject: "12345",
  email: "octo@example.com",
  emailVerified: true,
  displayName: "octo",
});

await assert.rejects(
  () =>
    completeOAuthCallback({
      database: fakeOAuthDatabase({ selectQueue: [] }),
      providerKey: "google",
      requestUrl: "https://console.uzyntra.com/api/auth/oauth/google/callback",
      state: "state-a",
      stateCookie: "state-b",
      codeVerifier: "verifier",
      authorizationCode: "code",
      env: { GOOGLE_CLIENT_ID: "id", GOOGLE_CLIENT_SECRET: "secret" },
    }),
  /oauth state is invalid/,
);

await assert.rejects(
  () =>
    resolveOAuthIdentity({
      database: fakeOAuthDatabase({ selectQueue: [] }),
      provider: providerRecord(),
      profile: { sub: "google-subject", email: "user@example.com", email_verified: false },
    }),
  /verified provider email is required/,
);

await assert.rejects(
  () =>
    completeOAuthCallback({
      database: fakeOAuthDatabase({
        selectQueue: [
          [providerRecord()],
          [oauthAttemptRecord()],
          [{ id: "attempt-replayed" }],
        ],
      }),
      providerKey: "google",
      requestUrl: "https://console.uzyntra.com/api/auth/oauth/google/callback",
      state: "state-ok",
      stateCookie: "state-ok",
      codeVerifier: "verifier-ok",
      authorizationCode: "already-used-code",
      env: { GOOGLE_CLIENT_ID: "id", GOOGLE_CLIENT_SECRET: "secret" },
    }),
  /oauth callback is invalid/,
);

await assert.rejects(
  () =>
    linkExternalIdentity({
      database: fakeOAuthDatabase({
        selectQueue: [
          [{ id: "membership-1" }],
          [providerRecord()],
          [{
            id: "external-other",
            organizationId: "org-2",
            userId: "user-2",
            providerId: "provider-google",
            status: "active",
          }],
        ],
      }),
      organizationId: "org-1",
      userId: "user-1",
      providerId: "provider-google",
      externalSubjectId: "google-subject",
      providerEmail: "user@example.com",
      emailVerified: true,
    }),
  /external identity is already linked/,
);

await assert.rejects(
  () =>
    resolveOAuthIdentity({
      database: fakeOAuthDatabase({
        selectQueue: [
          [{
            id: "external-existing",
            organizationId: "org-2",
            userId: "user-2",
            providerId: "provider-google",
            status: "active",
          }],
          [activeMembership("user-2", "org-2")],
          [],
        ],
      }),
      provider: providerRecord(),
      profile: { sub: "google-subject", email: "user@example.com", email_verified: true },
    }),
  /linked identity user is not active/,
);

await assert.rejects(
  () =>
    resolveOAuthIdentity({
      database: fakeOAuthDatabase({
        selectQueue: [
          [],
          [{ id: "user-disabled", email: "user@example.com", status: "disabled" }],
        ],
      }),
      provider: providerRecord(),
      profile: { sub: "google-subject", email: "user@example.com", email_verified: true },
    }),
  /user is not active/,
);

const writes = [];
const completed = await completeOAuthCallback({
  database: fakeOAuthDatabase({
    writes,
    selectQueue: [
      [providerRecord()],
      [oauthAttemptRecord()],
      [],
      [],
      [{ id: "user-1", email: "user@example.com", status: "active", deletedAt: null }],
      [activeMembership("user-1", "org-1")],
      [{ id: "membership-1" }],
      [providerRecord()],
      [],
    ],
  }),
  providerKey: "google",
  requestUrl: "https://console.uzyntra.com/api/auth/oauth/google/callback",
  state: "state-ok",
  stateCookie: "state-ok",
  codeVerifier: "verifier-ok",
  authorizationCode: "fresh-code",
  fetchImpl: fakeFetch([
    { access_token: "provider-access-token", token_type: "Bearer", expires_in: 3600 },
    { sub: "google-subject", email: "User@Example.COM", email_verified: true, name: "User" },
  ]),
  env: { GOOGLE_CLIENT_ID: "id", GOOGLE_CLIENT_SECRET: "secret" },
  requestId: "request-1",
});

assert.equal(completed.user.email, "user@example.com");
assert.equal(completed.provider.providerKey, "google");
assert.equal(completed.linkedIdentity, true);
assert.equal(completed.createdUser, false);
assert.equal(completed.redirectPath, "/");
assert.equal(typeof completed.token, "string");
assert.ok(completed.token.length > 20);

const serializedWrites = JSON.stringify(writes);
assert.equal(serializedWrites.includes("provider-access-token"), false);
assert.equal(serializedWrites.includes("fresh-code"), false);
assert.equal(serializedWrites.includes("verifier-ok"), false);
assert.equal(serializedWrites.includes("google-subject"), false);
assert.equal(serializedWrites.includes(hashIdentityValue("google-subject")), true);
assert.ok(writes.some((write) => write.eventType === OAUTH_AUDIT_EVENTS.LOGIN_COMPLETED));
assert.ok(writes.some((write) => write.eventType === "identity.linked"));
assert.ok(writes.some((write) => write.tokenHash));

const tokenPayload = await exchangeAuthorizationCode({
  runtime,
  authorizationCode: "code",
  codeVerifier: "verifier",
  redirectUri: "https://console.uzyntra.com/api/auth/oauth/google/callback",
  fetchImpl: fakeFetch([{ error: "bad_verifier" }], 400),
}).catch((error) => error);
assert.match(tokenPayload.message, /oauth token exchange failed/);

console.log("phase 9 OAuth simulation tests passed");

function providerRecord() {
  return {
    id: "provider-google",
    organizationId: null,
    providerKey: "google",
    providerType: "google",
    displayName: "Google",
    status: "active",
    scopes: ["openid", "email", "profile"],
    authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenEndpoint: "https://oauth2.googleapis.com/token",
    userInfoEndpoint: "https://openidconnect.googleapis.com/v1/userinfo",
    deletedAt: null,
  };
}

function oauthAttemptRecord() {
  return {
    id: "attempt-1",
    providerId: "provider-google",
    stateHash: hashIdentityValue("state-ok"),
    pkceVerifierHash: hashIdentityValue("verifier-ok"),
    status: "pending",
    redirectPath: "/",
    expiresAt: new Date(Date.now() + 60_000),
  };
}

function activeMembership(userId, organizationId) {
  return {
    membership: {
      id: "membership-1",
      userId,
      organizationId,
      status: "active",
      createdAt: new Date(),
    },
    organization: {
      id: organizationId,
      name: "Example Org",
      slug: "example",
      status: "active",
      deletedAt: null,
    },
    settings: {
      organizationId,
      sessionTimeoutSeconds: 28_800,
    },
  };
}

function fakeOAuthDatabase({ selectQueue = [], writes = [] } = {}) {
  return {
    select() {
      return chain({
        result: () => selectQueue.shift() || [],
      });
    },
    insert() {
      return {
        values(value) {
          writes.push(value);
          const result = insertResult(value);
          return {
            onConflictDoUpdate() {
              return this;
            },
            async returning() {
              return [result];
            },
          };
        },
      };
    },
    update() {
      return {
        set(value) {
          writes.push(value);
          return chain({ result: () => [] });
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

  if (value.externalSubjectHash) {
    return {
      id: "external-1",
      ...value,
      status: value.status || "active",
      linkedAt: value.linkedAt || new Date(),
    };
  }

  if (value.eventType) {
    return { id: `audit-${value.eventType}`, ...value };
  }

  return { id: "inserted-1", ...value };
}

function fakeFetch(payloads, status = 200) {
  const queue = [...payloads];
  return async () => ({
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return queue.shift();
    },
  });
}
