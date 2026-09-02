import assert from "node:assert/strict";
import {
  AUDIT_EVENT_TYPES,
} from "../src/lib/audit/index.js";
import {
  DEFAULT_IDENTITY_PROVIDERS,
  IDENTITY_AUDIT_EVENT_TYPES,
  IDENTITY_PROVIDER_TYPES,
  hashIdentityValue,
  normalizeExternalIdentityInput,
  normalizeIdentityAuditEvent,
  normalizeIdentityProvider,
  normalizeVerifiedEmailIdentity,
  publicIdentityProvider,
  recordIdentityAuditEvent,
  sanitizeIdentityMetadata,
} from "../src/lib/identity/index.js";

process.env.AUTH_API_KEY_SECRET = "0123456789abcdef0123456789abcdef";
process.env.AUTH_SESSION_SECRET = "abcdef0123456789abcdef0123456789";

assert.equal(AUDIT_EVENT_TYPES.IDENTITY_CREATED, "identity.created");
assert.equal(AUDIT_EVENT_TYPES.IDENTITY_LINKED, "identity.linked");
assert.equal(AUDIT_EVENT_TYPES.IDENTITY_UNLINKED, "identity.unlinked");
assert.equal(AUDIT_EVENT_TYPES.IDENTITY_PROVIDER_CHANGED, "identity.provider.changed");
assert.equal(AUDIT_EVENT_TYPES.IDENTITY_VERIFICATION_UPDATED, "identity.verification.updated");

assert.deepEqual(
  DEFAULT_IDENTITY_PROVIDERS.map((provider) => [provider.providerKey, provider.providerType, provider.status]),
  [
    ["password", "password", "active"],
    ["google", "google", "disabled"],
    ["github", "github", "disabled"],
    ["oidc", "oidc", "disabled"],
    ["saml", "saml", "disabled"],
  ],
);

const provider = normalizeIdentityProvider({
  providerKey: "Google Workspace",
  providerType: IDENTITY_PROVIDER_TYPES.GOOGLE,
  displayName: "Google Workspace",
  status: "disabled",
  clientId: "client-id-public-value",
  configuration: { prompt: "select_account" },
});

assert.equal(provider.providerKey, "google_workspace");
assert.equal(provider.providerType, "google");
assert.equal(provider.status, "disabled");
assert.deepEqual(provider.configuration, { prompt: "select_account" });

assert.throws(
  () => normalizeIdentityProvider({ providerType: "twitter", displayName: "Twitter" }),
  /identity provider type is invalid/,
);

assert.throws(
  () => sanitizeIdentityMetadata({ nested: { accessToken: "plain-secret" } }),
  /nested.accessToken/,
);

const subjectHash = hashIdentityValue("provider-user-123");
assert.notEqual(subjectHash, "provider-user-123");
assert.equal(subjectHash, hashIdentityValue("provider-user-123"));
assert.notEqual(subjectHash, hashIdentityValue("provider-user-456"));

const external = normalizeExternalIdentityInput({
  organizationId: "org-1",
  userId: "user-1",
  providerId: "provider-1",
  externalSubjectId: "provider-user-123",
  providerEmail: "User@Example.COM",
  emailVerified: true,
  metadata: { providerTenant: "workspace-1" },
});

assert.equal(external.organizationId, "org-1");
assert.equal(external.providerEmail, "user@example.com");
assert.equal(external.emailVerified, true);
assert.equal(external.externalSubjectHash, subjectHash);
assert.notEqual(external.providerEmailHash, "user@example.com");
assert.equal(JSON.stringify(external).includes("provider-user-123"), false);

const verifiedEmail = normalizeVerifiedEmailIdentity({
  organizationId: "org-1",
  userId: "user-1",
  email: "User@Example.COM",
  verificationSource: "manual",
});

assert.equal(verifiedEmail.email, "user@example.com");
assert.equal(verifiedEmail.verificationSource, "manual");
assert.equal(verifiedEmail.status, "active");
assert.notEqual(verifiedEmail.emailHash, "user@example.com");

const publicProvider = publicIdentityProvider({
  id: "provider-1",
  providerKey: "google",
  providerType: "google",
  displayName: "Google",
  status: "disabled",
  clientId: "1234567890abcdef",
  isSystem: true,
});

assert.equal(publicProvider.clientId, "1234...cdef");
assert.equal("configuration" in publicProvider, false);

const auditEvent = normalizeIdentityAuditEvent({
  organizationId: "org-1",
  userId: "user-1",
  actorUserId: "actor-1",
  providerId: "provider-1",
  eventType: IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_LINKED,
  action: "identity.linked",
  result: "success",
  metadata: { providerKey: "google", emailVerified: true },
});

assert.equal(auditEvent.eventType, "identity.linked");
assert.equal(auditEvent.result, "success");
assert.deepEqual(auditEvent.metadata, { providerKey: "google", emailVerified: true });

assert.throws(
  () =>
    normalizeIdentityAuditEvent({
      eventType: "identity.provider.secret_updated",
      action: "identity.provider.secret_updated",
      result: "success",
    }),
  /identity audit event type is invalid/,
);

assert.throws(
  () =>
    normalizeIdentityAuditEvent({
      eventType: IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_PROVIDER_CHANGED,
      action: "identity.provider.changed",
      result: "success",
      metadata: { clientSecret: "never-store" },
    }),
  /clientSecret/,
);

const writes = [];
const inserted = await recordIdentityAuditEvent({
  database: fakeDatabase(writes),
  organizationId: "org-1",
  userId: "user-1",
  actorUserId: "actor-1",
  providerId: "provider-1",
  eventType: IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_VERIFICATION_UPDATED,
  action: "identity.verification.updated",
  result: "success",
  requestId: "request-1",
  metadata: { verificationSource: "password" },
});

assert.equal(inserted.id, "identity-audit-1");
assert.equal(writes[0].eventType, "identity.verification.updated");
assert.equal(JSON.stringify(writes).includes("never-store"), false);

console.log("phase 9 identity foundation tests passed");

function fakeDatabase(writes = []) {
  return {
    insert() {
      return {
        values(value) {
          writes.push(value);
          return {
            async returning() {
              return [{ id: "identity-audit-1", ...value }];
            },
          };
        },
      };
    },
  };
}
