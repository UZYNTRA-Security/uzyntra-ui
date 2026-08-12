import assert from "node:assert/strict";
import {
  API_KEY_STATUSES,
  apiKeyPrefixFromPlaintext,
  createApiKey,
  generateApiKey,
  hashApiKey,
  publicApiKey,
  verifyApiKey,
} from "../src/lib/api-keys/index.js";

process.env.AUTH_API_KEY_SECRET = "0123456789abcdef0123456789abcdef";

const first = generateApiKey();
const second = generateApiKey();
assert.match(first.plaintextKey, /^uz_live_[A-Za-z0-9_-]+_[A-Za-z0-9_-]+$/);
assert.notEqual(first.plaintextKey, second.plaintextKey);
assert.notEqual(first.keyPrefix, second.keyPrefix);
assert.equal(apiKeyPrefixFromPlaintext(first.plaintextKey), first.keyPrefix);
assert.match(first.keyPrefix, /^uz_live_[a-f0-9]+$/);
assert.equal(apiKeyPrefixFromPlaintext("uz_live_ab_cd_0123"), null);

const keyHash = hashApiKey(first.plaintextKey);
const stored = {
  id: "api-key-1",
  keyHash,
  status: API_KEY_STATUSES.ACTIVE,
  expiresAt: new Date(Date.now() + 60_000),
  revokedAt: null,
};

assert.equal(verifyApiKey(first.plaintextKey, stored), true);
assert.equal(verifyApiKey(second.plaintextKey, stored), false);
assert.equal(verifyApiKey(first.plaintextKey, { ...stored, status: API_KEY_STATUSES.REVOKED }), false);
assert.equal(verifyApiKey(first.plaintextKey, { ...stored, revokedAt: new Date() }), false);
assert.equal(verifyApiKey(first.plaintextKey, { ...stored, expiresAt: new Date(Date.now() - 1) }), false);

const safeRecord = publicApiKey({ ...stored, keyPrefix: first.keyPrefix, name: "CI key" });
assert.equal("keyHash" in safeRecord, false);

const writes = [];
const created = await createApiKey({
  database: fakeDatabase(writes),
  organizationId: "org-1",
  serviceAccountId: "service-account-1",
  name: "CI key",
  auditContext: { userId: "user-1", requestId: "request-1" },
});

assert.equal(created.plaintextKey.startsWith("uz_live_"), true);
assert.equal("keyHash" in created.apiKey, false);
assert.equal(created.apiKey.organizationId, "org-1");
assert.equal(created.apiKey.serviceAccountId, "service-account-1");

const auditWrite = writes.find((write) => write.eventType === "api_key.created");
const apiKeyWrite = writes.find((write) => write.keyHash);
assert.ok(auditWrite);
assert.ok(apiKeyWrite);
assert.equal(auditWrite.organizationId, "org-1");
assert.equal(auditWrite.serviceAccountId, "service-account-1");
assert.equal(auditWrite.userId, "user-1");
assert.equal(auditWrite.metadata.keyPrefix, created.apiKey.keyPrefix);
assert.equal(JSON.stringify(auditWrite).includes(created.plaintextKey), false);
assert.equal(JSON.stringify(auditWrite).includes(apiKeyWrite.keyHash), false);

console.log("api key tests passed");

function fakeDatabase(writes = []) {
  return {
    insert() {
      return {
        values(value) {
          writes.push(value);
          return {
            async returning() {
              if (value.eventType) {
                return [{ id: "audit-1", ...value }];
              }

              return [{ id: "api-key-created", ...value }];
            },
          };
        },
      };
    },
  };
}
