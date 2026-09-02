import assert from "node:assert/strict";
import {
  AUDIT_EVENT_TYPES,
} from "../src/lib/audit/index.js";
import {
  IDENTITY_AUDIT_EVENT_TYPES,
} from "../src/lib/identity/index.js";
import {
  MFA_AUDIT_EVENTS,
  createMfaChallenge,
  createWebAuthnRegistrationChallenge,
  enrollTotpMethod,
  generateRecoveryCode,
  generateRecoveryCodes,
  generateTotpCode,
  generateTotpSecret,
  getMfaRequirement,
  hashMfaValue,
  openMfaSecret,
  registerWebAuthnCredential,
  sealMfaSecret,
  totpProvisioningUri,
  verifyMfaChallengeAndCreateSession,
  verifyTotpCode,
  verifyTotpEnrollment,
} from "../src/lib/auth/mfa.js";

process.env.AUTH_API_KEY_SECRET = "0123456789abcdef0123456789abcdef";
process.env.AUTH_SESSION_SECRET = "abcdef0123456789abcdef0123456789";
process.env.AUTH_MFA_SECRET_ENCRYPTION_KEY =
  "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

assert.equal(AUDIT_EVENT_TYPES.MFA_ENABLED, "mfa.enabled");
assert.equal(AUDIT_EVENT_TYPES.MFA_DISABLED, "mfa.disabled");
assert.equal(AUDIT_EVENT_TYPES.MFA_CHALLENGE_CREATED, "mfa.challenge.created");
assert.equal(AUDIT_EVENT_TYPES.MFA_CHALLENGE_SUCCESS, "mfa.challenge.success");
assert.equal(AUDIT_EVENT_TYPES.MFA_CHALLENGE_FAILED, "mfa.challenge.failed");
assert.equal(AUDIT_EVENT_TYPES.MFA_RECOVERY_USED, "mfa.recovery.used");
assert.equal(IDENTITY_AUDIT_EVENT_TYPES.MFA_RECOVERY_USED, "mfa.recovery.used");

const secret = generateTotpSecret();
assert.match(secret, /^[A-Z2-7]+$/);
const now = new Date("2026-08-27T12:00:00.000Z");
const code = generateTotpCode({ secret, now });
assert.match(code, /^\d{6}$/);
assert.equal(verifyTotpCode({ secret, code, now }), true);
assert.equal(verifyTotpCode({ secret, code: "000000", now }), false);
assert.equal(
  totpProvisioningUri({ secret, issuer: "UZYNTRA", accountName: "user@example.com" }).startsWith(
    "otpauth://totp/UZYNTRA:user%40example.com?",
  ),
  true,
);

const sealed = sealMfaSecret(secret);
assert.equal(sealed.format, "uzyntra.mfa.secret.v1");
assert.equal(JSON.stringify(sealed).includes(secret), false);
assert.equal(openMfaSecret(sealed), secret);

const recoveryCode = generateRecoveryCode();
assert.match(recoveryCode, /^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/);
assert.notEqual(hashMfaValue(recoveryCode), recoveryCode);

const totpWrites = [];
const totpEnrollment = await enrollTotpMethod({
  database: fakeDatabase({ writes: totpWrites }),
  organizationId: "org-1",
  userId: "user-1",
  accountName: "user@example.com",
  auditContext: { userId: "user-1", requestId: "request-1" },
});
assert.equal(totpEnrollment.method.methodType, "totp");
assert.equal(totpEnrollment.method.status, "pending");
assert.equal(totpEnrollment.otpauthUri.includes(totpEnrollment.secret), true);
assert.equal(JSON.stringify(totpWrites).includes(totpEnrollment.secret), false);

const pendingMethod = {
  id: "method-totp",
  organizationId: "org-1",
  userId: "user-1",
  methodType: "totp",
  status: "pending",
  secretCiphertext: sealMfaSecret(secret),
  deletedAt: null,
};

const verifyWrites = [];
await assert.rejects(
  () =>
    verifyTotpEnrollment({
      database: fakeDatabase({ selectQueue: [[pendingMethod]], writes: verifyWrites }),
      organizationId: "org-1",
      userId: "user-1",
      methodId: "method-totp",
      code: "000000",
      now,
    }),
  /mfa verification failed/,
);
assert.ok(verifyWrites.some((write) => write.eventType === MFA_AUDIT_EVENTS.CHALLENGE_FAILED));
assert.ok(verifyWrites.some((write) => write.result === "failure"));

const enabledMethod = await verifyTotpEnrollment({
  database: fakeDatabase({ selectQueue: [[pendingMethod]] }),
  organizationId: "org-1",
  userId: "user-1",
  methodId: "method-totp",
  code,
  now,
});
assert.equal(enabledMethod.status, "active");
assert.equal(enabledMethod.methodType, "totp");
assert.equal("secretCiphertext" in enabledMethod, false);

const challengeWrites = [];
const challenge = await createMfaChallenge({
  database: fakeDatabase({ writes: challengeWrites }),
  organizationId: "org-1",
  userId: "user-1",
  methodId: "method-totp",
  requestId: "request-2",
  now,
});
assert.ok(challenge.id);
assert.ok(challenge.token);
assert.equal(JSON.stringify(challengeWrites).includes(challenge.token), false);

await assert.rejects(
  () =>
    verifyMfaChallengeAndCreateSession({
      database: fakeDatabase({ selectQueue: [[]] }),
      challengeId: "challenge-1",
      challengeToken: "wrong",
      code,
      now,
    }),
  /mfa challenge is invalid/,
);

const activeMethod = {
  ...pendingMethod,
  status: "active",
};
const successfulWrites = [];
const sessionResult = await verifyMfaChallengeAndCreateSession({
  database: fakeDatabase({
    writes: successfulWrites,
    selectQueue: [
      [{
        id: "challenge-1",
        organizationId: "org-1",
        userId: "user-1",
        methodId: "method-totp",
        status: "pending",
        attemptCount: 0,
        maxAttempts: 5,
        expiresAt: new Date(now.getTime() + 60_000),
      }],
      [[activeMethod][0]],
      [{ organizationId: "org-1", sessionTimeoutSeconds: 900 }],
    ],
  }),
  challengeId: "challenge-1",
  challengeToken: "challenge-token",
  methodId: "method-totp",
  code,
  now,
});
assert.equal(typeof sessionResult.token, "string");
assert.ok(sessionResult.token.length > 20);
assert.ok(successfulWrites.some((write) => write.status === "succeeded"));
assert.ok(successfulWrites.some((write) => write.eventType === MFA_AUDIT_EVENTS.CHALLENGE_SUCCESS));
assert.ok(successfulWrites.some((write) => write.tokenHash));
assert.equal(JSON.stringify(successfulWrites).includes("challenge-token"), false);

const recoveryWrites = [];
const generatedRecovery = await generateRecoveryCodes({
  database: fakeDatabase({ writes: recoveryWrites }),
  organizationId: "org-1",
  userId: "user-1",
});
assert.equal(generatedRecovery.recoveryCodes.length, 10);
assert.equal(generatedRecovery.method.methodType, "recovery_codes");
assert.equal(JSON.stringify(recoveryWrites).includes(generatedRecovery.recoveryCodes[0]), false);
assert.ok(JSON.stringify(recoveryWrites).includes(hashMfaValue(generatedRecovery.recoveryCodes[0])));

const recoveryLoginWrites = [];
const recoverySession = await verifyMfaChallengeAndCreateSession({
  database: fakeDatabase({
    writes: recoveryLoginWrites,
    selectQueue: [
      [{
        id: "challenge-recovery",
        organizationId: "org-1",
        userId: "user-1",
        methodId: null,
        status: "pending",
        attemptCount: 0,
        maxAttempts: 5,
        expiresAt: new Date(now.getTime() + 60_000),
      }],
      [],
      [{ id: "recovery-1", codeHash: hashMfaValue("ABCD-EFGH-IJKL"), status: "active" }],
      [{ organizationId: "org-1", sessionTimeoutSeconds: 900 }],
    ],
  }),
  challengeId: "challenge-recovery",
  challengeToken: "challenge-token",
  recoveryCode: "ABCD-EFGH-IJKL",
  now,
});
assert.ok(recoverySession.token);
assert.ok(recoveryLoginWrites.some((write) => write.status === "used"));
assert.ok(recoveryLoginWrites.some((write) => write.eventType === MFA_AUDIT_EVENTS.RECOVERY_USED));

const webauthnChallenge = await createWebAuthnRegistrationChallenge({
  database: fakeDatabase(),
  organizationId: "org-1",
  userId: "user-1",
});
assert.ok(webauthnChallenge.id);
assert.ok(webauthnChallenge.token);

const webauthnWrites = [];
const passkey = await registerWebAuthnCredential({
  database: fakeDatabase({ writes: webauthnWrites }),
  organizationId: "org-1",
  userId: "user-1",
  credentialId: "credential-public-id",
  publicKey: "public-key-material",
  signCount: 3,
  deviceMetadata: { device: "security-key" },
});
assert.equal(passkey.methodType, "webauthn");
assert.equal(passkey.status, "active");
assert.equal(passkey.deviceMetadata.device, "security-key");
assert.equal(JSON.stringify(webauthnWrites).includes("credential-public-id"), false);
assert.equal(JSON.stringify(webauthnWrites).includes("private"), false);

const requirement = await getMfaRequirement({
  database: fakeDatabase({
    selectQueue: [
      [activeMethod],
      [{ organizationId: "org-1", mfaRequired: false }],
    ],
  }),
  organizationId: "org-1",
  userId: "user-1",
});
assert.equal(requirement.required, true);
assert.equal(requirement.reason, "user_enabled");

console.log("phase 9 MFA tests passed");

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

  if (value.challengeHash) {
    return { id: "challenge-1", ...value };
  }

  if (value.eventType) {
    return { id: `audit-${value.eventType}`, ...value };
  }

  return {
    id: value.methodType ? `method-${value.methodType}` : "inserted-1",
    ...value,
    status: value.status || "active",
    createdAt: new Date(),
  };
}

function updateResult(value) {
  return {
    id: "updated-1",
    organizationId: "org-1",
    userId: "user-1",
    methodType: "totp",
    displayName: "Authenticator app",
    ...value,
  };
}
