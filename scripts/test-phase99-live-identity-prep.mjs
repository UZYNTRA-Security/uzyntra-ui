import assert from "node:assert/strict";
import {
  assertNoSecretValuesInValidationResult,
  buildStagingIdentityProviderChecklist,
  sanitizedIdentityProviderEvidence,
  validateIdentityEnvironmentSeparation,
} from "../src/lib/identity-live-validation/index.js";

const stagingEnv = {
  GOOGLE_CLIENT_ID: "google-client-id",
  GOOGLE_CLIENT_SECRET: "google-client-secret",
  GITHUB_CLIENT_ID: "github-client-id",
  GITHUB_CLIENT_SECRET: "github-client-secret",
  SSO_ENTERPRISE_OIDC_CLIENT_SECRET: "oidc-client-secret",
  AUTH_API_KEY_SECRET: "0123456789abcdef0123456789abcdef",
  AUTH_MFA_SECRET_ENCRYPTION_KEY: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
};

const checklist = buildStagingIdentityProviderChecklist({
  env: stagingEnv,
  baseUrl: "https://staging-console.uzyntra.com/login",
  environment: "staging",
});

assert.equal(checklist.environment, "staging");
assert.equal(checklist.baseUrl, "https://staging-console.uzyntra.com");
assert.equal(checklist.readyForLiveProviderActivation, true);
assert.equal(checklist.separation.status, "pass");
assert.equal(
  checklist.providers.find((provider) => provider.providerType === "google_oauth").callbackUrl,
  "https://staging-console.uzyntra.com/api/auth/oauth/google/callback",
);
assert.equal(
  checklist.providers.find((provider) => provider.providerType === "github_oauth").callbackUrl,
  "https://staging-console.uzyntra.com/api/auth/oauth/github/callback",
);
assert.equal(
  checklist.providers.find((provider) => provider.providerType === "enterprise_saml").callbackUrl,
  "https://staging-console.uzyntra.com/api/auth/sso/saml/<provider>/callback",
);
assert.equal(JSON.stringify(checklist).includes("google-client-secret"), false);
assert.equal(JSON.stringify(checklist).includes("oidc-client-secret"), false);
assert.equal(assertNoSecretValuesInValidationResult(checklist, stagingEnv), true);

const missingChecklist = buildStagingIdentityProviderChecklist({
  env: {},
  baseUrl: "https://staging-console.uzyntra.com",
});
assert.equal(missingChecklist.readyForLiveProviderActivation, false);
assert.deepEqual(
  missingChecklist.providers.find((provider) => provider.providerType === "google_oauth").missingVariables,
  ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"],
);

const productionLeak = validateIdentityEnvironmentSeparation({
  env: { PRODUCTION_GOOGLE_CLIENT_SECRET: "prod-secret" },
  baseUrl: "https://staging-console.uzyntra.com",
  environment: "staging",
});
assert.equal(productionLeak.status, "fail");
assert.equal(productionLeak.findings[0].code, "production_variable_visible_in_staging");

const productionOrigin = validateIdentityEnvironmentSeparation({
  env: stagingEnv,
  baseUrl: "https://console.uzyntra.com",
  environment: "staging",
});
assert.equal(productionOrigin.status, "fail");
assert.equal(productionOrigin.findings[0].code, "staging_uses_production_console");

const maskedEvidence = sanitizedIdentityProviderEvidence({
  providerType: "google_oauth",
  providerName: "Google staging",
  environment: "staging",
  callbackUrl: "https://staging-console.uzyntra.com/api/auth/oauth/google/callback",
  issuer: "https://accounts.google.com",
  clientId: "1234567890abcdef",
  certificateFingerprint: "AA:BB:CC",
  testAccount: "operator@example.com",
  notes: "Ready for live validation",
});
assert.equal(maskedEvidence.clientId, "1234...cdef");
assert.equal(maskedEvidence.testAccount, "op***@example.com");
assert.equal(JSON.stringify(maskedEvidence).includes("1234567890abcdef"), false);
assert.equal(JSON.stringify(maskedEvidence).includes("operator@example.com"), false);

assert.throws(
  () => assertNoSecretValuesInValidationResult({ value: "google-client-secret" }, stagingEnv),
  /exposes secret values/,
);

console.log("phase 9.9.1 live identity preparation tests passed");
