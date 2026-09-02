const DEFAULT_STAGING_BASE_URL = "https://staging-console.uzyntra.com";
const PRODUCTION_BASE_URL = "https://console.uzyntra.com";

export const LIVE_IDENTITY_PROVIDER_TYPES = Object.freeze({
  GOOGLE_OAUTH: "google_oauth",
  GITHUB_OAUTH: "github_oauth",
  ENTERPRISE_SAML: "enterprise_saml",
  ENTERPRISE_OIDC: "enterprise_oidc",
  SCIM: "scim",
  MFA: "mfa",
});

export const STAGING_IDENTITY_PROVIDER_REQUIREMENTS = Object.freeze({
  [LIVE_IDENTITY_PROVIDER_TYPES.GOOGLE_OAUTH]: Object.freeze({
    displayName: "Google OAuth",
    requiredVariables: Object.freeze(["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"]),
    callbackPath: "/api/auth/oauth/google/callback",
    evidence: Object.freeze(["oauth_client_id_masked", "redirect_uri", "test_user_email_masked"]),
  }),
  [LIVE_IDENTITY_PROVIDER_TYPES.GITHUB_OAUTH]: Object.freeze({
    displayName: "GitHub OAuth",
    requiredVariables: Object.freeze(["GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET"]),
    callbackPath: "/api/auth/oauth/github/callback",
    evidence: Object.freeze(["oauth_app_id_masked", "callback_url", "test_user_email_masked"]),
  }),
  [LIVE_IDENTITY_PROVIDER_TYPES.ENTERPRISE_SAML]: Object.freeze({
    displayName: "Enterprise SAML",
    requiredVariables: Object.freeze([]),
    callbackPath: "/api/auth/sso/saml/<provider>/callback",
    evidence: Object.freeze(["idp_metadata_url", "acs_url", "certificate_fingerprint"]),
  }),
  [LIVE_IDENTITY_PROVIDER_TYPES.ENTERPRISE_OIDC]: Object.freeze({
    displayName: "Enterprise OIDC",
    requiredVariables: Object.freeze(["SSO_ENTERPRISE_OIDC_CLIENT_SECRET"]),
    callbackPath: "/api/auth/sso/oidc/<provider>/callback",
    evidence: Object.freeze(["issuer", "client_id_masked", "jwks_uri", "callback_url"]),
  }),
  [LIVE_IDENTITY_PROVIDER_TYPES.SCIM]: Object.freeze({
    displayName: "SCIM",
    requiredVariables: Object.freeze(["AUTH_API_KEY_SECRET"]),
    callbackPath: "/scim/v2",
    evidence: Object.freeze(["base_url", "provider_id_masked", "token_id_masked"]),
  }),
  [LIVE_IDENTITY_PROVIDER_TYPES.MFA]: Object.freeze({
    displayName: "MFA Devices",
    requiredVariables: Object.freeze(["AUTH_MFA_SECRET_ENCRYPTION_KEY"]),
    callbackPath: "/security/mfa",
    evidence: Object.freeze(["device_type", "challenge_result", "audit_event_id"]),
  }),
});

export function buildStagingIdentityProviderChecklist({
  env = process.env,
  baseUrl = DEFAULT_STAGING_BASE_URL,
  environment = "staging",
} = {}) {
  const normalizedBaseUrl = normalizeBaseUrl(baseUrl);
  const providers = Object.entries(STAGING_IDENTITY_PROVIDER_REQUIREMENTS).map(([providerType, requirement]) => {
    const missingVariables = requirement.requiredVariables.filter((name) => !hasValue(env[name]));
    return {
      providerType,
      displayName: requirement.displayName,
      callbackUrl: callbackUrl(normalizedBaseUrl, requirement.callbackPath),
      requiredVariables: [...requirement.requiredVariables],
      variableStatus: Object.fromEntries(
        requirement.requiredVariables.map((name) => [name, hasValue(env[name]) ? "set" : "missing"]),
      ),
      missingVariables,
      evidenceRequired: [...requirement.evidence],
      status: missingVariables.length ? "needs_configuration" : "ready_for_live_validation",
    };
  });
  const separation = validateIdentityEnvironmentSeparation({ env, baseUrl: normalizedBaseUrl, environment });

  return {
    environment,
    baseUrl: normalizedBaseUrl,
    productionBaseUrl: PRODUCTION_BASE_URL,
    providers,
    separation,
    readyForLiveProviderActivation:
      separation.status === "pass" && providers.every((provider) => provider.status === "ready_for_live_validation"),
  };
}

export function validateIdentityEnvironmentSeparation({
  env = process.env,
  baseUrl = DEFAULT_STAGING_BASE_URL,
  environment = "staging",
} = {}) {
  const normalizedEnvironment = String(environment || "").trim().toLowerCase() || "staging";
  const normalizedBaseUrl = normalizeBaseUrl(baseUrl);
  const findings = [];

  if (normalizedEnvironment === "staging" && normalizedBaseUrl === PRODUCTION_BASE_URL) {
    findings.push({
      severity: "critical",
      code: "staging_uses_production_console",
      message: "Staging identity validation must not use the production console origin.",
    });
  }

  for (const name of Object.keys(env || {})) {
    if (/^PROD(UCTION)?_/i.test(name)) {
      findings.push({
        severity: "high",
        code: "production_variable_visible_in_staging",
        variable: name,
        message: "Production-scoped variables must not be present in staging identity validation.",
      });
    }
  }

  if (hasValue(env.GOOGLE_CLIENT_SECRET) && !hasValue(env.GOOGLE_CLIENT_ID)) {
    findings.push({
      severity: "medium",
      code: "google_secret_without_client_id",
      variable: "GOOGLE_CLIENT_ID",
      message: "Google OAuth staging client ID is required when its secret is configured.",
    });
  }

  if (hasValue(env.GITHUB_CLIENT_SECRET) && !hasValue(env.GITHUB_CLIENT_ID)) {
    findings.push({
      severity: "medium",
      code: "github_secret_without_client_id",
      variable: "GITHUB_CLIENT_ID",
      message: "GitHub OAuth staging client ID is required when its secret is configured.",
    });
  }

  return {
    status: findings.some((finding) => ["critical", "high"].includes(finding.severity)) ? "fail" : "pass",
    findings,
    checkedAt: new Date().toISOString(),
  };
}

export function sanitizedIdentityProviderEvidence(input = {}) {
  return {
    providerType: safeString(input.providerType, 80),
    providerName: safeString(input.providerName, 160),
    environment: safeString(input.environment || "staging", 32),
    configuredAt: input.configuredAt || null,
    callbackUrl: input.callbackUrl ? safeString(input.callbackUrl, 2048) : null,
    issuer: input.issuer ? safeString(input.issuer, 2048) : null,
    clientId: input.clientId ? maskIdentifier(input.clientId) : null,
    certificateFingerprint: input.certificateFingerprint ? safeString(input.certificateFingerprint, 128) : null,
    testAccount: input.testAccount ? maskEmail(input.testAccount) : null,
    notes: safeString(input.notes, 1000),
  };
}

export function assertNoSecretValuesInValidationResult(result, env = process.env) {
  const serialized = JSON.stringify(result);
  const leaked = Object.entries(env || {})
    .filter(([name, value]) => isSecretName(name) && hasValue(value))
    .filter(([, value]) => serialized.includes(String(value)));
  if (leaked.length) {
    throw new Error(`identity validation result exposes secret values: ${leaked.map(([name]) => name).join(", ")}`);
  }
  return true;
}

function callbackUrl(baseUrl, callbackPath) {
  if (callbackPath.includes("<provider>")) {
    return `${baseUrl}${callbackPath}`;
  }
  return `${baseUrl}${callbackPath}`;
}

function normalizeBaseUrl(value) {
  const url = new URL(value || DEFAULT_STAGING_BASE_URL);
  return url.origin;
}

function hasValue(value) {
  return typeof value === "string" && value.trim().length > 0 && !/^<.+>$/.test(value.trim());
}

function isSecretName(name) {
  return /SECRET|TOKEN|PASSWORD|PRIVATE|KEY/i.test(name);
}

function maskIdentifier(value) {
  const text = safeString(value, 255);
  if (!text) return null;
  if (text.length <= 8) return "****";
  return `${text.slice(0, 4)}...${text.slice(-4)}`;
}

function maskEmail(value) {
  const text = safeString(value, 255).toLowerCase();
  const [local, domain] = text.split("@");
  if (!local || !domain) return maskIdentifier(text);
  return `${local.slice(0, 2)}***@${domain}`;
}

function safeString(value, maxLength = 512) {
  return String(value || "")
    .replace(/[^\x20-\x7E]/g, "")
    .trim()
    .slice(0, maxLength);
}
