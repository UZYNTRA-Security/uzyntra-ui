async function request(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    cache: "no-store",
  });

  const contentType = response.headers.get("content-type") || "";
  const isJson = contentType.includes("application/json");
  const payload = isJson ? await response.json() : await response.text();

  if (!response.ok) {
    const message =
      typeof payload === "string"
        ? payload
        : payload?.error || payload?.message || "Request failed";
    throw new Error(message);
  }

  return payload;
}

function qs(params = {}) {
  const search = new URLSearchParams();

  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === "") return;
    search.set(key, String(value));
  });

  const query = search.toString();
  return query ? `?${query}` : "";
}

export const api = {
  getMetrics: () => request("/api/admin/metrics"),
  getSecurityEventAnalytics: (params = {}) =>
    request(`/api/security-events/analytics${qs(params)}`),
  getSecurityEvents: (params = {}) =>
    request(`/api/security-events${qs(params)}`),
  getSecurityDashboard: (params = {}) =>
    request(`/api/security/dashboard${qs(params)}`),
  getSecurityMetrics: (params = {}) =>
    request(`/api/security/metrics${qs(params)}`),
  getSecurityTrends: (params = {}) =>
    request(`/api/security/trends${qs(params)}`),
  getSecurityPosture: (params = {}) =>
    request(`/api/security/posture${qs(params)}`),
  getTopThreats: (params = {}) =>
    request(`/api/security/top-threats${qs(params)}`),
  getNotificationDeliveries: (params = {}) =>
    request(`/api/security/notification-deliveries${qs(params)}`),
  getNotificationHealth: (params = {}) =>
    request(`/api/security/notification-health${qs(params)}`),
  getDetections: (params = {}) => request(`/api/detections${qs(params)}`),
  getDetectionRules: (params = {}) => request(`/api/detection-rules${qs(params)}`),
  saveDetectionRule: (input) =>
    request("/api/detection-rules", { method: "POST", body: JSON.stringify(input) }),
  createDetectionFeedback: (input) =>
    request("/api/detections/feedback", { method: "POST", body: JSON.stringify(input) }),
  getRiskAnalysis: (params = {}) => request(`/api/risk-analysis${qs(params)}`),
  getCorrelationEvents: (params = {}) => request(`/api/correlation-events${qs(params)}`),
  getThreatIntelligence: (params = {}) => request(`/api/threat-intelligence${qs(params)}`),
  getThreatIndicators: (params = {}) => request(`/api/threat-indicators${qs(params)}`),
  createThreatIndicator: (input) =>
    request("/api/threat-indicators", { method: "POST", body: JSON.stringify(input) }),
  reviewThreatIndicator: (input) =>
    request("/api/threat-indicators/review", { method: "POST", body: JSON.stringify(input) }),
  getThreatMatches: (params = {}) => request(`/api/threat-matches${qs(params)}`),
  getThreatSources: (params = {}) => request(`/api/threat-sources${qs(params)}`),
  getZeroTrustPolicies: (params = {}) => request(`/api/policies${qs(params)}`),
  createZeroTrustPolicy: (input) =>
    request("/api/policies", { method: "POST", body: JSON.stringify(input) }),
  getZeroTrustPolicy: (policyId) => request(`/api/policies/${policyId}`),
  createZeroTrustPolicyVersion: (policyId, input) =>
    request(`/api/policies/${policyId}/versions`, { method: "POST", body: JSON.stringify(input) }),
  activateZeroTrustPolicy: (policyId, versionId) =>
    request(`/api/policies/${policyId}/activate`, {
      method: "POST",
      body: JSON.stringify({ versionId }),
    }),
  rollbackZeroTrustPolicy: (policyId, targetVersionId) =>
    request(`/api/policies/${policyId}/rollback`, {
      method: "POST",
      body: JSON.stringify({ targetVersionId }),
    }),
  getPolicyDecisions: (params = {}) => request(`/api/policy-decisions${qs(params)}`),
  explainPolicyDecision: (decisionId) => request(`/api/policy-decisions/explain${qs({ decisionId })}`),
  simulateZeroTrustPolicy: (input) =>
    request("/api/policy-simulator", { method: "POST", body: JSON.stringify(input) }),
  getPolicySimulations: (params = {}) => request(`/api/policy-simulations${qs(params)}`),
  getPolicyTestCases: (params = {}) => request(`/api/policy-test-cases${qs(params)}`),
  createPolicyTestCase: (input) =>
    request("/api/policy-test-cases", { method: "POST", body: JSON.stringify(input) }),
  runPolicyTestCase: (testCaseId) =>
    request("/api/policy-test-cases", { method: "POST", body: JSON.stringify({ run: true, testCaseId }) }),
  getPolicyChangeRequests: (params = {}) =>
    request(`/api/policy-change-requests${qs(params)}`),
  createPolicyChangeRequest: (input) =>
    request("/api/policy-change-requests", { method: "POST", body: JSON.stringify(input) }),
  getPlaybooks: (params = {}) => request(`/api/playbooks${qs(params)}`),
  createPlaybook: (input) =>
    request("/api/playbooks", { method: "POST", body: JSON.stringify(input) }),
  getAutomationRuns: (params = {}) => request(`/api/automation-runs${qs(params)}`),
  triggerAutomationRun: (input) =>
    request("/api/automation-runs", { method: "POST", body: JSON.stringify(input) }),
  getResponseActions: (params = {}) => request(`/api/response-actions${qs(params)}`),
  createResponseAction: (input) =>
    request("/api/response-actions", { method: "POST", body: JSON.stringify(input) }),
  getInvestigations: (params = {}) => request(`/api/investigations${qs(params)}`),
  createInvestigation: (input) =>
    request("/api/investigations", { method: "POST", body: JSON.stringify(input) }),
  getEvidence: (params = {}) => request(`/api/evidence${qs(params)}`),
  getAiSessions: (params = {}) => request(`/api/ai/sessions${qs(params)}`),
  createAiSession: (input) =>
    request("/api/ai/sessions", { method: "POST", body: JSON.stringify(input) }),
  getAiMessages: (params = {}) => request(`/api/ai/messages${qs(params)}`),
  createAiMessage: (input) =>
    request("/api/ai/messages", { method: "POST", body: JSON.stringify(input) }),
  explainSecurityContext: (input) =>
    request("/api/ai/explain", { method: "POST", body: JSON.stringify(input) }),
  getAiReports: (params = {}) => request(`/api/ai/reports${qs(params)}`),
  generateAiReport: (input) =>
    request("/api/ai/reports", { method: "POST", body: JSON.stringify(input) }),
  getAiContext: (params = {}) => request(`/api/ai/context${qs(params)}`),
  submitAiFeedback: (input) =>
    request("/api/ai/feedback", { method: "POST", body: JSON.stringify(input) }),
  getEnterpriseOverview: () => request("/api/enterprise"),
  getOrganizationHierarchy: (params = {}) =>
    request(`/api/organizations/hierarchy${qs(params)}`),
  createOrganizationHierarchy: (input) =>
    request("/api/organizations/hierarchy", { method: "POST", body: JSON.stringify(input) }),
  getCustomerTenants: (params = {}) => request(`/api/customer-tenants${qs(params)}`),
  createCustomerTenant: (input) =>
    request("/api/customer-tenants", { method: "POST", body: JSON.stringify(input) }),
  getDelegatedAccess: (params = {}) => request(`/api/delegated-access${qs(params)}`),
  createDelegatedAccess: (input) =>
    request("/api/delegated-access", { method: "POST", body: JSON.stringify(input) }),
  getComplianceReports: (params = {}) => request(`/api/compliance-reports${qs(params)}`),
  createComplianceReport: (input) =>
    request("/api/compliance-reports", { method: "POST", body: JSON.stringify(input) }),
  getUsage: (params = {}) => request(`/api/usage${qs(params)}`),
  recordUsage: (input) =>
    request("/api/usage", { method: "POST", body: JSON.stringify(input) }),
  getPlatformOverview: () => request("/api/platform"),
  getPlatformRegions: (params = {}) => request(`/api/platform/regions${qs(params)}`),
  createPlatformRegion: (input) =>
    request("/api/platform/regions", { method: "POST", body: JSON.stringify(input) }),
  assignTenantRegion: (input) =>
    request("/api/platform/regions", {
      method: "POST",
      body: JSON.stringify({ assignTenantRegion: input }),
    }),
  createRegionalService: (input) =>
    request("/api/platform/regions", {
      method: "POST",
      body: JSON.stringify({ regionalService: input }),
    }),
  getPlatformHealth: (params = {}) => request(`/api/platform/health${qs(params)}`),
  recordPlatformHealth: (input) =>
    request("/api/platform/health", { method: "POST", body: JSON.stringify(input) }),
  getDeveloperApps: (params = {}) => request(`/api/developer/apps${qs(params)}`),
  createDeveloperApp: (input) =>
    request("/api/developer/apps", { method: "POST", body: JSON.stringify(input) }),
  getIntegrationCatalog: (params = {}) => request(`/api/integrations/catalog${qs(params)}`),
  createIntegrationCatalogEntry: (input) =>
    request("/api/integrations/catalog", { method: "POST", body: JSON.stringify(input) }),
  getMarketplace: (params = {}) => request(`/api/marketplace${qs(params)}`),
  createMarketplaceListing: (input) =>
    request("/api/marketplace", { method: "POST", body: JSON.stringify(input) }),
  getEmergencyBypasses: (params = {}) => request(`/api/emergency-bypass${qs(params)}`),
  createEmergencyBypass: (input) =>
    request("/api/emergency-bypass", { method: "POST", body: JSON.stringify(input) }),
  getProtectionRules: (params = {}) => request(`/api/protection${qs(params)}`),
  createProtectionRule: (input) =>
    request("/api/protection", { method: "POST", body: JSON.stringify(input) }),
  simulateAdaptiveProtection: (input) =>
    request("/api/protection/simulate", { method: "POST", body: JSON.stringify(input) }),
  getEnforcementEvents: (params = {}) => request(`/api/enforcement-events${qs(params)}`),
  getRateLimits: (params = {}) => request(`/api/rate-limits${qs(params)}`),
  createRateLimit: (input) =>
    request("/api/rate-limits", { method: "POST", body: JSON.stringify(input) }),
  getBlocklists: (params = {}) => request(`/api/blocklists${qs(params)}`),
  createBlocklist: (input) =>
    request("/api/blocklists", { method: "POST", body: JSON.stringify(input) }),
  getAllowlists: (params = {}) => request(`/api/allowlists${qs(params)}`),
  createAllowlist: (input) =>
    request("/api/allowlists", { method: "POST", body: JSON.stringify(input) }),
  getCredentialProtection: (params = {}) => request(`/api/credential-protection${qs(params)}`),
  createCredentialProtection: (input) =>
    request("/api/credential-protection", { method: "POST", body: JSON.stringify(input) }),
  getAlerts: (params = {}) => request(`/api/alerts${qs(params)}`),
  getAlertAnalytics: () => request("/api/alerts/analytics"),
  acknowledgeAlert: (alertId, note = "") =>
    request(`/api/alerts/${alertId}/acknowledge`, {
      method: "POST",
      body: JSON.stringify({ note }),
    }),
  resolveAlert: (alertId, note = "") =>
    request(`/api/alerts/${alertId}/resolve`, {
      method: "POST",
      body: JSON.stringify({ note }),
    }),
  getAlertRules: (params = {}) => request(`/api/alert-rules${qs(params)}`),
  createAlertRule: (rule) =>
    request("/api/alert-rules", {
      method: "POST",
      body: JSON.stringify(rule),
    }),
  updateAlertRule: (ruleId, rule) =>
    request(`/api/alert-rules/${ruleId}`, {
      method: "PATCH",
      body: JSON.stringify(rule),
    }),
  deleteAlertRule: (ruleId) =>
    request(`/api/alert-rules/${ruleId}`, { method: "DELETE" }),
  getIncidents: (params = {}) => request(`/api/incidents${qs(params)}`),
  createIncident: ({ alertIds, title, summary }) =>
    request("/api/incidents", {
      method: "POST",
      body: JSON.stringify({ alertIds, title, summary }),
    }),
  updateIncident: (incidentId, patch) =>
    request(`/api/incidents/${incidentId}`, {
      method: "PATCH",
      body: JSON.stringify(patch),
    }),
  getNotificationChannels: () => request("/api/notification-channels"),
  createNotificationChannel: (channel) =>
    request("/api/notification-channels", {
      method: "POST",
      body: JSON.stringify(channel),
    }),
  getApiInventory: (params = {}) =>
    request(`/api/api-inventory${qs(params)}`),
  getEvents: (limit = 10, offset = 0) =>
    request(`/api/admin/events/recent?limit=${limit}&offset=${offset}`),
  searchEvents: (params = {}) =>
    request(`/api/admin/events/search${qs(params)}`),
  getMitigations: () => request("/api/admin/mitigations/active"),
  getAudits: (limit = 10, offset = 0) =>
    request(`/api/admin/audits/recent?limit=${limit}&offset=${offset}`),
  getReputations: () => request("/api/admin/reputations"),
  getPolicy: () => request("/api/admin/policy/effective"),

  unblockIp: (ip) =>
    request(`/api/admin/mitigations/unblock/${encodeURIComponent(ip)}`, {
      method: "POST",
    }),

  manualBlockIp: ({ source_ip, ttl_secs, reason }) =>
    request("/api/admin/mitigations/block", {
      method: "POST",
      body: JSON.stringify({ source_ip, ttl_secs, reason }),
    }),

  resetReputation: (ip) =>
    request(`/api/admin/reputations/reset/${encodeURIComponent(ip)}`, {
      method: "POST",
    }),

  setGlobalRuleMode: ({ rule_id, mode }) =>
    request("/api/admin/policy/rules/set", {
      method: "POST",
      body: JSON.stringify({ rule_id, mode }),
    }),

  upsertRouteOverride: ({ path_prefix, rule_modes }) =>
    request("/api/admin/policy/routes/upsert", {
      method: "POST",
      body: JSON.stringify({ path_prefix, rule_modes }),
    }),

  deleteRouteOverride: ({ path_prefix }) =>
    request("/api/admin/policy/routes/delete", {
      method: "POST",
      body: JSON.stringify({ path_prefix }),
    }),

  upsertRouteRateLimit: ({ path_prefix, requests_per_window, window_secs }) =>
    request("/api/admin/policy/rate-limits/upsert", {
      method: "POST",
      body: JSON.stringify({ path_prefix, requests_per_window, window_secs }),
    }),

  deleteRouteRateLimit: ({ path_prefix }) =>
    request("/api/admin/policy/rate-limits/delete", {
      method: "POST",
      body: JSON.stringify({ path_prefix }),
    }),

  me: () => request("/api/auth/me"),
  getOrganizations: () => request("/api/organizations"),
  createOrganization: ({ name, slug }) =>
    request("/api/organizations", {
      method: "POST",
      body: JSON.stringify({ name, slug }),
    }),
  switchOrganization: (organizationId) =>
    request("/api/organizations/switch", {
      method: "POST",
      body: JSON.stringify({ organizationId }),
    }),
  getRoles: () => request("/api/roles"),
  getMembers: () => request("/api/members"),
  updateMemberStatus: (membershipId, status) =>
    request(`/api/members/${membershipId}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),
  assignMemberRole: (membershipId, roleId) =>
    request(`/api/members/${membershipId}/roles`, {
      method: "POST",
      body: JSON.stringify({ roleId }),
    }),
  removeMemberRole: (membershipId, roleId) =>
    request(`/api/members/${membershipId}/roles`, {
      method: "DELETE",
      body: JSON.stringify({ roleId }),
    }),
  getInvitations: () => request("/api/invitations"),
  createInvitation: ({ email, roleId }) =>
    request("/api/invitations", {
      method: "POST",
      body: JSON.stringify({ email, roleId }),
    }),
  revokeInvitation: (invitationId) =>
    request(`/api/invitations/${invitationId}/revoke`, { method: "POST" }),
  getFirewalls: () => request("/api/firewalls"),
  registerFirewall: ({ name, environment, region, hostname }) =>
    request("/api/firewalls", {
      method: "POST",
      body: JSON.stringify({ name, environment, region, hostname }),
    }),
  createEnrollmentToken: (firewallId) =>
    request(`/api/firewalls/${firewallId}/enrollment-token`, { method: "POST" }),
  disableFirewall: (firewallId) =>
    request(`/api/firewalls/${firewallId}`, {
      method: "PATCH",
      body: JSON.stringify({ status: "disabled" }),
    }),
  selectFirewall: (firewallInstanceId) =>
    request("/api/firewalls/select", {
      method: "POST",
      body: JSON.stringify({ firewallInstanceId }),
    }),
  getServiceAccounts: () => request("/api/service-accounts"),
  createServiceAccount: ({ name, roleId }) =>
    request("/api/service-accounts", {
      method: "POST",
      body: JSON.stringify({ name, roleId }),
    }),
  updateServiceAccountStatus: (serviceAccountId, status) =>
    request(`/api/service-accounts/${serviceAccountId}`, {
      method: "PATCH",
      body: JSON.stringify({ status }),
    }),
  getApiKeys: () => request("/api/api-keys"),
  createApiKey: ({ name, serviceAccountId, expiresAt }) =>
    request("/api/api-keys", {
      method: "POST",
      body: JSON.stringify({ name, serviceAccountId, expiresAt }),
    }),
  revokeApiKey: (apiKeyId) => request(`/api/api-keys/${apiKeyId}/revoke`, { method: "POST" }),
  rotateApiKey: (apiKeyId, replacementName) =>
    request(`/api/api-keys/${apiKeyId}/rotate`, {
      method: "POST",
      body: JSON.stringify({ replacementName }),
    }),
  getOrganizationSettings: () => request("/api/organization-settings"),
  updateOrganizationSettings: (settings) =>
    request("/api/organization-settings", {
      method: "PATCH",
      body: JSON.stringify(settings),
    }),
  getIdentityProviders: () => request("/api/identity/providers"),
  getIdentityStatus: () => request("/api/identity/status"),
  getSsoProviders: () => request("/api/identity/sso/providers"),
  createSsoProvider: (provider) =>
    request("/api/identity/sso/providers", {
      method: "POST",
      body: JSON.stringify(provider),
    }),
  getScimProviders: () => request("/api/identity/scim"),
  createScimProvider: (provider) =>
    request("/api/identity/scim", {
      method: "POST",
      body: JSON.stringify(provider),
    }),
  generateScimToken: (input) =>
    request("/api/identity/scim", {
      method: "POST",
      body: JSON.stringify({ ...input, generateToken: true }),
    }),
  getIdentitySecurityDashboard: () => request("/api/identity/security"),
  getIdentitySecurityEvents: (params = {}) =>
    request(`/api/identity/security/events${qs(params)}`),
  getIdentityRiskScores: (params = {}) =>
    request(`/api/identity/security/risk-scores${qs(params)}`),
  createIdentityRiskScore: (input) =>
    request("/api/identity/security/risk-scores", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  getIdentityAccessReviews: (params = {}) =>
    request(`/api/identity/access-reviews${qs(params)}`),
  createIdentityAccessReview: (input) =>
    request("/api/identity/access-reviews", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  completeIdentityAccessReview: (input) =>
    request("/api/identity/access-reviews", {
      method: "POST",
      body: JSON.stringify({ ...input, completeReview: true }),
    }),
  getIdentityComplianceReports: (params = {}) =>
    request(`/api/identity/compliance-reports${qs(params)}`),
  createIdentityComplianceReport: (input) =>
    request("/api/identity/compliance-reports", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  getIdentityObservability: (params = {}) =>
    request(`/api/identity/observability${qs(params)}`),
  getIdentityMetrics: (params = {}) =>
    request(`/api/identity/hardening/metrics${qs(params)}`),
  recordIdentityMetric: (input) =>
    request("/api/identity/hardening/metrics", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  getIdentityAuditReports: (params = {}) =>
    request(`/api/identity/audit-reports${qs(params)}`),
  createIdentityAuditReport: (input) =>
    request("/api/identity/audit-reports", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  getIdentitySecurityReport: (params = {}) =>
    request(`/api/identity/security-report${qs(params)}`),
  generateIdentitySecurityReport: (params = {}) =>
    request(`/api/identity/security-report${qs(params)}`, {
      method: "POST",
    }),
  getIdentityRecoveryState: (params = {}) =>
    request(`/api/identity/recovery${qs(params)}`),
  createIdentityRecoveryWorkflow: (input) =>
    request("/api/identity/recovery", {
      method: "POST",
      body: JSON.stringify(input),
    }),
  createBreakGlassAdministrator: (input) =>
    request("/api/identity/recovery", {
      method: "POST",
      body: JSON.stringify({ ...input, breakGlassAdministrator: true }),
    }),
  getMfaMethods: () => request("/api/mfa/methods"),
  enrollTotp: () => request("/api/mfa/totp/enroll", { method: "POST" }),
  verifyTotp: ({ methodId, code }) =>
    request("/api/mfa/totp/verify", { method: "POST", body: JSON.stringify({ methodId, code }) }),
  generateRecoveryCodes: () => request("/api/mfa/recovery-codes", { method: "POST" }),
  createWebAuthnChallenge: () => request("/api/mfa/webauthn/challenge", { method: "POST" }),
  disableMfaMethod: (methodId) => request(`/api/mfa/methods/${methodId}`, { method: "DELETE" }),
  verifyMfaLogin: ({ code, recoveryCode, methodId } = {}) =>
    request("/api/auth/mfa/verify", {
      method: "POST",
      body: JSON.stringify({ code, recoveryCode, methodId }),
    }),
};
