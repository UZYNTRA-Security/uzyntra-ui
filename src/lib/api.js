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
};
