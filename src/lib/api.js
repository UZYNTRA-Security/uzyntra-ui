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
};
