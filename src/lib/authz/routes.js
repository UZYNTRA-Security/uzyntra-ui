import "server-only";

import { PERMISSIONS } from "../rbac/catalog.js";

export const ADMIN_ROUTE_PERMISSIONS = Object.freeze([
  adminRoute("GET", /^metrics$/, PERMISSIONS.METRICS_READ),
  adminRoute("GET", /^events\/recent$/, PERMISSIONS.EVENTS_READ),
  adminRoute("GET", /^events\/search$/, PERMISSIONS.EVENTS_READ),
  adminRoute("GET", /^mitigations\/active$/, PERMISSIONS.MITIGATION_READ),
  adminRoute("GET", /^audits\/recent$/, PERMISSIONS.AUDITS_READ),
  adminRoute("GET", /^reputations$/, PERMISSIONS.REPUTATION_READ),
  adminRoute("GET", /^policy\/effective$/, PERMISSIONS.POLICY_READ),
  adminRoute("POST", /^mitigations\/unblock\/[A-Za-z0-9.:%_-]+$/, PERMISSIONS.MITIGATION_DELETE),
  adminRoute("POST", /^mitigations\/block$/, PERMISSIONS.MITIGATION_CREATE),
  adminRoute("POST", /^reputations\/reset\/[A-Za-z0-9.:%_-]+$/, PERMISSIONS.REPUTATION_RESET),
  adminRoute("POST", /^policy\/rules\/set$/, PERMISSIONS.POLICY_UPDATE),
  adminRoute("POST", /^policy\/routes\/upsert$/, PERMISSIONS.POLICY_UPDATE),
  adminRoute("POST", /^policy\/routes\/delete$/, PERMISSIONS.POLICY_UPDATE),
  adminRoute("POST", /^policy\/rate-limits\/upsert$/, PERMISSIONS.POLICY_UPDATE),
  adminRoute("POST", /^policy\/rate-limits\/delete$/, PERMISSIONS.POLICY_UPDATE),
]);

export function requiredPermissionForAdminRoute(method, pathKey) {
  const route = ADMIN_ROUTE_PERMISSIONS.find(
    (item) => item.method === method && item.pattern.test(pathKey),
  );

  return route?.permission || null;
}

function adminRoute(method, pattern, permission) {
  return Object.freeze({ method, pattern, permission });
}
