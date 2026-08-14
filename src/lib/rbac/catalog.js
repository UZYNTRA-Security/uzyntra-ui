import "server-only";

export const PERMISSIONS = Object.freeze({
  EVENTS_READ: "events.read",
  EVENTS_EXPORT: "events.export",
  METRICS_READ: "metrics.read",
  AUDITS_READ: "audits.read",
  MITIGATION_READ: "mitigation.read",
  MITIGATION_CREATE: "mitigation.create",
  MITIGATION_DELETE: "mitigation.delete",
  REPUTATION_READ: "reputation.read",
  REPUTATION_RESET: "reputation.reset",
  POLICY_READ: "policy.read",
  POLICY_UPDATE: "policy.update",
  USERS_MANAGE: "users.manage",
  ROLES_MANAGE: "roles.manage",
  ORGANIZATIONS_MANAGE: "organizations.manage",
  ORGANIZATION_SETTINGS_MANAGE: "organization_settings.manage",
  API_KEYS_MANAGE: "api_keys.manage",
  SERVICE_ACCOUNTS_MANAGE: "service_accounts.manage",
  BILLING_MANAGE: "billing.manage",
  FIREWALLS_MANAGE: "firewalls.manage",
  SECURITY_EVENTS_INGEST: "security_events.ingest",
});

export const PERMISSION_CATALOG = Object.freeze([
  permission(PERMISSIONS.EVENTS_READ, "Read security events"),
  permission(PERMISSIONS.EVENTS_EXPORT, "Export security events"),
  permission(PERMISSIONS.METRICS_READ, "Read security metrics"),
  permission(PERMISSIONS.AUDITS_READ, "Read audit entries"),
  permission(PERMISSIONS.MITIGATION_READ, "Read active mitigations"),
  permission(PERMISSIONS.MITIGATION_CREATE, "Create mitigations"),
  permission(PERMISSIONS.MITIGATION_DELETE, "Remove mitigations"),
  permission(PERMISSIONS.REPUTATION_READ, "Read source reputation"),
  permission(PERMISSIONS.REPUTATION_RESET, "Reset source reputation"),
  permission(PERMISSIONS.POLICY_READ, "Read firewall policy"),
  permission(PERMISSIONS.POLICY_UPDATE, "Update firewall policy"),
  permission(PERMISSIONS.USERS_MANAGE, "Manage organization users"),
  permission(PERMISSIONS.ROLES_MANAGE, "Manage organization roles"),
  permission(PERMISSIONS.ORGANIZATIONS_MANAGE, "Manage organizations"),
  permission(PERMISSIONS.ORGANIZATION_SETTINGS_MANAGE, "Manage organization settings"),
  permission(PERMISSIONS.API_KEYS_MANAGE, "Manage API keys"),
  permission(PERMISSIONS.SERVICE_ACCOUNTS_MANAGE, "Manage service accounts"),
  permission(PERMISSIONS.BILLING_MANAGE, "Manage billing settings"),
  permission(PERMISSIONS.FIREWALLS_MANAGE, "Manage firewall instances"),
  permission(PERMISSIONS.SECURITY_EVENTS_INGEST, "Ingest security telemetry"),
]);

export const DEFAULT_ROLES = Object.freeze([
  role("Owner", "Full organization control", Object.values(PERMISSIONS)),
  role("Security Admin", "Manage security operations and policy", [
    PERMISSIONS.EVENTS_READ,
    PERMISSIONS.EVENTS_EXPORT,
    PERMISSIONS.METRICS_READ,
    PERMISSIONS.AUDITS_READ,
    PERMISSIONS.MITIGATION_READ,
    PERMISSIONS.MITIGATION_CREATE,
    PERMISSIONS.MITIGATION_DELETE,
    PERMISSIONS.REPUTATION_READ,
    PERMISSIONS.REPUTATION_RESET,
    PERMISSIONS.POLICY_READ,
    PERMISSIONS.POLICY_UPDATE,
    PERMISSIONS.FIREWALLS_MANAGE,
    PERMISSIONS.API_KEYS_MANAGE,
    PERMISSIONS.SERVICE_ACCOUNTS_MANAGE,
  ]),
  role("Analyst", "Investigate activity and review reputation", [
    PERMISSIONS.EVENTS_READ,
    PERMISSIONS.METRICS_READ,
    PERMISSIONS.AUDITS_READ,
    PERMISSIONS.REPUTATION_READ,
  ]),
  role("Viewer", "Read basic security telemetry", [
    PERMISSIONS.EVENTS_READ,
    PERMISSIONS.METRICS_READ,
  ]),
]);

function permission(key, description) {
  return Object.freeze({ key, description });
}

function role(name, description, permissions) {
  return Object.freeze({ name, description, permissions: Object.freeze([...permissions]) });
}
