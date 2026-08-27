import "server-only";

import { db } from "../../db/client.js";
import { auditEvents } from "../../db/schema.js";

export const AUDIT_RESULTS = Object.freeze({
  SUCCESS: "success",
  FAILURE: "failure",
  DENIED: "denied",
  ERROR: "error",
});

export const AUDIT_SEVERITIES = Object.freeze({
  INFO: "info",
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
});

export const AUDIT_EVENT_TYPES = Object.freeze({
  AUTH_LOGIN_SUCCESS: "auth.login.success",
  AUTH_LOGIN_FAILURE: "auth.login.failure",
  AUTH_LOGOUT: "auth.logout",
  AUTH_SESSION_REVOKED: "auth.session.revoked",
  IDENTITY_LINKED: "identity.linked",
  IDENTITY_UNLINKED: "identity.unlinked",
  IDENTITY_VERIFIED: "identity.verified",
  IDENTITY_LOGIN_SUCCESS: "identity.login.success",
  IDENTITY_LOGIN_FAILURE: "identity.login.failure",
  IDENTITY_SESSION_CREATED: "identity.session.created",
  IDENTITY_SESSION_REVOKED: "identity.session.revoked",
  AUTHZ_ALLOWED: "authz.allowed",
  AUTHZ_DENIED: "authz.denied",
  POLICY_UPDATED: "policy.updated",
  MITIGATION_CREATED: "mitigation.created",
  MITIGATION_DELETED: "mitigation.deleted",
  USER_CREATED: "user.created",
  ROLE_UPDATED: "role.updated",
  ORGANIZATION_CREATED: "organization.created",
  ORGANIZATION_UPDATED: "organization.updated",
  ORGANIZATION_SWITCHED: "organization.switched",
  ORGANIZATION_SETTINGS_UPDATED: "org.settings_updated",
  MEMBER_INVITED: "member.invited",
  MEMBER_JOINED: "member.joined",
  MEMBER_DISABLED: "member.disabled",
  MEMBER_REACTIVATED: "member.reactivated",
  MEMBER_ROLE_CHANGED: "member.role_changed",
  INVITATION_REVOKED: "member.invitation_revoked",
  FIREWALL_REGISTERED: "firewall.registered",
  FIREWALL_ENROLLMENT_TOKEN_CREATED: "firewall.enrollment_token_created",
  FIREWALL_ENROLLED: "firewall.enrolled",
  FIREWALL_DISABLED: "firewall.disabled",
  FIREWALL_ENROLLMENT_FAILED: "firewall.enrollment_failed",
  SERVICE_ACCOUNT_CREATED: "service_account.created",
  SERVICE_ACCOUNT_DISABLED: "service_account.disabled",
  SERVICE_ACCOUNT_REACTIVATED: "service_account.reactivated",
  SERVICE_ACCOUNT_DELETED: "service_account.deleted",
  API_KEY_CREATED: "api_key.created",
  API_KEY_REVOKED: "api_key.revoked",
  API_KEY_ROTATED: "api_key.rotated",
  SECURITY_EVENT_INGESTED: "security_event.ingested",
  SECURITY_EVENT_INGESTION_FAILED: "security_event.ingestion_failed",
  FIREWALL_UPDATED: "firewall.updated",
  ALERT_RULE_CREATED: "alert_rule.created",
  ALERT_RULE_UPDATED: "alert_rule.updated",
  ALERT_RULE_ENABLED: "alert_rule.enabled",
  ALERT_RULE_DISABLED: "alert_rule.disabled",
  ALERT_ACKNOWLEDGED: "alert.acknowledged",
  ALERT_RESOLVED: "alert.resolved",
  ALERT_SUPPRESSED: "alert.suppressed",
  INCIDENT_CREATED: "incident.created",
  INCIDENT_ASSIGNED: "incident.assigned",
  INCIDENT_RESOLVED: "incident.resolved",
  NOTIFICATION_CHANNEL_CREATED: "notification_channel.created",
  NOTIFICATION_CHANNEL_UPDATED: "notification_channel.updated",
  NOTIFICATION_CHANNEL_DISABLED: "notification_channel.disabled",
  WEBHOOK_SECRET_ROTATED: "webhook.secret_rotated",
  EXPORT_CREATED: "export.created",
  ZERO_TRUST_POLICY_CREATED: "zero_trust.policy.created",
  ZERO_TRUST_POLICY_UPDATED: "zero_trust.policy.updated",
  ZERO_TRUST_POLICY_ACTIVATED: "zero_trust.policy.activated",
  ZERO_TRUST_POLICY_ROLLED_BACK: "zero_trust.policy.rolled_back",
  ZERO_TRUST_POLICY_SIMULATED: "zero_trust.policy.simulated",
  ZERO_TRUST_DECISION_RECORDED: "zero_trust.decision.recorded",
  EMERGENCY_BYPASS_CREATED: "emergency_bypass.created",
  EMERGENCY_BYPASS_EXPIRED: "emergency_bypass.expired",
  EMERGENCY_BYPASS_USED: "emergency_bypass.used",
  PROTECTION_RULE_CREATED: "protection.rule.created",
  PROTECTION_RULE_UPDATED: "protection.rule.updated",
  PROTECTION_SIMULATED: "protection.simulated",
  ENFORCEMENT_EVENT_RECORDED: "protection.enforcement_event.recorded",
  RATE_LIMIT_POLICY_CREATED: "protection.rate_limit.created",
  PROTECTION_BLOCKLIST_UPDATED: "protection.blocklist.updated",
  PROTECTION_ALLOWLIST_UPDATED: "protection.allowlist.updated",
  CREDENTIAL_PROTECTION_UPDATED: "protection.credential.updated",
  POLICY_SIMULATION_RUN: "policy_simulation.run",
  POLICY_TEST_CASE_CREATED: "policy_test_case.created",
  POLICY_CHANGE_REQUESTED: "policy_change_request.requested",
  SOAR_PLAYBOOK_CREATED: "soar.playbook.created",
  SOAR_PLAYBOOK_UPDATED: "soar.playbook.updated",
  SOAR_AUTOMATION_EXECUTED: "soar.automation.executed",
  SOAR_ACTION_EXECUTED: "soar.action.executed",
  SOAR_ACTION_APPROVED: "soar.action.approved",
  SOAR_INVESTIGATION_CREATED: "soar.investigation.created",
  SOAR_EVIDENCE_COLLECTED: "soar.evidence.collected",
  AI_SESSION_CREATED: "ai.session.created",
  AI_QUERY_EXECUTED: "ai.query.executed",
  AI_REPORT_GENERATED: "ai.report.generated",
  AI_FEEDBACK_SUBMITTED: "ai.feedback.submitted",
  ENTERPRISE_HIERARCHY_UPDATED: "enterprise.hierarchy.updated",
  ENTERPRISE_CUSTOMER_CREATED: "enterprise.customer.created",
  DELEGATED_ACCESS_GRANTED: "enterprise.delegated_access.granted",
  COMPLIANCE_REPORT_CREATED: "enterprise.compliance_report.created",
  USAGE_RECORD_CREATED: "enterprise.usage.record_created",
  PLATFORM_REGION_CREATED: "platform.region.created",
  TENANT_REGION_ASSIGNED: "platform.tenant_region.assigned",
  REGIONAL_SERVICE_REGISTERED: "platform.regional_service.registered",
  PLATFORM_HEALTH_RECORDED: "platform.health.recorded",
  BACKUP_JOB_RECORDED: "platform.backup.recorded",
  RESTORE_OPERATION_RECORDED: "platform.restore.recorded",
  DEVELOPER_APP_CREATED: "developer.app.created",
  INTEGRATION_CATALOG_CREATED: "integration.catalog.created",
  MARKETPLACE_LISTING_CREATED: "marketplace.listing.created",
});

export async function createAuditEvent({ database = db(), ...event } = {}) {
  const values = normalizeAuditEvent(event);
  assertAuditEventSafe(values);

  const [created] = await database.insert(auditEvents).values(values).returning();
  return created;
}

export function normalizeAuditEvent(event = {}) {
  const required = ["eventType", "action", "result"];
  required.forEach((field) => {
    if (!event[field] || typeof event[field] !== "string") {
      throw new Error(`audit event ${field} is required`);
    }
  });

  const result = normalizeEnum(event.result, Object.values(AUDIT_RESULTS), "audit result");
  const severity = normalizeEnum(
    event.severity || AUDIT_SEVERITIES.INFO,
    Object.values(AUDIT_SEVERITIES),
    "audit severity",
  );

  return {
    organizationId: nullableString(event.organizationId),
    userId: nullableString(event.userId),
    serviceAccountId: nullableString(event.serviceAccountId),
    firewallInstanceId: nullableString(event.firewallInstanceId),
    eventType: boundedString(event.eventType, 160),
    action: boundedString(event.action, 160),
    resourceType: nullableBoundedString(event.resourceType, 120),
    resourceId: nullableBoundedString(event.resourceId, 160),
    result,
    severity,
    ipAddress: nullableBoundedString(event.ipAddress, 45),
    userAgent: nullableCleanString(event.userAgent, 1024),
    requestId: nullableBoundedString(event.requestId, 160),
    metadata: normalizeMetadata(event.metadata),
  };
}

export function assertAuditEventSafe(event) {
  const unsafePath = firstSensitivePath(event);
  if (unsafePath) {
    throw new Error(`audit event contains sensitive field: ${unsafePath}`);
  }
}

function normalizeMetadata(metadata) {
  if (metadata == null) {
    return {};
  }

  if (Array.isArray(metadata) || typeof metadata !== "object") {
    throw new Error("audit metadata must be an object");
  }

  return JSON.parse(JSON.stringify(metadata));
}

function firstSensitivePath(value, path = []) {
  if (!value || typeof value !== "object") {
    return null;
  }

  for (const [key, child] of Object.entries(value)) {
    const currentPath = [...path, key];
    if (isSensitiveKey(key)) {
      return currentPath.join(".");
    }

    const nested = firstSensitivePath(child, currentPath);
    if (nested) {
      return nested;
    }
  }

  return null;
}

function isSensitiveKey(key) {
  return /password|secret|token|cookie|authorization|private[_-]?key|session[_-]?id|key[_-]?hash|password[_-]?hash|x[_-]?admin[_-]?token/i.test(
    key,
  );
}

function normalizeEnum(value, allowed, label) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!allowed.includes(normalized)) {
    throw new Error(`${label} is invalid`);
  }

  return normalized;
}

function nullableString(value) {
  if (!value) {
    return null;
  }

  return String(value);
}

function boundedString(value, maxLength) {
  const text = String(value || "").trim();
  if (!text) {
    throw new Error("audit value is required");
  }

  return text.slice(0, maxLength);
}

function nullableBoundedString(value, maxLength) {
  if (!value) {
    return null;
  }

  return String(value).trim().slice(0, maxLength) || null;
}

function nullableCleanString(value, maxLength) {
  if (!value) {
    return null;
  }

  return String(value).replace(/[^\x20-\x7E]/g, "").trim().slice(0, maxLength) || null;
}
