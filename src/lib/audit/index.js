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
