import "server-only";

import { and, eq, isNull } from "drizzle-orm";
import { db } from "../../db/client.js";
import { firewallInstances, securityEvents } from "../../db/schema.js";
import { upsertApiInventoryFromSecurityEvent } from "../api-inventory/index.js";

export const SECURITY_EVENT_TYPES = Object.freeze({
  ATTACK: "attack",
  POLICY: "policy",
  ANOMALY: "anomaly",
});

export const SECURITY_ATTACK_TYPES = Object.freeze({
  SQL_INJECTION: "sql_injection",
  XSS: "xss",
  COMMAND_INJECTION: "command_injection",
  PATH_TRAVERSAL: "path_traversal",
  CREDENTIAL_ATTACK: "credential_attack",
  SSRF: "ssrf",
  REQUEST_SMUGGLING: "request_smuggling",
  SCHEMA_VIOLATION: "schema_violation",
  OBJECT_ENUMERATION: "object_enumeration",
  TENANT_BOUNDARY_VIOLATION: "tenant_boundary_violation",
  SHADOW_API: "shadow_api",
  API_INVENTORY: "api_inventory",
  RESOURCE_ABUSE: "resource_abuse",
  SECURITY_MISCONFIGURATION: "security_misconfiguration",
  RESPONSE_LEAK: "response_leak",
  PAYLOAD_EVASION: "payload_evasion",
  METHOD_ABUSE: "method_abuse",
  BEHAVIOR_ANOMALY: "behavior_anomaly",
  RATE_LIMIT_EXCEEDED: "rate_limit_exceeded",
});

export const SECURITY_EVENT_SEVERITIES = Object.freeze({
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
});

export const SECURITY_EVENT_ACTIONS = Object.freeze({
  BLOCKED: "blocked",
  ALLOWED: "allowed",
  RATE_LIMITED: "rate_limited",
  CHALLENGED: "challenged",
});

export async function createSecurityEvent({ database = db(), ...event } = {}) {
  const values = normalizeSecurityEvent(event);
  validateSecurityEvent(values);
  await validateFirewallOwnership(database, values.organizationId, values.firewallInstanceId);

  const [created] = await database.insert(securityEvents).values(values).returning();
  await upsertApiInventoryFromSecurityEvent({ database, event: created });
  return created;
}

export function normalizeSecurityEvent(event = {}) {
  return {
    organizationId: requiredString(event.organizationId, "organizationId"),
    firewallInstanceId: requiredString(event.firewallInstanceId, "firewallInstanceId"),
    eventType: normalizedToken(event.eventType, "eventType", 80),
    attackType: normalizedToken(event.attackType, "attackType", 80),
    severity: normalizedEnum(
      event.severity,
      Object.values(SECURITY_EVENT_SEVERITIES),
      "security event severity",
    ),
    sourceIp: nullableBoundedString(event.sourceIp, 45),
    requestPath: nullableCleanString(event.requestPath, 2048),
    httpMethod: nullableHttpMethod(event.httpMethod),
    userAgent: nullableCleanString(event.userAgent, 1024),
    country: nullableCountry(event.country),
    confidence: nullableConfidence(event.confidence),
    detectorId: nullableDetectorId(event.detectorId || event.detector_id),
    detectorIds: normalizeDetectorIds(event.detectorIds || event.detector_ids),
    score: nullableScore(event.score),
    apiRouteId: nullableCleanString(event.apiRouteId || event.api_route_id, 2048),
    anomalyType: nullableToken(event.anomalyType || event.anomaly_type, "anomalyType", 80),
    actionTaken: normalizedEnum(
      event.actionTaken,
      Object.values(SECURITY_EVENT_ACTIONS),
      "security event action",
    ),
    requestId: nullableBoundedString(event.requestId, 160),
    rawMetadata: sanitizeMetadata(event.rawMetadata),
    occurredAt: requiredDate(event.occurredAt, "occurredAt"),
  };
}

export function validateSecurityEvent(event = {}) {
  requiredString(event.organizationId, "organizationId");
  requiredString(event.firewallInstanceId, "firewallInstanceId");
  normalizedToken(event.eventType, "eventType", 80);
  normalizedToken(event.attackType, "attackType", 80);
  normalizedEnum(event.severity, Object.values(SECURITY_EVENT_SEVERITIES), "security event severity");
  normalizedEnum(event.actionTaken, Object.values(SECURITY_EVENT_ACTIONS), "security event action");
  nullableConfidence(event.confidence);
  nullableDetectorId(event.detectorId);
  normalizeDetectorIds(event.detectorIds);
  nullableScore(event.score);
  requiredDate(event.occurredAt, "occurredAt");
  sanitizeMetadata(event.rawMetadata);

  return true;
}

export async function validateFirewallOwnership(database, organizationId, firewallInstanceId) {
  const [firewall] = await database
    .select({
      id: firewallInstances.id,
      organizationId: firewallInstances.organizationId,
      status: firewallInstances.status,
      deletedAt: firewallInstances.deletedAt,
    })
    .from(firewallInstances)
    .where(
      and(
        eq(firewallInstances.id, firewallInstanceId),
        eq(firewallInstances.organizationId, organizationId),
        eq(firewallInstances.status, "active"),
        isNull(firewallInstances.deletedAt),
      ),
    )
    .limit(1);

  if (
    !firewall ||
    firewall.id !== firewallInstanceId ||
    firewall.organizationId !== organizationId ||
    firewall.status !== "active" ||
    firewall.deletedAt
  ) {
    throw new Error("firewall instance is not available for this organization");
  }

  return firewall;
}

export function sanitizeMetadata(metadata) {
  if (metadata == null) {
    return {};
  }

  if (Array.isArray(metadata) || typeof metadata !== "object") {
    throw new Error("security event rawMetadata must be an object");
  }

  return sanitizeJsonValue(metadata, []);
}

function sanitizeJsonValue(value, path) {
  if (path.length > 8) {
    throw new Error(`security event metadata exceeds maximum depth: ${path.join(".")}`);
  }

  if (value == null || typeof value === "boolean" || typeof value === "number") {
    return value;
  }

  if (typeof value === "string") {
    return cleanString(value, 2048);
  }

  if (Array.isArray(value)) {
    return value.slice(0, 50).map((item, index) => sanitizeJsonValue(item, [...path, String(index)]));
  }

  if (typeof value === "object") {
    const entries = Object.entries(value).slice(0, 100);
    return entries.reduce((safe, [key, child]) => {
      const cleanKey = cleanMetadataKey(key);
      const currentPath = [...path, cleanKey];
      if (isSensitiveMetadataKey(cleanKey)) {
        throw new Error(`security event metadata contains sensitive field: ${currentPath.join(".")}`);
      }

      safe[cleanKey] = sanitizeJsonValue(child, currentPath);
      return safe;
    }, {});
  }

  throw new Error("security event metadata contains unsupported value");
}

function cleanMetadataKey(key) {
  const cleanKey = String(key || "")
    .replace(/[^\w.-]/g, "_")
    .slice(0, 120);

  if (!cleanKey) {
    throw new Error("security event metadata contains an empty key");
  }

  return cleanKey;
}

function isSensitiveMetadataKey(key) {
  return /password|secret|token|cookie|authorization|private[_-]?key|session|key[_-]?hash|password[_-]?hash|api[_-]?key|x[_-]?admin[_-]?token/i.test(
    key,
  );
}

function normalizedEnum(value, allowed, label) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!allowed.includes(normalized)) {
    throw new Error(`${label} is invalid`);
  }

  return normalized;
}

function normalizedToken(value, label, maxLength) {
  const normalized = requiredString(value, label).trim().toLowerCase();
  if (!/^[a-z0-9_.:-]+$/.test(normalized)) {
    throw new Error(`${label} must use a stable token format`);
  }

  return normalized.slice(0, maxLength);
}

function nullableToken(value, label, maxLength) {
  if (!value) {
    return null;
  }

  return normalizedToken(value, label, maxLength);
}

function requiredString(value, label) {
  const text = String(value || "").trim();
  if (!text) {
    throw new Error(`${label} is required`);
  }

  return text;
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

  return cleanString(value, maxLength) || null;
}

function cleanString(value, maxLength) {
  return String(value).replace(/[^\x20-\x7E]/g, "").trim().slice(0, maxLength);
}

function nullableHttpMethod(value) {
  if (!value) {
    return null;
  }

  const method = String(value).trim().toUpperCase();
  if (!/^[A-Z]{1,16}$/.test(method)) {
    throw new Error("httpMethod is invalid");
  }

  return method;
}

function nullableCountry(value) {
  if (!value) {
    return null;
  }

  const country = String(value).trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(country)) {
    throw new Error("country must be an ISO 3166-1 alpha-2 code");
  }

  return country;
}

function nullableConfidence(value) {
  if (value == null || value === "") {
    return null;
  }

  const confidence = Number(value);
  if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
    throw new Error("confidence must be between 0 and 1");
  }

  return confidence;
}

function nullableScore(value) {
  if (value == null || value === "") {
    return null;
  }

  const score = Number(value);
  if (!Number.isFinite(score) || score < 0 || score > 100) {
    throw new Error("score must be between 0 and 100");
  }

  return score;
}

function nullableDetectorId(value) {
  if (!value) {
    return null;
  }

  return normalizedToken(value, "detectorId", 80);
}

function normalizeDetectorIds(value) {
  if (value == null || value === "") {
    return [];
  }

  const items = Array.isArray(value) ? value : [value];
  return Array.from(new Set(items.map((item) => nullableDetectorId(item)).filter(Boolean))).slice(
    0,
    50,
  );
}

function requiredDate(value, label) {
  const date = value instanceof Date ? value : new Date(value || "");
  if (Number.isNaN(date.getTime())) {
    throw new Error(`${label} is required`);
  }

  return date;
}
