import "server-only";

import crypto from "node:crypto";
import { and, desc, eq, gte, ilike, inArray, isNull, lte, or, sql } from "drizzle-orm";
import { db } from "../../db/client.js";
import {
  alertRules,
  alertSuppressions,
  alerts,
  firewallInstances,
  incidentAlerts,
  incidents,
  notificationChannels,
  notificationDeliveries,
  securityEvents,
} from "../../db/schema.js";
import {
  AUDIT_EVENT_TYPES,
  AUDIT_RESULTS,
  AUDIT_SEVERITIES,
  createAuditEvent,
} from "../audit/index.js";
import { sealIntegrationSecret } from "../notifications/crypto.js";
import { safeWebhookPayload, validateWebhookUrl } from "../notifications/webhook.js";

export const ALERT_STATUSES = Object.freeze(["open", "acknowledged", "resolved", "suppressed"]);
export const INCIDENT_STATUSES = Object.freeze(["open", "investigating", "contained", "resolved"]);
export const SEVERITIES = Object.freeze(["low", "medium", "high", "critical"]);
export const ACTIONS = Object.freeze(["blocked", "allowed", "rate_limited", "challenged"]);
export const SUPPORTED_DETECTORS = Object.freeze([
  "method.disallowed",
  "path.traversal.basic",
  "sqli.basic",
  "xss.basic",
  "cmdi.basic",
  "ssrf.basic",
  "evasion.encoding",
  "header.crlf",
  "smuggling.cl_te",
  "auth.missing_api_key",
  "auth.invalid_api_key",
  "body.sqli.basic",
  "body.xss.basic",
  "body.cmdi.basic",
  "rate_limit.exceeded",
  "missing.x_content_type_options",
  "missing.x_frame_options",
  "missing.csp",
  "uz-api-schema-001",
  "uz-api-schema-002",
  "uz-ssrf-001",
  "uz-auth-abuse-001",
  "uz-auth-abuse-002",
  "uz-api-resource-001",
  "uz-api-inv-001",
]);

const DEFAULT_LIMIT = 25;
const MAX_LIMIT = 100;
const SEVERITY_RANK = Object.freeze({ low: 1, medium: 2, high: 3, critical: 4 });

export function normalizeAlertRule(input = {}) {
  const detectorIds = tokenList(input.detectorIds || input.detector_ids, 80);
  detectorIds.forEach((detector) => {
    if (!SUPPORTED_DETECTORS.includes(detector)) {
      throw new Error(`unsupported detector id: ${detector}`);
    }
  });

  const attackTypes = tokenList(input.attackTypes || input.attack_types, 80);
  const anomalyTypes = tokenList(input.anomalyTypes || input.anomaly_types, 80);
  const actions = tokenList(input.actions, 32);
  actions.forEach((action) => {
    if (!ACTIONS.includes(action)) throw new Error(`unsupported alert action: ${action}`);
  });

  const routePatterns = routePatternList(input.routePatterns || input.route_patterns);
  const explicitMatchAll = Boolean(input.matchAll || input.match_all);
  if (
    !explicitMatchAll &&
    detectorIds.length === 0 &&
    attackTypes.length === 0 &&
    anomalyTypes.length === 0 &&
    actions.length === 0 &&
    routePatterns.length === 0 &&
    !input.scoreThreshold &&
    !input.confidenceThreshold
  ) {
    throw new Error("alert rule must define at least one criterion or explicitly match all");
  }

  return {
    firewallInstanceId: nullableId(input.firewallInstanceId || input.firewall_instance_id),
    name: boundedString(input.name, 160),
    description: nullableCleanString(input.description, 2000),
    status: enumValue(input.status || "active", ["active", "disabled", "deleted"], "alert rule status"),
    severityThreshold: enumValue(
      input.severityThreshold || input.severity_threshold || "high",
      SEVERITIES,
      "severity threshold",
    ),
    confidenceThreshold: nullableNumber(input.confidenceThreshold ?? input.confidence_threshold, 0, 1, "confidence threshold"),
    scoreThreshold: nullableNumber(input.scoreThreshold ?? input.score_threshold, 0, 100, "score threshold"),
    detectorIds,
    attackTypes,
    anomalyTypes,
    actions,
    routePatterns,
    aggregationWindowSeconds: boundedInteger(input.aggregationWindowSeconds ?? input.aggregation_window_seconds ?? 300, 30, 86400, "aggregation window"),
    thresholdCount: boundedInteger(input.thresholdCount ?? input.threshold_count ?? 1, 1, 1000, "threshold count"),
    cooldownSeconds: boundedInteger(input.cooldownSeconds ?? input.cooldown_seconds ?? 300, 0, 86400, "cooldown"),
    autoCreateIncident: Boolean(input.autoCreateIncident || input.auto_create_incident),
  };
}

export async function createAlertRule({ database = db(), organizationId, userId, input }) {
  const rule = normalizeAlertRule(input);
  if (rule.firewallInstanceId) {
    await validateAlertFirewallOwnership(database, organizationId, rule.firewallInstanceId);
  }

  const [created] = await database
    .insert(alertRules)
    .values({ ...rule, organizationId, createdByUserId: userId || null })
    .returning();

  await audit(database, {
    organizationId,
    userId,
    eventType: AUDIT_EVENT_TYPES.ALERT_RULE_CREATED,
    resourceType: "alert_rule",
    resourceId: created.id,
    metadata: { name: created.name, severityThreshold: created.severityThreshold },
  });
  return created;
}

export async function validateAlertFirewallOwnership(database, organizationId, firewallInstanceId) {
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

  if (!firewall) {
    throw new Error("firewall instance is not available for this organization");
  }

  return firewall;
}

export async function updateAlertRule({ database = db(), organizationId, userId, ruleId, input }) {
  const rule = normalizeAlertRule(input);
  if (rule.firewallInstanceId) {
    await validateAlertFirewallOwnership(database, organizationId, rule.firewallInstanceId);
  }

  const [updated] = await database
    .update(alertRules)
    .set({ ...rule, updatedAt: new Date(), deletedAt: rule.status === "deleted" ? new Date() : null })
    .where(and(eq(alertRules.id, ruleId), eq(alertRules.organizationId, organizationId)))
    .returning();

  if (!updated) throw new Error("alert rule not found");

  await audit(database, {
    organizationId,
    userId,
    eventType:
      updated.status === "disabled"
        ? AUDIT_EVENT_TYPES.ALERT_RULE_DISABLED
        : updated.status === "active"
          ? AUDIT_EVENT_TYPES.ALERT_RULE_ENABLED
          : AUDIT_EVENT_TYPES.ALERT_RULE_UPDATED,
    resourceType: "alert_rule",
    resourceId: updated.id,
    metadata: { status: updated.status },
  });
  return updated;
}

export async function listAlertRules({ database = db(), organizationId, filters = {} }) {
  const limit = boundedLimit(filters.limit);
  const predicates = [eq(alertRules.organizationId, organizationId), isNull(alertRules.deletedAt)];
  if (filters.status) predicates.push(eq(alertRules.status, enumValue(filters.status, ["active", "disabled", "deleted"], "rule status")));
  if (filters.firewallInstanceId) {
    await validateAlertFirewallOwnership(database, organizationId, filters.firewallInstanceId);
    predicates.push(eq(alertRules.firewallInstanceId, filters.firewallInstanceId));
  }

  const rows = await database
    .select()
    .from(alertRules)
    .where(and(...predicates))
    .orderBy(desc(alertRules.updatedAt))
    .limit(limit);
  return { items: rows, pageInfo: { limit, hasMore: false, nextCursor: null } };
}

export async function evaluateAlertRulesForEvent({ database = db(), event }) {
  const candidateRules = await database
    .select()
    .from(alertRules)
    .where(
      and(
        eq(alertRules.organizationId, event.organizationId),
        eq(alertRules.status, "active"),
        isNull(alertRules.deletedAt),
        or(isNull(alertRules.firewallInstanceId), eq(alertRules.firewallInstanceId, event.firewallInstanceId)),
      ),
    )
    .limit(250);

  const alertsCreated = [];
  for (const rule of candidateRules.filter(isAlertRuleRow)) {
    if (!ruleMatchesEvent(rule, event)) continue;
    if (await isSuppressed({ database, rule, event })) continue;

    const windowStart = new Date(new Date(event.occurredAt).getTime() - rule.aggregationWindowSeconds * 1000);
    const count = await matchingEventCount({ database, rule, event, windowStart });
    if (count < rule.thresholdCount) continue;

    const created = await upsertAlertForRule({ database, rule, event, eventCount: count });
    if (created) alertsCreated.push(created);
  }

  return alertsCreated;
}

function isAlertRuleRow(rule) {
  return Boolean(rule?.id && rule?.name && rule?.aggregationWindowSeconds && rule?.thresholdCount);
}

export function ruleMatchesEvent(rule, event) {
  if (SEVERITY_RANK[event.severity] < SEVERITY_RANK[rule.severityThreshold]) return false;
  if (rule.confidenceThreshold != null && Number(event.confidence || 0) < rule.confidenceThreshold) return false;
  if (rule.scoreThreshold != null && Number(event.score || 0) < rule.scoreThreshold) return false;
  if (rule.detectorIds?.length && !rule.detectorIds.includes(event.detectorId)) return false;
  if (rule.attackTypes?.length && !rule.attackTypes.includes(event.attackType)) return false;
  if (rule.anomalyTypes?.length && !rule.anomalyTypes.includes(event.anomalyType)) return false;
  if (rule.actions?.length && !rule.actions.includes(event.actionTaken)) return false;
  if (rule.routePatterns?.length && !routeMatches(rule.routePatterns, event.requestPath || event.apiRouteId || "")) return false;
  return true;
}

export function alertFingerprint({ rule, event }) {
  const route = normalizeRouteForDedupe(event.apiRouteId || event.requestPath);
  return crypto
    .createHash("sha256")
    .update(
      [
        event.organizationId,
        event.firewallInstanceId,
        rule.id,
        event.detectorId || "",
        event.attackType || "",
        event.anomalyType || "",
        event.sourceIp || "",
        route,
      ].join("|"),
    )
    .digest("hex");
}

export async function upsertAlertForRule({ database = db(), rule, event, eventCount }) {
  const fingerprint = alertFingerprint({ rule, event });
  const now = new Date();
  const route = event.apiRouteId || event.requestPath || null;
  const [existing] = await database
    .select()
    .from(alerts)
    .where(
      and(
        eq(alerts.organizationId, event.organizationId),
        eq(alerts.dedupeFingerprint, fingerprint),
        inArray(alerts.status, ["open", "acknowledged"]),
      ),
    )
    .limit(1);

  if (existing) {
    const [updated] = await database
      .update(alerts)
      .set({
        eventCount: sql`${alerts.eventCount} + ${Math.max(1, eventCount)}`,
        lastSeenAt: event.occurredAt,
        updatedAt: now,
        metadata: {
          ...(existing.metadata || {}),
          latestSecurityEventId: event.id,
          cooldownSeconds: rule.cooldownSeconds,
        },
      })
      .where(eq(alerts.id, existing.id))
      .returning();
    return updated;
  }

  const [created] = await database
    .insert(alerts)
    .values({
      organizationId: event.organizationId,
      firewallInstanceId: event.firewallInstanceId,
      alertRuleId: rule.id,
      dedupeFingerprint: fingerprint,
      severity: event.severity,
      title: `${event.severity.toUpperCase()} ${event.attackType} alert`,
      summary: `Rule "${rule.name}" matched ${eventCount} event(s) within ${rule.aggregationWindowSeconds} seconds.`,
      detectorId: event.detectorId,
      attackType: event.attackType,
      anomalyType: event.anomalyType,
      sourceIp: event.sourceIp,
      route,
      eventCount,
      firstSeenAt: event.occurredAt,
      lastSeenAt: event.occurredAt,
      metadata: {
        ruleName: rule.name,
        securityEventId: event.id,
        thresholdCount: rule.thresholdCount,
        aggregationWindowSeconds: rule.aggregationWindowSeconds,
        cooldownSeconds: rule.cooldownSeconds,
      },
    })
    .returning();

  if (rule.autoCreateIncident) {
    await createIncidentFromAlerts({
      database,
      organizationId: created.organizationId,
      userId: rule.createdByUserId,
      alertIds: [created.id],
      title: created.title,
      summary: created.summary,
    });
  }

  await createNotificationDeliveriesForAlert({ database, alert: created });
  return created;
}

export async function acknowledgeAlert({ database = db(), organizationId, userId, alertId, note }) {
  const [current] = await database
    .select()
    .from(alerts)
    .where(and(eq(alerts.id, alertId), eq(alerts.organizationId, organizationId)))
    .limit(1);
  if (!current) throw new Error("alert not found");
  if (current.status !== "open") throw new Error("only open alerts can be acknowledged");

  const [updated] = await database
    .update(alerts)
    .set({
      status: "acknowledged",
      acknowledgedAt: new Date(),
      acknowledgedByUserId: userId || null,
      metadata: { ...(current.metadata || {}), acknowledgeNote: nullableCleanString(note, 1000) },
      updatedAt: new Date(),
    })
    .where(eq(alerts.id, current.id))
    .returning();

  await audit(database, {
    organizationId,
    userId,
    eventType: AUDIT_EVENT_TYPES.ALERT_ACKNOWLEDGED,
    resourceType: "alert",
    resourceId: updated.id,
  });
  return updated;
}

export async function resolveAlert({ database = db(), organizationId, userId, alertId, note }) {
  const [current] = await database
    .select()
    .from(alerts)
    .where(and(eq(alerts.id, alertId), eq(alerts.organizationId, organizationId)))
    .limit(1);
  if (!current) throw new Error("alert not found");
  if (!["open", "acknowledged"].includes(current.status)) {
    throw new Error("only open or acknowledged alerts can be resolved");
  }

  const [updated] = await database
    .update(alerts)
    .set({
      status: "resolved",
      resolvedAt: new Date(),
      resolvedByUserId: userId || null,
      resolutionNote: nullableCleanString(note, 2000),
      updatedAt: new Date(),
    })
    .where(eq(alerts.id, current.id))
    .returning();

  await audit(database, {
    organizationId,
    userId,
    eventType: AUDIT_EVENT_TYPES.ALERT_RESOLVED,
    resourceType: "alert",
    resourceId: updated.id,
  });
  return updated;
}

export async function listAlerts({ database = db(), organizationId, filters = {} }) {
  const limit = boundedLimit(filters.limit);
  const predicates = [eq(alerts.organizationId, organizationId)];
  if (filters.status) predicates.push(eq(alerts.status, enumValue(filters.status, ALERT_STATUSES, "alert status")));
  if (filters.severity) predicates.push(eq(alerts.severity, enumValue(filters.severity, SEVERITIES, "alert severity")));
  if (filters.detectorId) predicates.push(eq(alerts.detectorId, token(filters.detectorId, 80)));
  if (filters.attackType) predicates.push(eq(alerts.attackType, token(filters.attackType, 80)));
  if (filters.sourceIp) predicates.push(eq(alerts.sourceIp, boundedString(filters.sourceIp, 45)));
  if (filters.route) predicates.push(ilike(alerts.route, `%${nullableCleanString(filters.route, 500)}%`));
  if (filters.alertRuleId) predicates.push(eq(alerts.alertRuleId, boundedString(filters.alertRuleId, 160)));
  if (filters.firewallInstanceId) {
    await validateAlertFirewallOwnership(database, organizationId, filters.firewallInstanceId);
    predicates.push(eq(alerts.firewallInstanceId, filters.firewallInstanceId));
  }

  const rows = await database
    .select()
    .from(alerts)
    .where(and(...predicates))
    .orderBy(desc(alerts.lastSeenAt), desc(alerts.createdAt))
    .limit(limit);
  return { items: rows, pageInfo: { limit, hasMore: false, nextCursor: null } };
}

export async function getAlertAnalytics({ database = db(), organizationId }) {
  const [summary] = await database
    .select({
      open: sql`sum(case when ${alerts.status} = 'open' then 1 else 0 end)`,
      acknowledged: sql`sum(case when ${alerts.status} = 'acknowledged' then 1 else 0 end)`,
      criticalOpen: sql`sum(case when ${alerts.status} = 'open' and ${alerts.severity} = 'critical' then 1 else 0 end)`,
      resolved24h: sql`sum(case when ${alerts.status} = 'resolved' and ${alerts.resolvedAt} >= now() - interval '24 hours' then 1 else 0 end)`,
    })
    .from(alerts)
    .where(eq(alerts.organizationId, organizationId));

  const [incidentSummary] = await database
    .select({
      active: sql`sum(case when ${incidents.status} <> 'resolved' then 1 else 0 end)`,
    })
    .from(incidents)
    .where(eq(incidents.organizationId, organizationId));

  return {
    totals: {
      open: numberValue(summary?.open),
      acknowledged: numberValue(summary?.acknowledged),
      criticalOpen: numberValue(summary?.criticalOpen),
      resolved24h: numberValue(summary?.resolved24h),
      activeIncidents: numberValue(incidentSummary?.active),
    },
  };
}

export async function createIncidentFromAlerts({
  database = db(),
  organizationId,
  userId,
  alertIds = [],
  title,
  summary,
}) {
  if (!alertIds.length) throw new Error("at least one alert is required");
  const selectedAlerts = await database
    .select()
    .from(alerts)
    .where(and(eq(alerts.organizationId, organizationId), inArray(alerts.id, alertIds.slice(0, 20))));
  if (selectedAlerts.length !== alertIds.length) throw new Error("one or more alerts are unavailable");

  const highest = selectedAlerts
    .map((alert) => alert.severity)
    .sort((a, b) => SEVERITY_RANK[b] - SEVERITY_RANK[a])[0];
  const firstSeenAt = new Date(Math.min(...selectedAlerts.map((alert) => new Date(alert.firstSeenAt).getTime())));
  const lastSeenAt = new Date(Math.max(...selectedAlerts.map((alert) => new Date(alert.lastSeenAt).getTime())));
  const firewallIds = Array.from(new Set(selectedAlerts.map((alert) => alert.firewallInstanceId)));

  const [created] = await database
    .insert(incidents)
    .values({
      organizationId,
      firewallInstanceId: firewallIds.length === 1 ? firewallIds[0] : null,
      title: boundedString(title || selectedAlerts[0].title, 240),
      summary: nullableCleanString(summary || `Incident created from ${selectedAlerts.length} alert(s).`, 2000),
      severity: highest,
      createdByUserId: userId || null,
      firstSeenAt,
      lastSeenAt,
      metadata: { alertCount: selectedAlerts.length },
    })
    .returning();

  await database
    .insert(incidentAlerts)
    .values(selectedAlerts.map((alert) => ({ incidentId: created.id, alertId: alert.id, linkedByUserId: userId || null })))
    .onConflictDoNothing();

  await database
    .update(alerts)
    .set({ incidentId: created.id, updatedAt: new Date() })
    .where(inArray(alerts.id, selectedAlerts.map((alert) => alert.id)));

  await audit(database, {
    organizationId,
    userId,
    eventType: AUDIT_EVENT_TYPES.INCIDENT_CREATED,
    resourceType: "incident",
    resourceId: created.id,
    metadata: { alertCount: selectedAlerts.length },
  });

  return created;
}

export async function listIncidents({ database = db(), organizationId, filters = {} }) {
  const predicates = [eq(incidents.organizationId, organizationId)];
  if (filters.status) predicates.push(eq(incidents.status, enumValue(filters.status, INCIDENT_STATUSES, "incident status")));
  if (filters.severity) predicates.push(eq(incidents.severity, enumValue(filters.severity, SEVERITIES, "incident severity")));
  const rows = await database
    .select()
    .from(incidents)
    .where(and(...predicates))
    .orderBy(desc(incidents.lastSeenAt))
    .limit(boundedLimit(filters.limit));
  return { items: rows, pageInfo: { limit: boundedLimit(filters.limit), hasMore: false, nextCursor: null } };
}

export async function updateIncident({ database = db(), organizationId, userId, incidentId, input = {} }) {
  const status = input.status ? enumValue(input.status, INCIDENT_STATUSES, "incident status") : undefined;
  const patch = { updatedAt: new Date() };
  if (status) {
    patch.status = status;
    if (status === "investigating") patch.acknowledgedAt = new Date();
    if (status === "resolved") {
      patch.resolvedAt = new Date();
      patch.resolution = nullableCleanString(input.resolution, 2000) || "Resolved";
    }
  }
  if (input.assignedToUserId !== undefined) patch.assignedToUserId = nullableId(input.assignedToUserId);

  const [updated] = await database
    .update(incidents)
    .set(patch)
    .where(and(eq(incidents.id, incidentId), eq(incidents.organizationId, organizationId)))
    .returning();
  if (!updated) throw new Error("incident not found");

  await audit(database, {
    organizationId,
    userId,
    eventType: status === "resolved" ? AUDIT_EVENT_TYPES.INCIDENT_RESOLVED : AUDIT_EVENT_TYPES.INCIDENT_ASSIGNED,
    resourceType: "incident",
    resourceId: updated.id,
    metadata: { status: updated.status },
  });
  return updated;
}

export async function createNotificationChannel({ database = db(), organizationId, userId, input = {} }) {
  const type = enumValue(input.type || "webhook", ["webhook", "email", "siem"], "channel type");
  const configuration = normalizeChannelConfiguration(type, input.configuration || input);
  const secretReference = input.signingSecret
    ? sealIntegrationSecret(input.signingSecret)
    : {};
  const [created] = await database
    .insert(notificationChannels)
    .values({
      organizationId,
      type,
      name: boundedString(input.name, 160),
      status: enumValue(input.status || "active", ["active", "disabled", "deleted"], "channel status"),
      configuration,
      secretReference,
      selectedEvents: tokenList(input.selectedEvents || ["alert.created", "alert.updated"], 80),
      createdByUserId: userId || null,
    })
    .returning();

  await audit(database, {
    organizationId,
    userId,
    eventType: AUDIT_EVENT_TYPES.NOTIFICATION_CHANNEL_CREATED,
    resourceType: "notification_channel",
    resourceId: created.id,
    metadata: { type: created.type, name: created.name },
  });
  return presentChannel(created);
}

export async function listNotificationChannels({ database = db(), organizationId }) {
  const rows = await database
    .select()
    .from(notificationChannels)
    .where(and(eq(notificationChannels.organizationId, organizationId), isNull(notificationChannels.deletedAt)))
    .orderBy(desc(notificationChannels.updatedAt))
    .limit(100);
  return { items: rows.map(presentChannel) };
}

export async function createNotificationDeliveriesForAlert({ database = db(), alert }) {
  const channels = await database
    .select()
    .from(notificationChannels)
    .where(
      and(
        eq(notificationChannels.organizationId, alert.organizationId),
        eq(notificationChannels.status, "active"),
        isNull(notificationChannels.deletedAt),
      ),
    )
    .limit(25);

  if (!channels.length) return [];
  const rows = channels
    .filter((channel) => !channel.selectedEvents?.length || channel.selectedEvents.includes("alert.created"))
    .map((channel) => {
      const deliveryId = crypto.randomUUID();
      return {
        id: deliveryId,
        organizationId: alert.organizationId,
        channelId: channel.id,
        alertId: alert.id,
        eventType: "alert.created",
        status: "pending",
        nextAttemptAt: new Date(),
        payload: safeWebhookPayload({
          deliveryId,
          eventType: "alert.created",
          organizationId: alert.organizationId,
          alert,
        }),
      };
    });

  if (!rows.length) return [];
  return database.insert(notificationDeliveries).values(rows).returning();
}

async function matchingEventCount({ database, rule, event, windowStart }) {
  const windowEnd = new Date(new Date(event.occurredAt).getTime() + 1);
  const predicates = [
    eq(securityEvents.organizationId, event.organizationId),
    eq(securityEvents.firewallInstanceId, event.firewallInstanceId),
    gte(securityEvents.occurredAt, windowStart),
    lte(securityEvents.occurredAt, windowEnd),
  ];

  if (rule.detectorIds?.length) predicates.push(inArray(securityEvents.detectorId, rule.detectorIds));
  if (rule.attackTypes?.length) predicates.push(inArray(securityEvents.attackType, rule.attackTypes));
  if (rule.anomalyTypes?.length) predicates.push(inArray(securityEvents.anomalyType, rule.anomalyTypes));
  if (event.sourceIp) predicates.push(eq(securityEvents.sourceIp, event.sourceIp));

  const [row] = await database.select({ count: sql`count(*)` }).from(securityEvents).where(and(...predicates));
  return numberValue(row?.count);
}

async function isSuppressed({ database, rule, event }) {
  const rows = await database
    .select()
    .from(alertSuppressions)
    .where(
      and(
        eq(alertSuppressions.organizationId, event.organizationId),
        eq(alertSuppressions.status, "active"),
        or(isNull(alertSuppressions.expiresAt), gte(alertSuppressions.expiresAt, new Date())),
      ),
    )
    .limit(100);

  return rows.some((suppression) => {
    if (suppression.firewallInstanceId && suppression.firewallInstanceId !== event.firewallInstanceId) return false;
    if (suppression.alertRuleId && suppression.alertRuleId !== rule.id) return false;
    if (suppression.scopeType === "rule") return suppression.alertRuleId === rule.id;
    if (suppression.scopeType === "detector") return suppression.scopeValue === event.detectorId;
    if (suppression.scopeType === "firewall") return suppression.firewallInstanceId === event.firewallInstanceId;
    if (suppression.scopeType === "route") return routeMatches([suppression.scopeValue], event.requestPath || event.apiRouteId || "");
    if (suppression.scopeType === "source_ip") return suppression.scopeValue === event.sourceIp;
    return false;
  });
}

function normalizeChannelConfiguration(type, input) {
  if (type === "webhook") {
    return {
      url: validateWebhookUrl(input.url),
      allowHttp: false,
    };
  }

  return {
    status: "prepared",
    provider: nullableCleanString(input.provider, 80) || null,
  };
}

function presentChannel(channel) {
  return {
    ...channel,
    secretReference: channel.secretReference?.format
      ? { format: channel.secretReference.format, keyVersion: channel.secretReference.keyVersion }
      : {},
  };
}

function routeMatches(patterns, route) {
  return patterns.some((pattern) => {
    const regex = new RegExp(`^${pattern.split("*").map(escapeRegex).join(".*")}$`);
    return regex.test(route);
  });
}

function normalizeRouteForDedupe(route) {
  return String(route || "").split("?")[0].slice(0, 256);
}

async function audit(database, event) {
  await createAuditEvent({
    database,
    eventType: event.eventType,
    action: event.eventType,
    result: AUDIT_RESULTS.SUCCESS,
    severity: AUDIT_SEVERITIES.INFO,
    organizationId: event.organizationId,
    userId: event.userId,
    resourceType: event.resourceType,
    resourceId: event.resourceId,
    metadata: event.metadata || {},
  });
}

function routePatternList(value) {
  const items = stringList(value, 20, 300);
  items.forEach((pattern) => {
    if (!/^\/[A-Za-z0-9_./:{}?&=%*-]*$/.test(pattern)) {
      throw new Error("route selector syntax is invalid");
    }
  });
  return items;
}

function tokenList(value, maxLength) {
  return stringList(value, 50, maxLength).map((item) => token(item, maxLength));
}

function stringList(value, maxItems, maxLength) {
  if (value == null || value === "") return [];
  const items = Array.isArray(value) ? value : String(value).split(",");
  return Array.from(
    new Set(items.map((item) => String(item || "").trim()).filter(Boolean)),
  ).slice(0, maxItems).map((item) => item.slice(0, maxLength));
}

function token(value, maxLength) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!/^[a-z0-9_.:-]+$/.test(normalized)) throw new Error("token value is invalid");
  return normalized.slice(0, maxLength);
}

function nullableId(value) {
  return value ? boundedString(value, 160) : null;
}

function enumValue(value, allowed, label) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!allowed.includes(normalized)) throw new Error(`${label} is invalid`);
  return normalized;
}

function boundedString(value, maxLength) {
  const text = String(value || "").trim();
  if (!text) throw new Error("value is required");
  return text.slice(0, maxLength);
}

function nullableCleanString(value, maxLength) {
  if (!value) return null;
  return String(value).replace(/[^\x20-\x7E]/g, "").trim().slice(0, maxLength) || null;
}

function nullableNumber(value, min, max, label) {
  if (value == null || value === "") return null;
  const number = Number(value);
  if (!Number.isFinite(number) || number < min || number > max) throw new Error(`${label} is invalid`);
  return number;
}

function boundedInteger(value, min, max, label) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < min || number > max) throw new Error(`${label} is invalid`);
  return number;
}

function boundedLimit(value) {
  const limit = Number(value || DEFAULT_LIMIT);
  return Number.isFinite(limit) && limit > 0 ? Math.min(Math.trunc(limit), MAX_LIMIT) : DEFAULT_LIMIT;
}

function numberValue(value) {
  return Number(value || 0);
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
