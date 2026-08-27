import "server-only";

import { and, count, desc, eq, inArray, isNull, lte, or, sql } from "drizzle-orm";
import { db } from "../../db/client.js";
import {
  aiAnalysisReports,
  alerts,
  complianceReports,
  customerContacts,
  delegatedAccessGrants,
  firewallInstances,
  incidents,
  organizationHierarchy,
  organizations,
  securityEvents,
  tenantSettings,
  usageRecords,
} from "../../db/schema.js";
import {
  AUDIT_EVENT_TYPES,
  AUDIT_RESULTS,
  AUDIT_SEVERITIES,
  createAuditEvent,
} from "../audit/index.js";

export const ENTERPRISE_RELATIONSHIP_TYPES = Object.freeze({
  MSSP_CUSTOMER: "mssp_customer",
  ENTERPRISE_CHILD: "enterprise_child",
  BUSINESS_UNIT: "business_unit",
  SUBSIDIARY: "subsidiary",
});

export const DELEGATED_ACCESS_LEVELS = Object.freeze({
  VIEWER: "viewer",
  ANALYST: "analyst",
  RESPONDER: "responder",
  ADMIN: "admin",
  AUDITOR: "auditor",
});

export const TENANT_PLANS = Object.freeze({
  STARTER: "starter",
  PROFESSIONAL: "professional",
  ENTERPRISE: "enterprise",
  MSSP: "mssp",
});

const RELATIONSHIP_TYPES = Object.values(ENTERPRISE_RELATIONSHIP_TYPES);
const ACCESS_LEVELS = Object.values(DELEGATED_ACCESS_LEVELS);
const PLANS = Object.values(TENANT_PLANS);
const TENANT_LIFECYCLE = ["provisioning", "active", "suspended", "pending_deletion", "deleted", "archived"];
const CONTACT_TYPES = ["security", "billing", "technical", "executive", "incident"];
const COMPLIANCE_TYPES = ["security_posture", "incident_summary", "compliance_summary", "executive", "customer_security"];
const USAGE_METRICS = [
  "api_requests",
  "security_events",
  "alerts",
  "incidents",
  "firewall_instances",
  "api_routes",
  "notification_deliveries",
  "ai_investigations",
  "customer_tenants",
  "analyst_seats",
];

export async function getEnterpriseOverview({ database = db(), organizationId } = {}) {
  const [customers, activeDelegations, activeIncidents, criticalAlerts, firewalls, reports, usage] =
    await Promise.all([
      scalarCount(database, organizationHierarchy, and(eq(organizationHierarchy.parentOrganizationId, organizationId), eq(organizationHierarchy.status, "active"))),
      scalarCount(database, delegatedAccessGrants, and(eq(delegatedAccessGrants.providerOrganizationId, organizationId), eq(delegatedAccessGrants.status, "active"))),
      scalarCount(database, incidents, and(eq(incidents.organizationId, organizationId), or(eq(incidents.status, "open"), eq(incidents.status, "investigating")))),
      scalarCount(database, alerts, and(eq(alerts.organizationId, organizationId), eq(alerts.severity, "critical"), or(eq(alerts.status, "open"), eq(alerts.status, "acknowledged")))),
      scalarCount(database, firewallInstances, and(eq(firewallInstances.organizationId, organizationId), eq(firewallInstances.status, "active"), isNull(firewallInstances.deletedAt))),
      scalarCount(database, complianceReports, eq(complianceReports.organizationId, organizationId)),
      listUsage({ database, organizationId, filters: { limit: 100 } }),
    ]);

  return {
    summary: {
      managedCustomers: customers,
      activeDelegations,
      activeIncidents,
      criticalAlerts,
      activeFirewalls: firewalls,
      complianceReports: reports,
    },
    usage: usage.summary,
    governance: {
      delegatedAccessRequiresApproval: true,
      hiddenGlobalAccessAllowed: false,
      aiExecutionAllowed: false,
    },
  };
}

export async function listOrganizationHierarchy({ database = db(), organizationId, filters = {} } = {}) {
  const limit = boundedLimit(filters.limit, 100, 200);
  const rows = await database
    .select()
    .from(organizationHierarchy)
    .where(
      or(
        eq(organizationHierarchy.parentOrganizationId, organizationId),
        eq(organizationHierarchy.childOrganizationId, organizationId),
      ),
    )
    .orderBy(desc(organizationHierarchy.updatedAt))
    .limit(limit);

  const orgIds = [...new Set(rows.flatMap((row) => [row.parentOrganizationId, row.childOrganizationId]))];
  const orgRows = orgIds.length
    ? await database
        .select({ id: organizations.id, name: organizations.name, slug: organizations.slug, status: organizations.status })
        .from(organizations)
        .where(inArray(organizations.id, orgIds))
    : [];
  const orgMap = new Map(orgRows.map((row) => [row.id, row]));

  return {
    items: rows.map((row) => ({
      ...row,
      parentOrganization: orgMap.get(row.parentOrganizationId) || null,
      childOrganization: orgMap.get(row.childOrganizationId) || null,
      currentScopeRole: row.parentOrganizationId === organizationId ? "parent" : "child",
    })),
  };
}

export async function createOrganizationHierarchy({
  database = db(),
  organizationId,
  userId,
  input = {},
  auditContext,
} = {}) {
  const childOrganizationId = requiredString(input.childOrganizationId, "child organization");
  if (childOrganizationId === organizationId) throw new Error("child organization cannot match parent organization");
  await requireOrganizationExists(database, childOrganizationId);

  const relationshipType = enumValue(input.relationshipType || ENTERPRISE_RELATIONSHIP_TYPES.MSSP_CUSTOMER, RELATIONSHIP_TYPES, "relationship type");
  const status = enumValue(input.status || "active", ["active", "pending", "suspended"], "relationship status");
  const expiresAt = optionalDate(input.expiresAt);

  const [row] = await database
    .insert(organizationHierarchy)
    .values({
      parentOrganizationId: organizationId,
      childOrganizationId,
      relationshipType,
      status,
      delegationMode: enumValue(input.delegationMode || "explicit", ["explicit", "approval_required", "contracted"], "delegation mode"),
      createdByUserId: userId,
      approvedByUserId: status === "active" ? userId : null,
      approvedAt: status === "active" ? new Date() : null,
      expiresAt,
      metadata: safeMetadata(input.metadata),
    })
    .onConflictDoUpdate({
      target: [organizationHierarchy.parentOrganizationId, organizationHierarchy.childOrganizationId],
      set: {
        relationshipType,
        status,
        delegationMode: enumValue(input.delegationMode || "explicit", ["explicit", "approval_required", "contracted"], "delegation mode"),
        approvedByUserId: status === "active" ? userId : null,
        approvedAt: status === "active" ? new Date() : null,
        expiresAt,
        updatedAt: new Date(),
      },
    })
    .returning();

  await auditEnterprise({
    database,
    organizationId,
    userId,
    eventType: AUDIT_EVENT_TYPES.ENTERPRISE_HIERARCHY_UPDATED,
    action: "enterprise.hierarchy.upsert",
    resourceType: "organization_hierarchy",
    resourceId: row.id,
    requestId: auditContext?.requestId,
    metadata: { childOrganizationId, relationshipType, status },
  });

  return row;
}

export async function listCustomerTenants({ database = db(), organizationId, filters = {} } = {}) {
  const limit = boundedLimit(filters.limit, 100, 200);
  const relations = await database
    .select({
      hierarchyId: organizationHierarchy.id,
      relationshipType: organizationHierarchy.relationshipType,
      relationshipStatus: organizationHierarchy.status,
      customerId: organizations.id,
      name: organizations.name,
      slug: organizations.slug,
      status: organizations.status,
      createdAt: organizations.createdAt,
    })
    .from(organizationHierarchy)
    .innerJoin(organizations, eq(organizations.id, organizationHierarchy.childOrganizationId))
    .where(and(eq(organizationHierarchy.parentOrganizationId, organizationId), isNull(organizations.deletedAt)))
    .orderBy(desc(organizationHierarchy.updatedAt))
    .limit(limit);

  const customerIds = relations.map((row) => row.customerId);
  const [settingsRows, incidentRows, alertRows, firewallRows] = customerIds.length
    ? await Promise.all([
        database.select().from(tenantSettings).where(inArray(tenantSettings.organizationId, customerIds)),
        groupedCount(database, incidents.organizationId, incidents, inArray(incidents.organizationId, customerIds)),
        groupedCount(database, alerts.organizationId, alerts, inArray(alerts.organizationId, customerIds)),
        groupedCount(database, firewallInstances.organizationId, firewallInstances, inArray(firewallInstances.organizationId, customerIds)),
      ])
    : [[], [], [], []];

  const settingsMap = new Map(settingsRows.map((row) => [row.organizationId, row]));
  const incidentMap = countMap(incidentRows);
  const alertMap = countMap(alertRows);
  const firewallMap = countMap(firewallRows);

  return {
    items: relations.map((row) => ({
      ...row,
      tenantSettings: settingsMap.get(row.customerId) || null,
      metrics: {
        incidents: incidentMap.get(row.customerId) || 0,
        alerts: alertMap.get(row.customerId) || 0,
        firewalls: firewallMap.get(row.customerId) || 0,
      },
    })),
  };
}

export async function createCustomerTenant({
  database = db(),
  organizationId,
  userId,
  input = {},
  auditContext,
} = {}) {
  const name = safeString(input.name, 255);
  const slug = normalizeSlug(input.slug || name);
  if (!name || !slug) throw new Error("customer name and slug are required");

  return database.transaction(async (tx) => {
    const [customer] = await tx
      .insert(organizations)
      .values({ name, slug, status: enumValue(input.status || "active", ["active", "disabled"], "customer status") })
      .returning();

    const [settings] = await tx
      .insert(tenantSettings)
      .values({
        organizationId: customer.id,
        planKey: enumValue(input.planKey || TENANT_PLANS.PROFESSIONAL, PLANS, "plan"),
        lifecycleStatus: enumValue(input.lifecycleStatus || "provisioning", TENANT_LIFECYCLE, "lifecycle status"),
        dataResidency: safeString(input.dataResidency || "global", 80),
        retentionDays: boundedNumber(input.retentionDays, 7, 2555, 90),
        msspEnabled: true,
        maxFirewalls: boundedNumber(input.maxFirewalls, 0, 100000, 5),
        maxUsers: boundedNumber(input.maxUsers, 0, 100000, 25),
        features: safeMetadata(input.features),
        metadata: { createdBy: "enterprise_foundation" },
      })
      .returning();

    const [relation] = await tx
      .insert(organizationHierarchy)
      .values({
        parentOrganizationId: organizationId,
        childOrganizationId: customer.id,
        relationshipType: enumValue(input.relationshipType || ENTERPRISE_RELATIONSHIP_TYPES.MSSP_CUSTOMER, RELATIONSHIP_TYPES, "relationship type"),
        status: "active",
        delegationMode: "explicit",
        createdByUserId: userId,
        approvedByUserId: userId,
        approvedAt: new Date(),
        metadata: { onboarding: "phase_8_9" },
      })
      .returning();

    let contact = null;
    if (input.contact?.email && input.contact?.name) {
      [contact] = await tx
        .insert(customerContacts)
        .values({
          organizationId: customer.id,
          parentOrganizationId: organizationId,
          contactType: enumValue(input.contact.contactType || "security", CONTACT_TYPES, "contact type"),
          name: safeString(input.contact.name, 160),
          email: safeEmail(input.contact.email),
          phone: nullableString(input.contact.phone, 64),
          escalationPriority: boundedNumber(input.contact.escalationPriority, 1, 5, 1),
          metadata: safeMetadata(input.contact.metadata),
        })
        .returning();
    }

    await auditEnterprise({
      database: tx,
      organizationId,
      userId,
      eventType: AUDIT_EVENT_TYPES.ENTERPRISE_CUSTOMER_CREATED,
      action: "enterprise.customer.create",
      resourceType: "organization",
      resourceId: customer.id,
      requestId: auditContext?.requestId,
      metadata: { customerOrganizationId: customer.id, planKey: settings.planKey },
    });

    return { customer, settings, relation, contact };
  });
}

export async function listDelegatedAccess({ database = db(), organizationId, filters = {} } = {}) {
  const predicates = [
    or(
      eq(delegatedAccessGrants.providerOrganizationId, organizationId),
      eq(delegatedAccessGrants.customerOrganizationId, organizationId),
    ),
  ];
  if (filters.status) predicates.push(eq(delegatedAccessGrants.status, safeString(filters.status, 32)));

  const rows = await database
    .select()
    .from(delegatedAccessGrants)
    .where(and(...predicates))
    .orderBy(desc(delegatedAccessGrants.updatedAt))
    .limit(boundedLimit(filters.limit, 100, 200));

  return {
    items: rows.map((row) => ({
      ...row,
      effective: isDelegatedAccessActive(row),
    })),
  };
}

export async function createDelegatedAccess({
  database = db(),
  organizationId,
  userId,
  input = {},
  auditContext,
} = {}) {
  const customerOrganizationId = requiredString(input.customerOrganizationId, "customer organization");
  await requireChildTenant(database, organizationId, customerOrganizationId);

  const accessLevel = enumValue(input.accessLevel || DELEGATED_ACCESS_LEVELS.ANALYST, ACCESS_LEVELS, "access level");
  const permissions = normalizeDelegatedPermissions(input.permissions, accessLevel);
  const status = enumValue(input.status || "pending", ["active", "pending", "suspended"], "delegated access status");
  const expiresAt = optionalDate(input.expiresAt) || defaultExpiration();

  const [row] = await database
    .insert(delegatedAccessGrants)
    .values({
      providerOrganizationId: organizationId,
      customerOrganizationId,
      userId: nullableString(input.userId, 80),
      accessLevel,
      status,
      permissions,
      approvalState: status === "active" ? "approved" : "pending_customer_approval",
      justification: nullableString(input.justification, 2000),
      expiresAt,
      approvedByUserId: status === "active" ? userId : null,
      metadata: safeMetadata(input.metadata),
    })
    .returning();

  await auditEnterprise({
    database,
    organizationId,
    userId,
    eventType: AUDIT_EVENT_TYPES.DELEGATED_ACCESS_GRANTED,
    action: "enterprise.delegated_access.create",
    resourceType: "delegated_access_grant",
    resourceId: row.id,
    requestId: auditContext?.requestId,
    metadata: { customerOrganizationId, accessLevel, status, expiresAt: expiresAt.toISOString() },
  });

  return row;
}

export function isDelegatedAccessActive(row, now = new Date()) {
  if (!row || row.status !== "active" || row.approvalState !== "approved") return false;
  if (row.expiresAt && new Date(row.expiresAt) <= now) return false;
  return true;
}

export async function listComplianceReports({ database = db(), organizationId, filters = {} } = {}) {
  const targetOrganizationId = await resolveTenantScope(database, organizationId, filters.organizationId);
  const predicates = [eq(complianceReports.organizationId, targetOrganizationId)];
  if (filters.reportType) predicates.push(eq(complianceReports.reportType, safeString(filters.reportType, 48)));
  if (filters.status) predicates.push(eq(complianceReports.status, safeString(filters.status, 32)));

  const rows = await database
    .select()
    .from(complianceReports)
    .where(and(...predicates))
    .orderBy(desc(complianceReports.periodEnd))
    .limit(boundedLimit(filters.limit, 100, 200));

  return { items: rows, organizationId: targetOrganizationId };
}

export async function createComplianceReport({
  database = db(),
  organizationId,
  userId,
  input = {},
  auditContext,
} = {}) {
  const targetOrganizationId = await resolveTenantScope(database, organizationId, input.organizationId);
  const periodStart = optionalDate(input.periodStart) || daysAgo(30);
  const periodEnd = optionalDate(input.periodEnd) || new Date();
  if (periodEnd < periodStart) throw new Error("report period is invalid");

  const reportType = enumValue(input.reportType || "compliance_summary", COMPLIANCE_TYPES, "report type");
  const framework = safeString(input.framework || "nist_csf", 80);
  const [eventCount, incidentCount, reportCount] = await Promise.all([
    scalarCount(database, securityEvents, and(eq(securityEvents.organizationId, targetOrganizationId), lte(securityEvents.occurredAt, periodEnd))),
    scalarCount(database, incidents, eq(incidents.organizationId, targetOrganizationId)),
    scalarCount(database, aiAnalysisReports, eq(aiAnalysisReports.organizationId, targetOrganizationId)),
  ]);

  const [row] = await database
    .insert(complianceReports)
    .values({
      organizationId: targetOrganizationId,
      requestedByUserId: userId,
      reportType,
      framework,
      status: enumValue(input.status || "draft", ["draft", "generated", "review_required"], "report status"),
      title: safeString(input.title || `${framework.toUpperCase()} ${reportType.replaceAll("_", " ")} report`, 240),
      periodStart,
      periodEnd,
      summary:
        safeString(input.summary, 4000) ||
        `Foundation report covering ${eventCount} security events, ${incidentCount} incidents, and ${reportCount} AI reports.`,
      evidenceRefs: normalizeEvidenceRefs(input.evidenceRefs, { eventCount, incidentCount, reportCount }),
      controlMappings: Array.isArray(input.controlMappings)
        ? input.controlMappings.slice(0, 50).map((item) => safeMetadata(item))
        : defaultControlMappings(framework),
      generatedAiReportId: nullableString(input.generatedAiReportId, 80),
      metadata: safeMetadata(input.metadata),
    })
    .returning();

  await auditEnterprise({
    database,
    organizationId: targetOrganizationId,
    userId,
    eventType: AUDIT_EVENT_TYPES.COMPLIANCE_REPORT_CREATED,
    action: "enterprise.compliance_report.create",
    resourceType: "compliance_report",
    resourceId: row.id,
    requestId: auditContext?.requestId,
    metadata: { reportType, framework, parentOrganizationId: organizationId === targetOrganizationId ? null : organizationId },
  });

  return row;
}

export async function listUsage({ database = db(), organizationId, filters = {} } = {}) {
  const targetOrganizationId = await resolveTenantScope(database, organizationId, filters.organizationId);
  const predicates = [eq(usageRecords.organizationId, targetOrganizationId)];
  if (filters.metricType) predicates.push(eq(usageRecords.metricType, safeString(filters.metricType, 64)));

  const rows = await database
    .select()
    .from(usageRecords)
    .where(and(...predicates))
    .orderBy(desc(usageRecords.periodEnd))
    .limit(boundedLimit(filters.limit, 100, 500));

  const summary = rows.reduce((acc, row) => {
    acc.totalQuantity += Number(row.quantity || 0);
    acc.byMetric[row.metricType] = (acc.byMetric[row.metricType] || 0) + Number(row.quantity || 0);
    return acc;
  }, { totalQuantity: 0, byMetric: {} });

  return { items: rows, summary, organizationId: targetOrganizationId };
}

export async function recordUsage({
  database = db(),
  organizationId,
  userId,
  input = {},
  auditContext,
} = {}) {
  const targetOrganizationId = await resolveTenantScope(database, organizationId, input.organizationId);
  const metricType = enumValue(input.metricType || "security_events", USAGE_METRICS, "usage metric");
  const periodStart = optionalDate(input.periodStart) || daysAgo(30);
  const periodEnd = optionalDate(input.periodEnd) || new Date();
  if (periodEnd < periodStart) throw new Error("usage period is invalid");

  const [row] = await database
    .insert(usageRecords)
    .values({
      organizationId: targetOrganizationId,
      metricType,
      quantity: boundedNumber(input.quantity, 0, 1_000_000_000, 0),
      periodStart,
      periodEnd,
      source: safeString(input.source || "manual_validation", 80),
      metadata: safeMetadata(input.metadata),
    })
    .returning();

  await auditEnterprise({
    database,
    organizationId: targetOrganizationId,
    userId,
    eventType: AUDIT_EVENT_TYPES.USAGE_RECORD_CREATED,
    action: "enterprise.usage.record",
    resourceType: "usage_record",
    resourceId: row.id,
    requestId: auditContext?.requestId,
    metadata: { metricType, quantity: row.quantity, parentOrganizationId: organizationId === targetOrganizationId ? null : organizationId },
  });

  return row;
}

async function resolveTenantScope(database, organizationId, requestedOrganizationId) {
  if (!requestedOrganizationId || requestedOrganizationId === organizationId) return organizationId;
  await requireChildTenant(database, organizationId, requestedOrganizationId);
  return requestedOrganizationId;
}

async function requireChildTenant(database, parentOrganizationId, childOrganizationId) {
  const [row] = await database
    .select({ id: organizationHierarchy.id })
    .from(organizationHierarchy)
    .where(
      and(
        eq(organizationHierarchy.parentOrganizationId, parentOrganizationId),
        eq(organizationHierarchy.childOrganizationId, childOrganizationId),
        eq(organizationHierarchy.status, "active"),
      ),
    )
    .limit(1);
  if (!row) throw new Error("Forbidden tenant scope");
  return row;
}

async function requireOrganizationExists(database, organizationId) {
  const [row] = await database
    .select({ id: organizations.id })
    .from(organizations)
    .where(and(eq(organizations.id, organizationId), isNull(organizations.deletedAt)))
    .limit(1);
  if (!row) throw new Error("organization not found");
  return row;
}

async function scalarCount(database, table, where) {
  const query = database.select({ value: count() }).from(table);
  const [row] = await (where ? query.where(where) : query);
  return Number(row?.value || 0);
}

async function groupedCount(database, groupColumn, table, where) {
  return database
    .select({ organizationId: groupColumn, value: count() })
    .from(table)
    .where(where)
    .groupBy(groupColumn);
}

function countMap(rows) {
  return new Map(rows.map((row) => [row.organizationId, Number(row.value || 0)]));
}

function normalizeDelegatedPermissions(value, accessLevel) {
  if (Array.isArray(value) && value.length > 0) {
    return value.map((item) => safeString(item, 120)).filter(Boolean).slice(0, 100);
  }
  const defaults = {
    viewer: ["events.read", "metrics.read", "incidents.read"],
    analyst: ["events.read", "metrics.read", "alerts.read", "incidents.read", "ai.analyze"],
    responder: ["incidents.manage", "response_actions.manage", "automation_runs.read"],
    admin: ["enterprise.read", "tenant.manage", "delegated_access.manage", "policy.update"],
    auditor: ["audits.read", "compliance_reports.read", "ai.reports.read"],
  };
  return defaults[accessLevel] || defaults.viewer;
}

function normalizeEvidenceRefs(value, counts) {
  if (Array.isArray(value)) return value.slice(0, 100).map((item) => safeMetadata(item));
  return [
    { type: "security_events", count: counts.eventCount },
    { type: "incidents", count: counts.incidentCount },
    { type: "ai_reports", count: counts.reportCount },
  ];
}

function defaultControlMappings(framework) {
  return [
    { framework, control: "identify", source: "api_inventory" },
    { framework, control: "detect", source: "security_events" },
    { framework, control: "respond", source: "incidents_soar" },
  ];
}

async function auditEnterprise({
  database,
  organizationId,
  userId,
  eventType,
  action,
  resourceType,
  resourceId,
  requestId,
  metadata,
}) {
  await createAuditEvent({
    database,
    eventType,
    action,
    result: AUDIT_RESULTS.SUCCESS,
    severity: AUDIT_SEVERITIES.INFO,
    organizationId,
    userId,
    resourceType,
    resourceId,
    requestId,
    metadata,
  });
}

function boundedLimit(value, fallback, max) {
  const number = Number(value || fallback);
  if (!Number.isFinite(number)) return fallback;
  return Math.min(Math.max(Math.trunc(number), 1), max);
}

function boundedNumber(value, min, max, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  const number = Number(value);
  if (!Number.isFinite(number)) throw new Error("numeric value is invalid");
  return Math.min(Math.max(Math.trunc(number), min), max);
}

function enumValue(value, allowed, label) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!allowed.includes(normalized)) throw new Error(`${label} is invalid`);
  return normalized;
}

function optionalDate(value) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error("date is invalid");
  return date;
}

function defaultExpiration() {
  const date = new Date();
  date.setDate(date.getDate() + 30);
  return date;
}

function daysAgo(days) {
  const date = new Date();
  date.setDate(date.getDate() - days);
  return date;
}

function requiredString(value, label) {
  const text = safeString(value, 160);
  if (!text) throw new Error(`${label} is required`);
  return text;
}

function safeString(value, maxLength) {
  return String(value || "").replace(/[^\x20-\x7E]/g, "").trim().slice(0, maxLength);
}

function nullableString(value, maxLength) {
  const text = safeString(value, maxLength);
  return text || null;
}

function safeEmail(value) {
  const email = safeString(value, 320).toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new Error("contact email is invalid");
  return email;
}

function normalizeSlug(value) {
  return (
    String(value || "")
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 120) || null
  );
}

function safeMetadata(metadata) {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return {};
  return scrub(metadata);
}

function scrub(value) {
  if (Array.isArray(value)) return value.slice(0, 50).map(scrub);
  if (!value || typeof value !== "object") return value;
  const output = {};
  for (const [key, child] of Object.entries(value)) {
    if (/password|secret|token|credential|authorization|cookie|private[_-]?key|api[_-]?key/i.test(key)) continue;
    output[safeString(key, 80)] = scrub(child);
  }
  return output;
}
