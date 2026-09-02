import "server-only";

import { and, desc, eq, gte, isNull, lte, sql } from "drizzle-orm";
import { db } from "../../db/client.js";
import {
  breakGlassAdministrators,
  identityAuditEvents,
  identityAuditReports,
  identityMetrics,
  identityRecoveryEvents,
  identityRecoveryWorkflows,
  identityRiskScores,
  identitySecurityEvents,
  mfaMethods,
  oauthLoginAttempts,
  organizationMemberships,
  scimProviders,
  scimSyncJobs,
  ssoLoginAttempts,
} from "../../db/schema.js";
import { AUDIT_RESULTS } from "../audit/index.js";
import {
  IDENTITY_AUDIT_EVENT_TYPES,
  listIdentityProviders,
  recordIdentityAuditEvent,
  sanitizeIdentityMetadata,
} from "../identity/index.js";
import { getIdentitySecurityDashboard } from "../identity-security/index.js";
import { safeString } from "../management/tokens.js";

const DEFAULT_DAYS = 30;
const MAX_DAYS = 180;
const DEFAULT_LIMIT = 25;
const MAX_LIMIT = 100;

export const IDENTITY_METRIC_TYPES = Object.freeze({
  LOGIN_SUCCESS_RATE: "login_success_rate",
  LOGIN_FAILURE_RATE: "login_failure_rate",
  MFA_SUCCESS_RATE: "mfa_success_rate",
  MFA_FAILURE_RATE: "mfa_failure_rate",
  OAUTH_HEALTH: "oauth_health",
  SSO_HEALTH: "sso_health",
  SCIM_HEALTH: "scim_health",
  RISKY_IDENTITY_TREND: "risky_identity_trend",
});

export const IDENTITY_METRIC_STATUSES = Object.freeze({
  HEALTHY: "healthy",
  DEGRADED: "degraded",
  CRITICAL: "critical",
  UNKNOWN: "unknown",
});

export const IDENTITY_AUDIT_REPORT_TYPES = Object.freeze({
  ADMINISTRATOR_ACTIVITY: "administrator_activity",
  AUTHENTICATION_ACTIVITY: "authentication_activity",
  PROVISIONING_ACTIVITY: "provisioning_activity",
  ACCESS_REVIEW: "access_review",
  IDENTITY_EVIDENCE: "identity_evidence",
});

export const IDENTITY_EXPORT_FORMATS = Object.freeze({
  CSV: "csv",
  JSON: "json",
  EVIDENCE_TIMELINE: "evidence_timeline",
});

export const BREAK_GLASS_STATUSES = Object.freeze({
  ACTIVE: "active",
  DISABLED: "disabled",
  EXPIRED: "expired",
  REVOKED: "revoked",
});

export const RECOVERY_WORKFLOW_TYPES = Object.freeze({
  ACCOUNT_RECOVERY: "account_recovery",
  LOCKOUT_RECOVERY: "lockout_recovery",
  BREAK_GLASS_ACTIVATION: "break_glass_activation",
  IDENTITY_DISASTER_RECOVERY: "identity_disaster_recovery",
});

export const RECOVERY_WORKFLOW_STATUSES = Object.freeze({
  DRAFT: "draft",
  REQUESTED: "requested",
  APPROVED: "approved",
  ACTIVE: "active",
  COMPLETED: "completed",
  REJECTED: "rejected",
  EXPIRED: "expired",
  CANCELLED: "cancelled",
});

export const RECOVERY_EVENT_TYPES = Object.freeze({
  REQUESTED: "recovery.requested",
  APPROVED: "recovery.approved",
  COMPLETED: "recovery.completed",
  REJECTED: "recovery.rejected",
  BREAK_GLASS_CREATED: "break_glass.created",
  BREAK_GLASS_ACTIVATED: "break_glass.activated",
  BREAK_GLASS_REVOKED: "break_glass.revoked",
  TESTED: "recovery.tested",
});

export async function recordIdentityMetric({
  database = db(),
  organizationId,
  metricType,
  metricValue,
  numerator = 0,
  denominator = 0,
  bucketStart,
  bucketEnd,
  status = null,
  dimensions = {},
  metadata = {},
} = {}) {
  if (!organizationId) throw new Error("organizationId is required");
  const value = clampPercent(metricValue);
  const [metric] = await database
    .insert(identityMetrics)
    .values({
      organizationId,
      metricType: enumValue(metricType, Object.values(IDENTITY_METRIC_TYPES), "identity metric type"),
      metricValue: value,
      numerator: nonNegativeInteger(numerator, "numerator"),
      denominator: nonNegativeInteger(denominator, "denominator"),
      status: status
        ? enumValue(status, Object.values(IDENTITY_METRIC_STATUSES), "metric status")
        : metricStatus(value),
      bucketStart: requiredDate(bucketStart, "bucketStart"),
      bucketEnd: requiredDate(bucketEnd, "bucketEnd"),
      dimensions: sanitizeIdentityMetadata(dimensions),
      metadata: sanitizeIdentityMetadata(metadata),
    })
    .returning();
  return publicIdentityMetric(metric);
}

export async function getIdentityObservabilityDashboard({ database = db(), organizationId, filters = {} } = {}) {
  if (!organizationId) throw new Error("organizationId is required");
  const query = normalizeQuery(filters);

  const [auth, oauth, sso, scim, mfa, risky, reports, recovery, metrics] = await Promise.all([
    authenticationHealth(database, organizationId, query),
    oauthHealth(database, organizationId, query),
    ssoHealth(database, organizationId, query),
    scimHealth(database, organizationId, query),
    mfaAdoption(database, organizationId),
    riskTrend(database, organizationId, query),
    listIdentityAuditReports({ database, organizationId, filters: { limit: 10 } }),
    listRecoveryState({ database, organizationId, filters: { limit: 10 } }),
    listIdentityMetrics({ database, organizationId, filters: { limit: 20 } }),
  ]);

  return {
    window: query.window,
    executive: {
      loginSuccessRate: auth.successRate,
      loginFailureRate: auth.failureRate,
      mfaAdoptionRate: mfa.adoptionRate,
      oauthHealth: oauth.healthScore,
      ssoHealth: sso.healthScore,
      scimHealth: scim.healthScore,
      riskyIdentities: risky.activeRiskCount,
      openRecoveryWorkflows: recovery.workflows.filter((item) => ["requested", "approved", "active"].includes(item.status)).length,
    },
    authentication: auth,
    oauth,
    sso,
    scim,
    mfa,
    risky,
    reports: reports.items,
    recovery,
    metrics: metrics.items,
  };
}

export async function generateIdentitySecurityReport({
  database = db(),
  organizationId,
  filters = {},
  generatedByUserId = null,
  auditContext = {},
  recordAudit = false,
} = {}) {
  if (!organizationId) throw new Error("organizationId is required");
  const query = normalizeQuery(filters);
  const [security, observability, providers] = await Promise.all([
    getIdentitySecurityDashboard({ database, organizationId, filters: query }),
    getIdentityObservabilityDashboard({ database, organizationId, filters: query }),
    listIdentityProviders({ database, organizationId }),
  ]);

  const report = buildIdentitySecurityReport({
    organizationId,
    generatedAt: new Date(),
    window: query.window,
    generatedByUserId,
    security,
    observability,
    providers,
  });

  if (recordAudit) {
    await recordIdentityAuditEvent({
      database,
      organizationId,
      actorUserId: auditContext.userId || generatedByUserId,
      eventType: IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_REPORT_GENERATED,
      action: IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_REPORT_GENERATED,
      result: AUDIT_RESULTS.SUCCESS,
      requestId: auditContext.requestId,
      ipAddress: auditContext.ipAddress,
      userAgent: auditContext.userAgent,
      metadata: {
        reportType: report.reportType,
        readinessStatus: report.releaseReadiness.status,
        criticalFindings: report.releaseReadiness.criticalFindings,
        highFindings: report.releaseReadiness.highFindings,
      },
    });
  }

  return report;
}

export function buildIdentitySecurityReport({
  organizationId,
  generatedAt = new Date(),
  window,
  generatedByUserId = null,
  security = {},
  observability = {},
  providers = [],
} = {}) {
  if (!organizationId) throw new Error("organizationId is required");
  const safeProviders = Array.isArray(providers) ? providers.map(publicIdentityProviderSummary) : [];
  const providerStatus = providerStatusSummary(safeProviders);
  const executive = security.executive || {};
  const obsExecutive = observability.executive || {};
  const authentication = observability.authentication || security.authenticationActivity || {};
  const recovery = observability.recovery || {};
  const riskyIdentities = Array.isArray(security.riskyIdentities) ? security.riskyIdentities : [];
  const accessReviews = Array.isArray(security.accessReviews) ? security.accessReviews : [];
  const identityEvents = Array.isArray(security.recentEvents) ? security.recentEvents : [];
  const reports = Array.isArray(observability.reports) ? observability.reports : [];
  const recoveryWorkflows = Array.isArray(recovery.workflows) ? recovery.workflows : [];
  const breakGlassAdmins = Array.isArray(recovery.breakGlassAdministrators) ? recovery.breakGlassAdministrators : [];
  const findings = identitySecurityReportFindings({
    providerStatus,
    executive,
    obsExecutive,
    authentication,
    riskyIdentities,
    accessReviews,
    recoveryWorkflows,
    breakGlassAdmins,
  });

  return {
    reportType: "identity_security_report",
    generatedAt: toIso(generatedAt),
    generatedByUserId: generatedByUserId || null,
    organizationId,
    window: window || security.window || observability.window || null,
    certificationClaims: [],
    summary: {
      identitySecurityScore: numberValue(executive.identitySecurityScore ?? 100),
      loginSuccessRate: numberValue(obsExecutive.loginSuccessRate ?? 100),
      loginFailureRate: numberValue(obsExecutive.loginFailureRate ?? 0),
      mfaAdoptionRate: numberValue(executive.mfaAdoptionRate ?? obsExecutive.mfaAdoptionRate ?? 100),
      riskyIdentities: numberValue(executive.riskyIdentities ?? obsExecutive.riskyIdentities ?? riskyIdentities.length),
      openAccessReviews: numberValue(executive.openAccessReviews ?? 0),
      openRecoveryWorkflows: numberValue(obsExecutive.openRecoveryWorkflows ?? recoveryWorkflows.length),
      ssoFailureRate: numberValue(executive.ssoFailureRate ?? 0),
      scimFailureRate: numberValue(executive.scimFailureRate ?? 0),
    },
    authenticationMethods: {
      password: providerStatus.password,
      google: providerStatus.google,
      github: providerStatus.github,
      oidc: providerStatus.oidc,
      saml: providerStatus.saml,
      mfa: {
        adoptionRate: numberValue(security.mfaAdoption?.adoptionRate ?? observability.mfa?.adoptionRate ?? 100),
        enabledUsers: numberValue(security.mfaAdoption?.enabledUsers ?? observability.mfa?.enabledUsers ?? 0),
        missingUsers: numberValue(security.mfaAdoption?.missingUsers ?? observability.mfa?.missingUsers ?? 0),
      },
    },
    providerPosture: {
      providers: safeProviders,
      oauth: sanitizeProviderHealth(observability.oauth),
      sso: sanitizeProviderHealth(security.ssoHealth || observability.sso),
      scim: sanitizeProviderHealth(security.scimHealth || observability.scim),
    },
    privilegedIdentityPosture: {
      accessReviews: accessReviews.map(publicReviewSummary),
      breakGlassAdministrators: breakGlassAdmins.map(publicBreakGlassReportSummary),
      recoveryWorkflows: recoveryWorkflows.map(publicRecoveryWorkflowSummary),
    },
    riskFindings: riskyIdentities.map(publicRiskReportSummary),
    identityEvents: identityEvents.map(publicSecurityEventSummary),
    evidence: {
      auditReports: reports.map(publicReportSummary),
      recoveryEvents: (Array.isArray(recovery.events) ? recovery.events : []).map(publicRecoveryEventSummary),
      significantAdministrativeEvents: identityEvents
        .filter((event) => /provider|mfa|scim|sso|recovery|break_glass|identity/i.test(event.eventType || ""))
        .slice(0, 10)
        .map(publicSecurityEventSummary),
    },
    releaseReadiness: {
      status: findings.some((finding) => finding.severity === "critical" || finding.severity === "high")
        ? "review_required"
        : "ready_for_validation",
      criticalFindings: findings.filter((finding) => finding.severity === "critical").length,
      highFindings: findings.filter((finding) => finding.severity === "high").length,
      findings,
    },
    limitations: [
      "This report is operational evidence only and does not claim SOC 2, ISO 27001, or other certification.",
      "External Google, GitHub, SAML, OIDC, and SCIM provider live validation remains a Phase 9.9 activity.",
    ],
  };
}

export async function listIdentityMetrics({ database = db(), organizationId, filters = {} } = {}) {
  if (!organizationId) throw new Error("organizationId is required");
  const query = normalizeQuery(filters);
  const rows = await database
    .select()
    .from(identityMetrics)
    .where(and(eq(identityMetrics.organizationId, organizationId), gte(identityMetrics.bucketStart, query.since), lte(identityMetrics.bucketEnd, query.until)))
    .orderBy(desc(identityMetrics.bucketStart), desc(identityMetrics.id))
    .limit(query.limit + 1)
    .offset(query.offset);
  return pageResult(rows.map(publicIdentityMetric), query);
}

export async function createIdentityAuditReport({
  database = db(),
  organizationId,
  reportType = IDENTITY_AUDIT_REPORT_TYPES.IDENTITY_EVIDENCE,
  exportFormat = IDENTITY_EXPORT_FORMATS.JSON,
  windowStart = null,
  windowEnd = null,
  generatedByUserId = null,
  metadata = {},
  auditContext = {},
} = {}) {
  if (!organizationId) throw new Error("organizationId is required");
  const type = enumValue(reportType, Object.values(IDENTITY_AUDIT_REPORT_TYPES), "identity audit report type");
  const format = enumValue(exportFormat, Object.values(IDENTITY_EXPORT_FORMATS), "identity export format");
  const query = normalizeQuery({ since: windowStart, until: windowEnd, limit: 100 });
  const payload = await buildAuditReportPayload({ database, organizationId, reportType: type, exportFormat: format, query });

  const [report] = await database
    .insert(identityAuditReports)
    .values({
      organizationId,
      reportType: type,
      exportFormat: format,
      status: "generated",
      windowStart: query.since,
      windowEnd: query.until,
      generatedByUserId,
      rowCount: payload.rowCount,
      reportPayload: payload,
      evidenceRef: payload.evidenceRef,
      metadata: sanitizeIdentityMetadata(metadata),
    })
    .returning();

  await recordIdentityAuditEvent({
    database,
    organizationId,
    actorUserId: auditContext.userId || generatedByUserId,
    eventType: IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_REPORT_GENERATED,
    action: IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_REPORT_GENERATED,
    result: AUDIT_RESULTS.SUCCESS,
    requestId: auditContext.requestId,
    ipAddress: auditContext.ipAddress,
    userAgent: auditContext.userAgent,
    metadata: { reportType: type, exportFormat: format, rowCount: payload.rowCount },
  });

  return publicIdentityAuditReport(report);
}

export async function listIdentityAuditReports({ database = db(), organizationId, filters = {} } = {}) {
  if (!organizationId) throw new Error("organizationId is required");
  const query = normalizeQuery(filters);
  const predicates = [eq(identityAuditReports.organizationId, organizationId), isNull(identityAuditReports.deletedAt)];
  if (filters.reportType) {
    predicates.push(eq(identityAuditReports.reportType, enumValue(filters.reportType, Object.values(IDENTITY_AUDIT_REPORT_TYPES), "identity audit report type")));
  }

  const rows = await database
    .select()
    .from(identityAuditReports)
    .where(and(...predicates))
    .orderBy(desc(identityAuditReports.generatedAt), desc(identityAuditReports.id))
    .limit(query.limit + 1)
    .offset(query.offset);
  return pageResult(rows.map(publicIdentityAuditReport), query);
}

export async function createBreakGlassAdministrator({
  database = db(),
  organizationId,
  userId,
  reason,
  approvedByUserId = null,
  expiresAt,
  status = BREAK_GLASS_STATUSES.DISABLED,
  metadata = {},
  auditContext = {},
} = {}) {
  if (!organizationId || !userId) throw new Error("organizationId and userId are required");
  const normalizedStatus = enumValue(status, Object.values(BREAK_GLASS_STATUSES), "break-glass status");
  const [record] = await database
    .insert(breakGlassAdministrators)
    .values({
      organizationId,
      userId,
      status: normalizedStatus,
      reason: requiredString(reason, "reason", 4000),
      mfaRequired: true,
      approvedByUserId,
      activatedAt: normalizedStatus === BREAK_GLASS_STATUSES.ACTIVE ? new Date() : null,
      expiresAt: requiredDate(expiresAt, "expiresAt"),
      metadata: sanitizeIdentityMetadata(metadata),
    })
    .returning();

  await recordRecoveryEvent({
    database,
    organizationId,
    breakGlassAdministratorId: record.id,
    actorUserId: auditContext.userId || approvedByUserId,
    targetUserId: userId,
    eventType: RECOVERY_EVENT_TYPES.BREAK_GLASS_CREATED,
    result: AUDIT_RESULTS.SUCCESS,
    summary: "Break-glass administrator record created",
    auditContext,
  });

  return publicBreakGlassAdministrator(record);
}

export async function createIdentityRecoveryWorkflow({
  database = db(),
  organizationId,
  targetUserId = null,
  workflowType = RECOVERY_WORKFLOW_TYPES.ACCOUNT_RECOVERY,
  reason,
  expiresAt = null,
  requestedByUserId = null,
  metadata = {},
  auditContext = {},
} = {}) {
  if (!organizationId) throw new Error("organizationId is required");
  const normalizedType = enumValue(workflowType, Object.values(RECOVERY_WORKFLOW_TYPES), "recovery workflow type");
  const [workflow] = await database
    .insert(identityRecoveryWorkflows)
    .values({
      organizationId,
      targetUserId,
      requestedByUserId,
      workflowType: normalizedType,
      status: RECOVERY_WORKFLOW_STATUSES.REQUESTED,
      reason: requiredString(reason, "reason", 4000),
      mfaRequired: true,
      approvalRequired: true,
      expiresAt: nullableDate(expiresAt),
      metadata: sanitizeIdentityMetadata(metadata),
    })
    .returning();

  await recordRecoveryEvent({
    database,
    organizationId,
    workflowId: workflow.id,
    actorUserId: auditContext.userId || requestedByUserId,
    targetUserId,
    eventType: RECOVERY_EVENT_TYPES.REQUESTED,
    result: AUDIT_RESULTS.SUCCESS,
    summary: "Identity recovery workflow requested",
    auditContext,
  });

  return publicIdentityRecoveryWorkflow(workflow);
}

export async function recordRecoveryEvent({
  database = db(),
  organizationId,
  workflowId = null,
  breakGlassAdministratorId = null,
  actorUserId = null,
  targetUserId = null,
  eventType,
  result = AUDIT_RESULTS.SUCCESS,
  summary = null,
  metadata = {},
  auditContext = {},
} = {}) {
  if (!organizationId) throw new Error("organizationId is required");
  const normalizedEventType = enumValue(eventType, Object.values(RECOVERY_EVENT_TYPES), "recovery event type");
  const [event] = await database
    .insert(identityRecoveryEvents)
    .values({
      organizationId,
      workflowId,
      breakGlassAdministratorId,
      actorUserId,
      targetUserId,
      eventType: normalizedEventType,
      result: enumValue(result, Object.values(AUDIT_RESULTS), "recovery event result"),
      summary: safeString(summary, 4000),
      metadata: sanitizeIdentityMetadata(metadata),
    })
    .returning();

  await recordIdentityAuditEvent({
    database,
    organizationId,
    userId: targetUserId,
    actorUserId: auditContext.userId || actorUserId,
    eventType: auditTypeForRecoveryEvent(normalizedEventType),
    action: normalizedEventType,
    result,
    requestId: auditContext.requestId,
    ipAddress: auditContext.ipAddress,
    userAgent: auditContext.userAgent,
    metadata: { recoveryEventType: normalizedEventType },
  });

  return publicIdentityRecoveryEvent(event);
}

export async function listRecoveryState({ database = db(), organizationId, filters = {} } = {}) {
  if (!organizationId) throw new Error("organizationId is required");
  const query = normalizeQuery(filters);
  const [workflows, breakGlassAdmins, events] = await Promise.all([
    database
      .select()
      .from(identityRecoveryWorkflows)
      .where(and(eq(identityRecoveryWorkflows.organizationId, organizationId), isNull(identityRecoveryWorkflows.deletedAt)))
      .orderBy(desc(identityRecoveryWorkflows.updatedAt))
      .limit(query.limit),
    database
      .select()
      .from(breakGlassAdministrators)
      .where(eq(breakGlassAdministrators.organizationId, organizationId))
      .orderBy(desc(breakGlassAdministrators.updatedAt))
      .limit(query.limit),
    database
      .select()
      .from(identityRecoveryEvents)
      .where(eq(identityRecoveryEvents.organizationId, organizationId))
      .orderBy(desc(identityRecoveryEvents.createdAt))
      .limit(query.limit),
  ]);

  return {
    workflows: workflows.map(publicIdentityRecoveryWorkflow),
    breakGlassAdministrators: breakGlassAdmins.map(publicBreakGlassAdministrator),
    events: events.map(publicIdentityRecoveryEvent),
  };
}

async function authenticationHealth(database, organizationId, query) {
  const whereClause = and(
    eq(identitySecurityEvents.organizationId, organizationId),
    gte(identitySecurityEvents.createdAt, query.since),
    lte(identitySecurityEvents.createdAt, query.until),
  );
  const [summary] = await database
    .select({
      success: sql`sum(case when ${identitySecurityEvents.eventType} = 'login.success' then 1 else 0 end)`,
      failure: sql`sum(case when ${identitySecurityEvents.eventType} = 'login.failure' then 1 else 0 end)`,
      mfaFailure: sql`sum(case when ${identitySecurityEvents.eventType} = 'mfa.failure' then 1 else 0 end)`,
      total: sql`count(*)`,
    })
    .from(identitySecurityEvents)
    .where(whereClause);

  const success = numberValue(summary?.success);
  const failure = numberValue(summary?.failure);
  const total = success + failure;
  return {
    successfulLogins: success,
    failedLogins: failure,
    mfaFailures: numberValue(summary?.mfaFailure),
    successRate: total ? roundNumber((success / total) * 100, 1) : 100,
    failureRate: total ? roundNumber((failure / total) * 100, 1) : 0,
  };
}

async function oauthHealth(database, organizationId, query) {
  const [summary] = await database
    .select({
      total: sql`count(*)`,
      failed: sql`sum(case when ${oauthLoginAttempts.status} = 'failed' then 1 else 0 end)`,
    })
    .from(oauthLoginAttempts)
    .where(and(gte(oauthLoginAttempts.createdAt, query.since), lte(oauthLoginAttempts.createdAt, query.until)));
  return healthFromFailures(summary);
}

async function ssoHealth(database, organizationId, query) {
  const [summary] = await database
    .select({
      total: sql`count(*)`,
      failed: sql`sum(case when ${ssoLoginAttempts.status} = 'failed' then 1 else 0 end)`,
    })
    .from(ssoLoginAttempts)
    .where(and(eq(ssoLoginAttempts.organizationId, organizationId), gte(ssoLoginAttempts.createdAt, query.since), lte(ssoLoginAttempts.createdAt, query.until)));
  return healthFromFailures(summary);
}

async function scimHealth(database, organizationId, query) {
  const [syncSummary] = await database
    .select({
      total: sql`count(*)`,
      failed: sql`sum(case when ${scimSyncJobs.status} = 'failed' then 1 else 0 end)`,
      running: sql`sum(case when ${scimSyncJobs.status} = 'running' then 1 else 0 end)`,
    })
    .from(scimSyncJobs)
    .where(and(eq(scimSyncJobs.organizationId, organizationId), gte(scimSyncJobs.createdAt, query.since), lte(scimSyncJobs.createdAt, query.until)));
  const [providerSummary] = await database
    .select({
      total: sql`count(*)`,
      active: sql`sum(case when ${scimProviders.status} = 'active' then 1 else 0 end)`,
    })
    .from(scimProviders)
    .where(and(eq(scimProviders.organizationId, organizationId), isNull(scimProviders.deletedAt)));
  return {
    ...healthFromFailures(syncSummary),
    running: numberValue(syncSummary?.running),
    providers: numberValue(providerSummary?.total),
    activeProviders: numberValue(providerSummary?.active),
  };
}

async function mfaAdoption(database, organizationId) {
  const [membershipSummary] = await database
    .select({ total: sql`count(*)` })
    .from(organizationMemberships)
    .where(and(eq(organizationMemberships.organizationId, organizationId), eq(organizationMemberships.status, "active")));
  const [mfaSummary] = await database
    .select({ enabled: sql`count(distinct ${mfaMethods.userId})` })
    .from(mfaMethods)
    .where(and(eq(mfaMethods.organizationId, organizationId), eq(mfaMethods.status, "active"), isNull(mfaMethods.deletedAt)));
  const total = numberValue(membershipSummary?.total);
  const enabled = numberValue(mfaSummary?.enabled);
  return {
    activeUsers: total,
    enabledUsers: enabled,
    missingUsers: Math.max(0, total - enabled),
    adoptionRate: total ? roundNumber((enabled / total) * 100, 1) : 100,
  };
}

async function riskTrend(database, organizationId, query) {
  const [summary] = await database
    .select({
      active: sql`sum(case when ${identityRiskScores.status} = 'active' then 1 else 0 end)`,
      high: sql`sum(case when ${identityRiskScores.score} >= 70 then 1 else 0 end)`,
      maxScore: sql`max(${identityRiskScores.score})`,
    })
    .from(identityRiskScores)
    .where(and(eq(identityRiskScores.organizationId, organizationId), isNull(identityRiskScores.deletedAt)));
  const rows = await database
    .select()
    .from(identityRiskScores)
    .where(and(eq(identityRiskScores.organizationId, organizationId), gte(identityRiskScores.updatedAt, query.since), lte(identityRiskScores.updatedAt, query.until), isNull(identityRiskScores.deletedAt)))
    .orderBy(desc(identityRiskScores.score), desc(identityRiskScores.updatedAt))
    .limit(10);
  return {
    activeRiskCount: numberValue(summary?.active),
    highRiskCount: numberValue(summary?.high),
    maxScore: numberValue(summary?.maxScore),
    topRisks: rows.map((row) => ({
      id: row.id,
      subjectType: row.subjectType,
      subjectId: row.subjectId,
      score: row.score,
      severity: row.severity,
      recommendedAction: row.recommendedAction,
      updatedAt: row.updatedAt,
    })),
  };
}

async function buildAuditReportPayload({ database, organizationId, reportType, exportFormat, query }) {
  const rows = await database
    .select({
      id: identityAuditEvents.id,
      eventType: identityAuditEvents.eventType,
      action: identityAuditEvents.action,
      result: identityAuditEvents.result,
      requestId: identityAuditEvents.requestId,
      createdAt: identityAuditEvents.createdAt,
    })
    .from(identityAuditEvents)
    .where(and(eq(identityAuditEvents.organizationId, organizationId), gte(identityAuditEvents.createdAt, query.since), lte(identityAuditEvents.createdAt, query.until)))
    .orderBy(desc(identityAuditEvents.createdAt))
    .limit(query.limit);
  const sanitizedRows = rows.map((row) => ({
    id: row.id,
    eventType: row.eventType,
    action: row.action,
    result: row.result,
    requestId: row.requestId,
    createdAt: row.createdAt,
  }));
  return {
    reportType,
    exportFormat,
    window: query.window,
    rowCount: sanitizedRows.length,
    evidenceRef: null,
    data: exportFormat === IDENTITY_EXPORT_FORMATS.CSV ? rowsToCsv(sanitizedRows) : sanitizedRows,
  };
}

function providerStatusSummary(providers) {
  const defaults = {
    password: providerStatus("password", "active", "Password"),
    google: providerStatus("google", "disabled", "Google"),
    github: providerStatus("github", "disabled", "GitHub"),
    oidc: providerStatus("oidc", "disabled", "OpenID Connect"),
    saml: providerStatus("saml", "disabled", "SAML"),
  };
  for (const provider of providers) {
    defaults[provider.providerType] = providerStatus(
      provider.providerType,
      provider.status,
      provider.displayName || provider.providerKey,
    );
  }
  return defaults;
}

function providerStatus(providerType, status, displayName) {
  return {
    providerType,
    displayName,
    status: safeString(status || "disabled", 32),
    enabled: status === "active",
  };
}

function publicIdentityProviderSummary(provider = {}) {
  return {
    id: provider.id,
    providerKey: safeString(provider.providerKey, 80),
    providerType: safeString(provider.providerType, 32),
    displayName: safeString(provider.displayName, 160),
    status: safeString(provider.status, 32),
    organizationId: provider.organizationId || null,
  };
}

function sanitizeProviderHealth(health = {}) {
  return {
    providers: numberValue(health.providers ?? health.total ?? 0),
    activeProviders: numberValue(health.activeProviders ?? 0),
    attempts: numberValue(health.attempts ?? health.total ?? 0),
    failures: numberValue(health.failures ?? 0),
    failureRate: numberValue(health.failureRate ?? 0),
    healthScore: numberValue(health.healthScore ?? Math.max(0, 100 - numberValue(health.failureRate ?? 0))),
    status: safeString(health.status || "unknown", 32),
  };
}

function publicRiskReportSummary(risk = {}) {
  return {
    id: risk.id,
    subjectType: safeString(risk.subjectType, 80),
    subjectId: safeString(risk.subjectId, 160),
    score: numberValue(risk.score),
    severity: safeString(risk.severity, 32),
    recommendedAction: safeString(risk.recommendedAction, 80),
    updatedAt: risk.updatedAt || null,
  };
}

function publicReviewSummary(review = {}) {
  return {
    id: review.id,
    name: safeString(review.name, 160),
    reviewType: safeString(review.reviewType, 64),
    status: safeString(review.status, 32),
    dueAt: review.dueAt || null,
    updatedAt: review.updatedAt || null,
  };
}

function publicBreakGlassReportSummary(record = {}) {
  return {
    id: record.id,
    userId: record.userId || null,
    status: safeString(record.status, 32),
    mfaRequired: record.mfaRequired !== false,
    activatedAt: record.activatedAt || null,
    expiresAt: record.expiresAt || null,
    revokedAt: record.revokedAt || null,
  };
}

function publicRecoveryWorkflowSummary(workflow = {}) {
  return {
    id: workflow.id,
    targetUserId: workflow.targetUserId || null,
    workflowType: safeString(workflow.workflowType, 64),
    status: safeString(workflow.status, 32),
    mfaRequired: workflow.mfaRequired !== false,
    approvalRequired: workflow.approvalRequired !== false,
    requestedAt: workflow.requestedAt || null,
    completedAt: workflow.completedAt || null,
    expiresAt: workflow.expiresAt || null,
  };
}

function publicSecurityEventSummary(event = {}) {
  return {
    id: event.id,
    eventType: safeString(event.eventType, 160),
    category: safeString(event.category, 64),
    result: safeString(event.result, 32),
    severity: safeString(event.severity, 32),
    riskScore: numberValue(event.riskScore),
    action: safeString(event.action, 80),
    createdAt: event.createdAt || null,
  };
}

function publicReportSummary(report = {}) {
  return {
    id: report.id,
    reportType: safeString(report.reportType, 80),
    exportFormat: safeString(report.exportFormat, 32),
    status: safeString(report.status, 32),
    rowCount: numberValue(report.rowCount),
    generatedAt: report.generatedAt || null,
  };
}

function publicRecoveryEventSummary(event = {}) {
  return {
    id: event.id,
    eventType: safeString(event.eventType, 160),
    result: safeString(event.result, 32),
    summary: safeString(event.summary, 400),
    createdAt: event.createdAt || null,
  };
}

function identitySecurityReportFindings({
  providerStatus,
  executive,
  obsExecutive,
  authentication,
  riskyIdentities,
  accessReviews,
  recoveryWorkflows,
  breakGlassAdmins,
}) {
  const findings = [];
  if (numberValue(executive.identitySecurityScore ?? 100) < 70) {
    findings.push({ severity: "high", summary: "Identity security score requires review before release." });
  }
  if (numberValue(obsExecutive.loginFailureRate ?? 0) >= 20) {
    findings.push({ severity: "high", summary: "Authentication failure rate is elevated." });
  }
  if (numberValue(authentication.mfaFailures ?? 0) >= 10) {
    findings.push({ severity: "medium", summary: "MFA failure volume should be reviewed." });
  }
  if (numberValue(executive.mfaAdoptionRate ?? obsExecutive.mfaAdoptionRate ?? 100) < 80) {
    findings.push({ severity: "medium", summary: "MFA adoption is below enterprise target." });
  }
  if (riskyIdentities.some((risk) => risk.severity === "critical" || Number(risk.score || 0) >= 90)) {
    findings.push({ severity: "high", summary: "Critical risky identities remain active." });
  }
  if (accessReviews.some((review) => ["open", "in_review"].includes(review.status))) {
    findings.push({ severity: "medium", summary: "Open identity access reviews require owner attention." });
  }
  if (recoveryWorkflows.some((workflow) => ["requested", "approved", "active"].includes(workflow.status))) {
    findings.push({ severity: "medium", summary: "Open recovery workflows require closure before production launch." });
  }
  if (breakGlassAdmins.some((record) => record.status === "active")) {
    findings.push({ severity: "high", summary: "Active break-glass administrator access must be time-bound and reviewed." });
  }
  if (providerStatus.password.status !== "active") {
    findings.push({ severity: "critical", summary: "Password authentication baseline is not active." });
  }
  if (!findings.length) {
    findings.push({ severity: "low", summary: "No blocking identity release findings generated." });
  }
  return findings;
}

function healthFromFailures(summary) {
  const total = numberValue(summary?.total);
  const failed = numberValue(summary?.failed);
  const failureRate = total ? roundNumber((failed / total) * 100, 1) : 0;
  return {
    total,
    failures: failed,
    failureRate,
    healthScore: clampPercent(100 - failureRate),
    status: failureRate >= 20 ? "critical" : failureRate >= 5 ? "degraded" : "healthy",
  };
}

function publicIdentityMetric(metric = {}) {
  return {
    id: metric.id,
    organizationId: metric.organizationId,
    metricType: metric.metricType,
    metricValue: roundNumber(metric.metricValue, 2),
    numerator: numberValue(metric.numerator),
    denominator: numberValue(metric.denominator),
    status: metric.status,
    bucketStart: metric.bucketStart,
    bucketEnd: metric.bucketEnd,
    dimensions: metric.dimensions || {},
  };
}

function publicIdentityAuditReport(report = {}) {
  return {
    id: report.id,
    organizationId: report.organizationId,
    reportType: report.reportType,
    exportFormat: report.exportFormat,
    status: report.status,
    windowStart: report.windowStart || null,
    windowEnd: report.windowEnd || null,
    generatedAt: report.generatedAt || null,
    rowCount: numberValue(report.rowCount),
    reportPayload: report.reportPayload || {},
    evidenceRef: report.evidenceRef || null,
  };
}

function publicBreakGlassAdministrator(record = {}) {
  return {
    id: record.id,
    organizationId: record.organizationId,
    userId: record.userId,
    status: record.status,
    reason: record.reason || null,
    mfaRequired: record.mfaRequired !== false,
    activatedAt: record.activatedAt || null,
    expiresAt: record.expiresAt || null,
    revokedAt: record.revokedAt || null,
    updatedAt: record.updatedAt || null,
  };
}

function publicIdentityRecoveryWorkflow(workflow = {}) {
  return {
    id: workflow.id,
    organizationId: workflow.organizationId,
    targetUserId: workflow.targetUserId || null,
    workflowType: workflow.workflowType,
    status: workflow.status,
    reason: workflow.reason || null,
    mfaRequired: workflow.mfaRequired !== false,
    approvalRequired: workflow.approvalRequired !== false,
    requestedAt: workflow.requestedAt || null,
    completedAt: workflow.completedAt || null,
    expiresAt: workflow.expiresAt || null,
  };
}

function publicIdentityRecoveryEvent(event = {}) {
  return {
    id: event.id,
    organizationId: event.organizationId,
    workflowId: event.workflowId || null,
    breakGlassAdministratorId: event.breakGlassAdministratorId || null,
    actorUserId: event.actorUserId || null,
    targetUserId: event.targetUserId || null,
    eventType: event.eventType,
    result: event.result,
    summary: event.summary || null,
    createdAt: event.createdAt || null,
  };
}

function auditTypeForRecoveryEvent(eventType) {
  if (eventType === RECOVERY_EVENT_TYPES.COMPLETED) {
    return IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_RECOVERY_COMPLETED;
  }
  if (eventType === RECOVERY_EVENT_TYPES.BREAK_GLASS_CREATED) {
    return IDENTITY_AUDIT_EVENT_TYPES.BREAK_GLASS_ADMIN_CREATED;
  }
  if (eventType === RECOVERY_EVENT_TYPES.BREAK_GLASS_ACTIVATED) {
    return IDENTITY_AUDIT_EVENT_TYPES.BREAK_GLASS_ADMIN_ACTIVATED;
  }
  if (eventType === RECOVERY_EVENT_TYPES.BREAK_GLASS_REVOKED) {
    return IDENTITY_AUDIT_EVENT_TYPES.BREAK_GLASS_ADMIN_REVOKED;
  }
  return IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_RECOVERY_REQUESTED;
}

function rowsToCsv(rows) {
  if (!rows.length) return "";
  const headers = Object.keys(rows[0]);
  const lines = [headers.join(",")];
  for (const row of rows) {
    lines.push(headers.map((header) => csvCell(row[header])).join(","));
  }
  return lines.join("\n");
}

function csvCell(value) {
  const text = value instanceof Date ? value.toISOString() : String(value ?? "");
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function toIso(value) {
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? new Date().toISOString() : date.toISOString();
}

function normalizeQuery(filters = {}) {
  const now = new Date();
  const until = nullableDate(filters.until) || now;
  const since = nullableDate(filters.since) || new Date(until.getTime() - boundedDays(filters.days) * 24 * 60 * 60 * 1000);
  if (since > until) throw new Error("date filter is invalid");
  return {
    since,
    until,
    limit: boundedLimit(filters.limit),
    offset: boundedOffset(filters.offset),
    window: { since: since.toISOString(), until: until.toISOString() },
  };
}

function pageResult(items, query) {
  return {
    items: items.slice(0, query.limit),
    pageInfo: {
      limit: query.limit,
      offset: query.offset,
      hasMore: items.length > query.limit,
      nextOffset: items.length > query.limit ? query.offset + query.limit : null,
    },
  };
}

function metricStatus(value) {
  if (value >= 95) return IDENTITY_METRIC_STATUSES.HEALTHY;
  if (value >= 80) return IDENTITY_METRIC_STATUSES.DEGRADED;
  return IDENTITY_METRIC_STATUSES.CRITICAL;
}

function enumValue(value, allowed, label) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!allowed.includes(normalized)) throw new Error(`${label} is invalid`);
  return normalized;
}

function requiredString(value, label, maxLength = 512) {
  const text = safeString(value, maxLength);
  if (!text) throw new Error(`${label} is required`);
  return text;
}

function requiredDate(value, label) {
  const date = nullableDate(value);
  if (!date) throw new Error(`${label} is required`);
  return date;
}

function nullableDate(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error("date filter is invalid");
  return date;
}

function nonNegativeInteger(value, label) {
  const number = Number(value || 0);
  if (!Number.isFinite(number) || number < 0) throw new Error(`${label} is invalid`);
  return Math.trunc(number);
}

function boundedDays(value) {
  const days = Number(value || DEFAULT_DAYS);
  return Number.isFinite(days) && days > 0 ? Math.min(Math.trunc(days), MAX_DAYS) : DEFAULT_DAYS;
}

function boundedLimit(value) {
  const limit = Number(value || DEFAULT_LIMIT);
  return Number.isFinite(limit) && limit > 0 ? Math.min(Math.trunc(limit), MAX_LIMIT) : DEFAULT_LIMIT;
}

function boundedOffset(value) {
  const offset = Number(value || 0);
  return Number.isFinite(offset) && offset > 0 ? Math.min(Math.trunc(offset), 10_000) : 0;
}

function numberValue(value) {
  const number = Number(value || 0);
  return Number.isFinite(number) ? number : 0;
}

function roundNumber(value, digits = 0) {
  const number = Number(value || 0);
  if (!Number.isFinite(number)) return 0;
  const factor = 10 ** digits;
  return Math.round(number * factor) / factor;
}

function clampPercent(value) {
  const number = Number(value || 0);
  if (!Number.isFinite(number)) return 0;
  return Math.max(0, Math.min(100, roundNumber(number, 2)));
}
