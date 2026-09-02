import "server-only";

import { and, desc, eq, gte, isNull, lte, sql } from "drizzle-orm";
import { db } from "../../db/client.js";
import {
  identityAccessReviews,
  identityAuditEvents,
  identityComplianceReports,
  identityProviders,
  identityRiskScores,
  identitySecurityEvents,
  mfaMethods,
  oauthLoginAttempts,
  organizationMemberships,
  scimProviders,
  scimSyncJobs,
  ssoLoginAttempts,
  userRoles,
  users,
} from "../../db/schema.js";
import { AUDIT_RESULTS } from "../audit/index.js";
import {
  IDENTITY_AUDIT_EVENT_TYPES,
  recordIdentityAuditEvent,
  sanitizeIdentityMetadata,
} from "../identity/index.js";
import { safeString } from "../management/tokens.js";

const DEFAULT_DAYS = 30;
const MAX_DAYS = 180;
const DEFAULT_LIMIT = 25;
const MAX_LIMIT = 100;

export const IDENTITY_SECURITY_EVENT_TYPES = Object.freeze({
  LOGIN_SUCCESS: "login.success",
  LOGIN_FAILURE: "login.failure",
  MFA_FAILURE: "mfa.failure",
  OAUTH_FAILURE: "oauth.failure",
  SSO_FAILURE: "sso.failure",
  SCIM_PROVISIONING_FAILURE: "scim.provisioning.failure",
  SUSPICIOUS_CHANGE: "identity.change.suspicious",
  RISK_DETECTED: "identity.risk.detected",
  ACCOUNT_FLAGGED: "identity.account.flagged",
});

export const IDENTITY_SECURITY_CATEGORIES = Object.freeze({
  AUTHENTICATION: "authentication",
  MFA: "mfa",
  OAUTH: "oauth",
  SSO: "sso",
  SCIM: "scim",
  GOVERNANCE: "governance",
  RISK: "risk",
});

export const IDENTITY_SECURITY_ACTIONS = Object.freeze({
  MONITOR: "monitor",
  REQUIRE_MFA: "require_mfa",
  RESTRICT_SESSION: "restrict_session",
  ALERT: "alert",
});

export const IDENTITY_RISK_STATUSES = Object.freeze({
  ACTIVE: "active",
  RESOLVED: "resolved",
  SUPPRESSED: "suppressed",
  EXPIRED: "expired",
});

export const ACCESS_REVIEW_TYPES = Object.freeze({
  PERIODIC: "periodic",
  PRIVILEGED: "privileged",
  INACTIVE_ACCOUNTS: "inactive_accounts",
  ORPHANED_IDENTITIES: "orphaned_identities",
});

export const ACCESS_REVIEW_STATUSES = Object.freeze({
  DRAFT: "draft",
  OPEN: "open",
  IN_REVIEW: "in_review",
  COMPLETED: "completed",
  CANCELLED: "cancelled",
  EXPIRED: "expired",
});

export const IDENTITY_COMPLIANCE_REPORT_TYPES = Object.freeze({
  USER_INVENTORY: "user_inventory",
  MFA_STATUS: "mfa_status",
  PRIVILEGED_ACCESS: "privileged_access",
  SSO_CONFIGURATION: "sso_configuration",
  PROVISIONING_HISTORY: "provisioning_history",
});

export async function recordIdentitySecurityEvent({
  database = db(),
  organizationId,
  userId = null,
  actorUserId = null,
  providerId = null,
  scimProviderId = null,
  auditEventId = null,
  eventType,
  category,
  result = AUDIT_RESULTS.SUCCESS,
  severity,
  riskScore = 0,
  action,
  ipAddress = null,
  userAgent = null,
  source = "identity",
  summary = null,
  metadata = {},
  auditContext = {},
} = {}) {
  const normalized = normalizeIdentitySecurityEvent({
    organizationId,
    userId,
    actorUserId,
    providerId,
    scimProviderId,
    auditEventId,
    eventType,
    category,
    result,
    severity,
    riskScore,
    action,
    ipAddress,
    userAgent,
    source,
    summary,
    metadata,
  });

  const [created] = await database.insert(identitySecurityEvents).values(normalized).returning();

  if (isRiskEvent(normalized)) {
    await recordIdentityAuditEvent({
      database,
      organizationId: normalized.organizationId,
      userId: normalized.userId,
      actorUserId: auditContext.userId || actorUserId || null,
      eventType: IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_RISK_DETECTED,
      action: normalized.eventType,
      result: normalized.result,
      requestId: auditContext.requestId,
      ipAddress: normalized.ipAddress || auditContext.ipAddress,
      userAgent: normalized.userAgent || auditContext.userAgent,
      metadata: {
        category: normalized.category,
        severity: normalized.severity,
        riskScore: normalized.riskScore,
        action: normalized.action,
      },
    });
  }

  return publicIdentitySecurityEvent(created);
}

export async function upsertIdentityRiskScore({
  database = db(),
  organizationId,
  userId = null,
  subjectType = "user",
  subjectId = null,
  signals = [],
  status = IDENTITY_RISK_STATUSES.ACTIVE,
  expiresAt = null,
  auditContext = {},
} = {}) {
  if (!organizationId) throw new Error("organizationId is required");
  const computed = computeIdentityRiskScore(signals);
  const normalizedSubjectType = enumValue(subjectType, ["user", "client", "provider", "organization"], "subject type");
  const normalizedStatus = enumValue(status, Object.values(IDENTITY_RISK_STATUSES), "risk status");

  const [score] = await database
    .insert(identityRiskScores)
    .values({
      organizationId,
      userId,
      subjectType: normalizedSubjectType,
      subjectId: safeString(subjectId || userId || organizationId, 160),
      score: computed.score,
      severity: computed.severity,
      confidence: computed.confidence,
      status: normalizedStatus,
      recommendedAction: computed.recommendedAction,
      factors: computed.factors,
      lastSignalAt: computed.lastSignalAt,
      expiresAt,
    })
    .returning();

  await recordIdentityAuditEvent({
    database,
    organizationId,
    userId,
    actorUserId: auditContext.userId || null,
    eventType: IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_RISK_DETECTED,
    action: IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_RISK_DETECTED,
    result: AUDIT_RESULTS.SUCCESS,
    requestId: auditContext.requestId,
    ipAddress: auditContext.ipAddress,
    userAgent: auditContext.userAgent,
    metadata: {
      subjectType: normalizedSubjectType,
      severity: computed.severity,
      score: computed.score,
      recommendedAction: computed.recommendedAction,
    },
  });

  return publicIdentityRiskScore(score);
}

export function computeIdentityRiskScore(signals = []) {
  const normalized = normalizeSignals(signals);
  const score = clampScore(normalized.reduce((sum, signal) => sum + signal.weight, 0));
  const confidence = normalized.length
    ? Math.min(1, roundNumber(normalized.reduce((sum, signal) => sum + signal.confidence, 0) / normalized.length, 3))
    : 0;
  const severity = severityForScore(score);
  const recommendedAction = actionForScore(score);
  const lastSignalAt = normalized
    .map((signal) => signal.observedAt)
    .filter(Boolean)
    .sort((a, b) => b.getTime() - a.getTime())[0] || null;

  return {
    score,
    severity,
    confidence,
    recommendedAction,
    factors: normalized.map((signal) => ({
      type: signal.type,
      weight: signal.weight,
      confidence: signal.confidence,
      summary: signal.summary,
      observedAt: signal.observedAt ? signal.observedAt.toISOString() : null,
    })),
    lastSignalAt,
  };
}

export async function createIdentityAccessReview({
  database = db(),
  organizationId,
  name,
  reviewType = ACCESS_REVIEW_TYPES.PERIODIC,
  status = ACCESS_REVIEW_STATUSES.OPEN,
  scope = {},
  summary = null,
  findings = [],
  createdByUserId = null,
  assignedToUserId = null,
  dueAt = null,
  metadata = {},
  auditContext = {},
} = {}) {
  if (!organizationId) throw new Error("organizationId is required");
  const normalized = {
    organizationId,
    name: requiredString(name || defaultReviewName(reviewType), "review name", 160),
    reviewType: enumValue(reviewType, Object.values(ACCESS_REVIEW_TYPES), "access review type"),
    status: enumValue(status, Object.values(ACCESS_REVIEW_STATUSES), "access review status"),
    scope: sanitizeIdentityMetadata(scope),
    summary: safeString(summary, 4000),
    findings: sanitizeFindings(findings),
    createdByUserId,
    assignedToUserId,
    dueAt: nullableDate(dueAt),
    metadata: sanitizeIdentityMetadata(metadata),
  };

  const [review] = await database.insert(identityAccessReviews).values(normalized).returning();

  await recordIdentityAuditEvent({
    database,
    organizationId,
    actorUserId: auditContext.userId || createdByUserId,
    eventType: IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_REVIEW_CREATED,
    action: IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_REVIEW_CREATED,
    result: AUDIT_RESULTS.SUCCESS,
    requestId: auditContext.requestId,
    ipAddress: auditContext.ipAddress,
    userAgent: auditContext.userAgent,
    metadata: {
      reviewType: normalized.reviewType,
      status: normalized.status,
    },
  });

  return publicIdentityAccessReview(review);
}

export async function completeIdentityAccessReview({
  database = db(),
  organizationId,
  reviewId,
  findings = [],
  summary = null,
  completedByUserId = null,
  auditContext = {},
} = {}) {
  if (!organizationId || !reviewId) throw new Error("organizationId and reviewId are required");
  const [review] = await database
    .update(identityAccessReviews)
    .set({
      status: ACCESS_REVIEW_STATUSES.COMPLETED,
      findings: sanitizeFindings(findings),
      summary: safeString(summary, 4000),
      completedAt: new Date(),
      updatedAt: new Date(),
    })
    .where(and(eq(identityAccessReviews.id, reviewId), eq(identityAccessReviews.organizationId, organizationId)))
    .returning();

  await recordIdentityAuditEvent({
    database,
    organizationId,
    actorUserId: auditContext.userId || completedByUserId,
    eventType: IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_REVIEW_COMPLETED,
    action: IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_REVIEW_COMPLETED,
    result: review ? AUDIT_RESULTS.SUCCESS : AUDIT_RESULTS.DENIED,
    requestId: auditContext.requestId,
    ipAddress: auditContext.ipAddress,
    userAgent: auditContext.userAgent,
    metadata: { outcome: review ? "completed" : "not_found" },
  });

  if (!review) throw new Error("access review is not available");
  return publicIdentityAccessReview(review);
}

export async function createIdentityComplianceReport({
  database = db(),
  organizationId,
  reportType = IDENTITY_COMPLIANCE_REPORT_TYPES.USER_INVENTORY,
  windowStart = null,
  windowEnd = null,
  generatedByUserId = null,
  metadata = {},
  auditContext = {},
} = {}) {
  if (!organizationId) throw new Error("organizationId is required");
  const type = enumValue(reportType, Object.values(IDENTITY_COMPLIANCE_REPORT_TYPES), "identity compliance report type");
  const metrics = await getIdentityComplianceMetrics({ database, organizationId, reportType: type });
  const findings = complianceFindings(type, metrics);

  const [report] = await database
    .insert(identityComplianceReports)
    .values({
      organizationId,
      reportType: type,
      status: "generated",
      windowStart: nullableDate(windowStart),
      windowEnd: nullableDate(windowEnd),
      generatedByUserId,
      metrics,
      findings,
      metadata: sanitizeIdentityMetadata(metadata),
    })
    .returning();

  await recordIdentityAuditEvent({
    database,
    organizationId,
    actorUserId: auditContext.userId || generatedByUserId,
    eventType: IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_POLICY_CHANGED,
    action: "identity.compliance_report.generated",
    result: AUDIT_RESULTS.SUCCESS,
    requestId: auditContext.requestId,
    ipAddress: auditContext.ipAddress,
    userAgent: auditContext.userAgent,
    metadata: { reportType: type },
  });

  return publicIdentityComplianceReport(report);
}

export async function getIdentitySecurityDashboard({ database = db(), organizationId, filters = {} } = {}) {
  if (!organizationId) throw new Error("organizationId is required");
  const query = normalizeQuery(filters);
  const eventWhere = and(
    eq(identitySecurityEvents.organizationId, organizationId),
    gte(identitySecurityEvents.createdAt, query.since),
    lte(identitySecurityEvents.createdAt, query.until),
  );

  const [activity, mfaAdoption, ssoHealth, scimHealth, riskyIdentities, accessReviews, complianceReports, recentEvents] =
    await Promise.all([
      identityActivity(database, eventWhere),
      getMfaAdoption(database, organizationId),
      getSsoHealth(database, organizationId),
      getScimHealth(database, organizationId),
      listIdentityRiskScores({ database, organizationId, filters: { status: "active", limit: 10 } }),
      listIdentityAccessReviews({ database, organizationId, filters: { limit: 10 } }),
      listIdentityComplianceReports({ database, organizationId, filters: { limit: 10 } }),
      listIdentitySecurityEvents({ database, organizationId, filters: { ...query, limit: 10 } }),
    ]);

  const activeRiskCount = riskyIdentities.items.length;
  const openReviewCount = accessReviews.items.filter((review) => ["open", "in_review"].includes(review.status)).length;

  return {
    window: query.window,
    executive: {
      identitySecurityScore: clampScore(100 - activeRiskCount * 8 - openReviewCount * 4 - activity.failedLogins * 2),
      riskyIdentities: activeRiskCount,
      openAccessReviews: openReviewCount,
      mfaAdoptionRate: mfaAdoption.adoptionRate,
      ssoFailureRate: ssoHealth.failureRate,
      scimFailureRate: scimHealth.failureRate,
    },
    authenticationActivity: activity,
    mfaAdoption,
    ssoHealth,
    scimHealth,
    riskyIdentities: riskyIdentities.items,
    accessReviews: accessReviews.items,
    complianceReports: complianceReports.items,
    recentEvents: recentEvents.items,
  };
}

export async function listIdentitySecurityEvents({ database = db(), organizationId, filters = {} } = {}) {
  if (!organizationId) throw new Error("organizationId is required");
  const query = normalizeQuery(filters);
  const predicates = [
    eq(identitySecurityEvents.organizationId, organizationId),
    gte(identitySecurityEvents.createdAt, query.since),
    lte(identitySecurityEvents.createdAt, query.until),
  ];
  if (filters.eventType) {
    predicates.push(eq(identitySecurityEvents.eventType, enumValue(filters.eventType, Object.values(IDENTITY_SECURITY_EVENT_TYPES), "identity security event type")));
  }
  if (filters.category) {
    predicates.push(eq(identitySecurityEvents.category, enumValue(filters.category, Object.values(IDENTITY_SECURITY_CATEGORIES), "identity security category")));
  }

  const rows = await database
    .select()
    .from(identitySecurityEvents)
    .where(and(...predicates))
    .orderBy(desc(identitySecurityEvents.createdAt), desc(identitySecurityEvents.id))
    .limit(query.limit + 1)
    .offset(query.offset);

  return pageResult(rows.map(publicIdentitySecurityEvent), query);
}

export async function listIdentityRiskScores({ database = db(), organizationId, filters = {} } = {}) {
  if (!organizationId) throw new Error("organizationId is required");
  const query = normalizeQuery(filters);
  const predicates = [eq(identityRiskScores.organizationId, organizationId), isNull(identityRiskScores.deletedAt)];
  if (filters.status) {
    predicates.push(eq(identityRiskScores.status, enumValue(filters.status, Object.values(IDENTITY_RISK_STATUSES), "risk status")));
  }

  const rows = await database
    .select()
    .from(identityRiskScores)
    .where(and(...predicates))
    .orderBy(desc(identityRiskScores.score), desc(identityRiskScores.updatedAt))
    .limit(query.limit + 1)
    .offset(query.offset);

  return pageResult(rows.map(publicIdentityRiskScore), query);
}

export async function listIdentityAccessReviews({ database = db(), organizationId, filters = {} } = {}) {
  if (!organizationId) throw new Error("organizationId is required");
  const query = normalizeQuery(filters);
  const predicates = [eq(identityAccessReviews.organizationId, organizationId), isNull(identityAccessReviews.deletedAt)];
  if (filters.status) {
    predicates.push(eq(identityAccessReviews.status, enumValue(filters.status, Object.values(ACCESS_REVIEW_STATUSES), "access review status")));
  }

  const rows = await database
    .select()
    .from(identityAccessReviews)
    .where(and(...predicates))
    .orderBy(desc(identityAccessReviews.updatedAt), desc(identityAccessReviews.id))
    .limit(query.limit + 1)
    .offset(query.offset);

  return pageResult(rows.map(publicIdentityAccessReview), query);
}

export async function listIdentityComplianceReports({ database = db(), organizationId, filters = {} } = {}) {
  if (!organizationId) throw new Error("organizationId is required");
  const query = normalizeQuery(filters);
  const rows = await database
    .select()
    .from(identityComplianceReports)
    .where(and(eq(identityComplianceReports.organizationId, organizationId), isNull(identityComplianceReports.deletedAt)))
    .orderBy(desc(identityComplianceReports.generatedAt), desc(identityComplianceReports.id))
    .limit(query.limit + 1)
    .offset(query.offset);

  return pageResult(rows.map(publicIdentityComplianceReport), query);
}

async function identityActivity(database, eventWhere) {
  const [summary] = await database
    .select({
      total: sql`count(*)`,
      successfulLogins: sql`sum(case when ${identitySecurityEvents.eventType} = 'login.success' then 1 else 0 end)`,
      failedLogins: sql`sum(case when ${identitySecurityEvents.eventType} = 'login.failure' then 1 else 0 end)`,
      mfaFailures: sql`sum(case when ${identitySecurityEvents.eventType} = 'mfa.failure' then 1 else 0 end)`,
      oauthFailures: sql`sum(case when ${identitySecurityEvents.eventType} = 'oauth.failure' then 1 else 0 end)`,
      ssoFailures: sql`sum(case when ${identitySecurityEvents.eventType} = 'sso.failure' then 1 else 0 end)`,
      scimFailures: sql`sum(case when ${identitySecurityEvents.eventType} = 'scim.provisioning.failure' then 1 else 0 end)`,
      suspiciousChanges: sql`sum(case when ${identitySecurityEvents.eventType} in ('identity.change.suspicious', 'identity.account.flagged') then 1 else 0 end)`,
      averageRiskScore: sql`avg(${identitySecurityEvents.riskScore})`,
    })
    .from(identitySecurityEvents)
    .where(eventWhere);

  return {
    total: numberValue(summary?.total),
    successfulLogins: numberValue(summary?.successfulLogins),
    failedLogins: numberValue(summary?.failedLogins),
    mfaFailures: numberValue(summary?.mfaFailures),
    oauthFailures: numberValue(summary?.oauthFailures),
    ssoFailures: numberValue(summary?.ssoFailures),
    scimFailures: numberValue(summary?.scimFailures),
    suspiciousChanges: numberValue(summary?.suspiciousChanges),
    averageRiskScore: roundNumber(summary?.averageRiskScore, 1),
  };
}

async function getMfaAdoption(database, organizationId) {
  const [membershipSummary] = await database
    .select({ total: sql`count(*)` })
    .from(organizationMemberships)
    .where(and(eq(organizationMemberships.organizationId, organizationId), eq(organizationMemberships.status, "active")));
  const [mfaSummary] = await database
    .select({ enabled: sql`count(distinct ${mfaMethods.userId})` })
    .from(mfaMethods)
    .where(and(eq(mfaMethods.organizationId, organizationId), eq(mfaMethods.status, "active"), isNull(mfaMethods.deletedAt)));

  const activeUsers = numberValue(membershipSummary?.total);
  const enabledUsers = numberValue(mfaSummary?.enabled);
  return {
    activeUsers,
    enabledUsers,
    missingUsers: Math.max(0, activeUsers - enabledUsers),
    adoptionRate: activeUsers ? Math.round((enabledUsers / activeUsers) * 100) : 100,
  };
}

async function getSsoHealth(database, organizationId) {
  const [providerSummary] = await database
    .select({
      total: sql`count(*)`,
      active: sql`sum(case when ${identityProviders.status} = 'active' and ${identityProviders.providerType} in ('saml', 'oidc') then 1 else 0 end)`,
    })
    .from(identityProviders)
    .where(eq(identityProviders.organizationId, organizationId));
  const [attemptSummary] = await database
    .select({
      total: sql`count(*)`,
      failed: sql`sum(case when ${ssoLoginAttempts.status} = 'failed' then 1 else 0 end)`,
    })
    .from(ssoLoginAttempts)
    .where(eq(ssoLoginAttempts.organizationId, organizationId));

  const attempts = numberValue(attemptSummary?.total);
  const failed = numberValue(attemptSummary?.failed);
  return {
    providers: numberValue(providerSummary?.total),
    activeProviders: numberValue(providerSummary?.active),
    attempts,
    failures: failed,
    failureRate: attempts ? roundNumber((failed / attempts) * 100, 1) : 0,
  };
}

async function getScimHealth(database, organizationId) {
  const [providerSummary] = await database
    .select({
      total: sql`count(*)`,
      active: sql`sum(case when ${scimProviders.status} = 'active' then 1 else 0 end)`,
    })
    .from(scimProviders)
    .where(and(eq(scimProviders.organizationId, organizationId), isNull(scimProviders.deletedAt)));
  const [syncSummary] = await database
    .select({
      total: sql`count(*)`,
      failed: sql`sum(case when ${scimSyncJobs.status} = 'failed' then 1 else 0 end)`,
      running: sql`sum(case when ${scimSyncJobs.status} = 'running' then 1 else 0 end)`,
    })
    .from(scimSyncJobs)
    .where(eq(scimSyncJobs.organizationId, organizationId));

  const syncs = numberValue(syncSummary?.total);
  const failed = numberValue(syncSummary?.failed);
  return {
    providers: numberValue(providerSummary?.total),
    activeProviders: numberValue(providerSummary?.active),
    syncs,
    failures: failed,
    running: numberValue(syncSummary?.running),
    failureRate: syncs ? roundNumber((failed / syncs) * 100, 1) : 0,
  };
}

async function getIdentityComplianceMetrics({ database, organizationId, reportType }) {
  const [usersSummary] = await database
    .select({
      totalUsers: sql`count(distinct ${organizationMemberships.userId})`,
      activeMemberships: sql`sum(case when ${organizationMemberships.status} = 'active' then 1 else 0 end)`,
    })
    .from(organizationMemberships)
    .where(eq(organizationMemberships.organizationId, organizationId));
  const [privilegedSummary] = await database
    .select({ privilegedAssignments: sql`count(*)` })
    .from(userRoles)
    .where(sql`${userRoles.roleId} is not null`);
  const [auditSummary] = await database
    .select({ identityAuditEvents: sql`count(*)` })
    .from(identityAuditEvents)
    .where(eq(identityAuditEvents.organizationId, organizationId));

  return {
    reportType,
    totalUsers: numberValue(usersSummary?.totalUsers),
    activeMemberships: numberValue(usersSummary?.activeMemberships),
    privilegedAssignments: numberValue(privilegedSummary?.privilegedAssignments),
    identityAuditEvents: numberValue(auditSummary?.identityAuditEvents),
  };
}

function complianceFindings(reportType, metrics) {
  const findings = [];
  if (reportType === IDENTITY_COMPLIANCE_REPORT_TYPES.MFA_STATUS && metrics.totalUsers > 0) {
    findings.push({ severity: "medium", summary: "MFA adoption should be reviewed against enterprise policy" });
  }
  if (reportType === IDENTITY_COMPLIANCE_REPORT_TYPES.PRIVILEGED_ACCESS && metrics.privilegedAssignments > 0) {
    findings.push({ severity: "medium", summary: "Privileged assignments require periodic owner review" });
  }
  if (!findings.length) {
    findings.push({ severity: "low", summary: "No blocking identity compliance findings generated" });
  }
  return findings;
}

function normalizeIdentitySecurityEvent(input) {
  if (!input.organizationId) throw new Error("organizationId is required");
  const riskScore = clampScore(input.riskScore);
  return {
    organizationId: input.organizationId,
    userId: input.userId,
    actorUserId: input.actorUserId,
    providerId: input.providerId,
    scimProviderId: input.scimProviderId,
    auditEventId: input.auditEventId,
    eventType: enumValue(input.eventType, Object.values(IDENTITY_SECURITY_EVENT_TYPES), "identity security event type"),
    category: enumValue(input.category, Object.values(IDENTITY_SECURITY_CATEGORIES), "identity security category"),
    result: enumValue(input.result, Object.values(AUDIT_RESULTS), "identity security result"),
    severity: input.severity ? enumValue(input.severity, ["low", "medium", "high", "critical"], "severity") : severityForScore(riskScore),
    riskScore,
    action: input.action ? enumValue(input.action, Object.values(IDENTITY_SECURITY_ACTIONS), "identity security action") : actionForScore(riskScore),
    ipAddress: safeString(input.ipAddress, 45),
    userAgent: safeString(input.userAgent, 1024),
    source: safeString(input.source || "identity", 80),
    summary: safeString(input.summary, 4000),
    metadata: sanitizeIdentityMetadata(input.metadata),
  };
}

function isRiskEvent(event) {
  return event.riskScore >= 50 || event.eventType === IDENTITY_SECURITY_EVENT_TYPES.RISK_DETECTED || event.eventType === IDENTITY_SECURITY_EVENT_TYPES.ACCOUNT_FLAGGED;
}

function normalizeSignals(signals) {
  if (!Array.isArray(signals)) throw new Error("identity risk signals must be an array");
  return signals.slice(0, 20).map((signal) => {
    const weight = Math.max(0, Math.min(100, Number(signal.weight || 0)));
    const confidence = Math.max(0, Math.min(1, Number(signal.confidence ?? 0.5)));
    return {
      type: safeString(signal.type || "identity_signal", 80),
      weight,
      confidence,
      summary: safeString(signal.summary || signal.type || "Identity risk signal", 400),
      observedAt: nullableDate(signal.observedAt) || new Date(),
    };
  });
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
    window: {
      since: since.toISOString(),
      until: until.toISOString(),
    },
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

function publicIdentitySecurityEvent(event = {}) {
  return {
    id: event.id,
    organizationId: event.organizationId,
    userId: event.userId || null,
    actorUserId: event.actorUserId || null,
    eventType: event.eventType,
    category: event.category,
    result: event.result,
    severity: event.severity,
    riskScore: numberValue(event.riskScore),
    action: event.action,
    source: event.source,
    summary: event.summary || null,
    metadata: event.metadata || {},
    createdAt: event.createdAt || null,
  };
}

function publicIdentityRiskScore(score = {}) {
  return {
    id: score.id,
    organizationId: score.organizationId,
    userId: score.userId || null,
    subjectType: score.subjectType,
    subjectId: score.subjectId || null,
    score: numberValue(score.score),
    severity: score.severity,
    confidence: roundNumber(score.confidence, 3),
    status: score.status,
    recommendedAction: score.recommendedAction,
    factors: Array.isArray(score.factors) ? score.factors : [],
    lastSignalAt: score.lastSignalAt || null,
    expiresAt: score.expiresAt || null,
    updatedAt: score.updatedAt || null,
  };
}

function publicIdentityAccessReview(review = {}) {
  return {
    id: review.id,
    organizationId: review.organizationId,
    name: review.name,
    reviewType: review.reviewType,
    status: review.status,
    scope: review.scope || {},
    summary: review.summary || null,
    findings: Array.isArray(review.findings) ? review.findings : [],
    dueAt: review.dueAt || null,
    completedAt: review.completedAt || null,
    updatedAt: review.updatedAt || null,
  };
}

function publicIdentityComplianceReport(report = {}) {
  return {
    id: report.id,
    organizationId: report.organizationId,
    reportType: report.reportType,
    status: report.status,
    windowStart: report.windowStart || null,
    windowEnd: report.windowEnd || null,
    generatedAt: report.generatedAt || null,
    metrics: report.metrics || {},
    findings: Array.isArray(report.findings) ? report.findings : [],
    evidenceRef: report.evidenceRef || null,
  };
}

function sanitizeFindings(findings) {
  if (findings == null) return [];
  if (!Array.isArray(findings)) throw new Error("findings must be an array");
  return findings.slice(0, 200).map((finding) => sanitizeIdentityMetadata(finding));
}

function severityForScore(score) {
  if (score >= 85) return "critical";
  if (score >= 70) return "high";
  if (score >= 40) return "medium";
  return "low";
}

function actionForScore(score) {
  if (score >= 85) return IDENTITY_SECURITY_ACTIONS.ALERT;
  if (score >= 70) return IDENTITY_SECURITY_ACTIONS.RESTRICT_SESSION;
  if (score >= 40) return IDENTITY_SECURITY_ACTIONS.REQUIRE_MFA;
  return IDENTITY_SECURITY_ACTIONS.MONITOR;
}

function defaultReviewName(reviewType) {
  return `${String(reviewType || "periodic").replace(/_/g, " ")} review`;
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

function nullableDate(value) {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) throw new Error("date filter is invalid");
  return date;
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

function clampScore(value) {
  const number = Number(value || 0);
  if (!Number.isFinite(number)) return 0;
  return Math.max(0, Math.min(100, Math.round(number)));
}
