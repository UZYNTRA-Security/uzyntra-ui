import assert from "node:assert/strict";
import {
  AUDIT_EVENT_TYPES,
} from "../src/lib/audit/index.js";
import {
  IDENTITY_AUDIT_EVENT_TYPES,
} from "../src/lib/identity/index.js";
import {
  BREAK_GLASS_STATUSES,
  IDENTITY_AUDIT_REPORT_TYPES,
  IDENTITY_EXPORT_FORMATS,
  IDENTITY_METRIC_TYPES,
  RECOVERY_EVENT_TYPES,
  RECOVERY_WORKFLOW_TYPES,
  createBreakGlassAdministrator,
  createIdentityAuditReport,
  createIdentityRecoveryWorkflow,
  getIdentityObservabilityDashboard,
  listIdentityMetrics,
  listRecoveryState,
  recordIdentityMetric,
} from "../src/lib/identity-hardening/index.js";
import { PERMISSIONS, DEFAULT_ROLES } from "../src/lib/rbac/catalog.js";

process.env.AUTH_API_KEY_SECRET = "0123456789abcdef0123456789abcdef";
process.env.AUTH_SESSION_SECRET = "abcdef0123456789abcdef0123456789";

assert.equal(AUDIT_EVENT_TYPES.IDENTITY_REPORT_GENERATED, "identity.report.generated");
assert.equal(AUDIT_EVENT_TYPES.IDENTITY_RECOVERY_REQUESTED, "identity.recovery.requested");
assert.equal(AUDIT_EVENT_TYPES.BREAK_GLASS_ADMIN_CREATED, "identity.break_glass.created");
assert.equal(IDENTITY_AUDIT_EVENT_TYPES.BREAK_GLASS_ADMIN_REVOKED, "identity.break_glass.revoked");

assert.equal(PERMISSIONS.IDENTITY_REPORTS_READ, "identity_reports.read");
assert.equal(PERMISSIONS.IDENTITY_REPORTS_MANAGE, "identity_reports.manage");
assert.equal(PERMISSIONS.IDENTITY_RECOVERY_MANAGE, "identity_recovery.manage");
const owner = DEFAULT_ROLES.find((role) => role.name === "Owner");
const securityAdmin = DEFAULT_ROLES.find((role) => role.name === "Security Admin");
assert.ok(owner.permissions.includes(PERMISSIONS.IDENTITY_RECOVERY_MANAGE));
assert.ok(securityAdmin.permissions.includes(PERMISSIONS.IDENTITY_REPORTS_MANAGE));

const metricWrites = [];
const metric = await recordIdentityMetric({
  database: fakeDatabase({ writes: metricWrites }),
  organizationId: "org-1",
  metricType: IDENTITY_METRIC_TYPES.LOGIN_SUCCESS_RATE,
  metricValue: 98.5,
  numerator: 197,
  denominator: 200,
  bucketStart: "2026-09-02T00:00:00.000Z",
  bucketEnd: "2026-09-02T01:00:00.000Z",
  dimensions: { provider: "password" },
});
assert.equal(metric.metricType, "login_success_rate");
assert.equal(metric.status, "healthy");
assert.equal(metric.numerator, 197);
assert.equal(JSON.stringify(metricWrites).includes("plain-secret"), false);

await assert.rejects(
  () =>
    recordIdentityMetric({
      database: fakeDatabase(),
      organizationId: "org-1",
      metricType: IDENTITY_METRIC_TYPES.LOGIN_FAILURE_RATE,
      metricValue: 10,
      bucketStart: "2026-09-02T00:00:00.000Z",
      bucketEnd: "2026-09-02T01:00:00.000Z",
      metadata: { token: "plain-secret" },
    }),
  /sensitive field/,
);

const reportWrites = [];
const report = await createIdentityAuditReport({
  database: fakeDatabase({
    writes: reportWrites,
    selectQueue: [[identityAuditRecord(), identityAuditRecord({ id: "audit-2", eventType: "mfa.enabled" })]],
  }),
  organizationId: "org-1",
  reportType: IDENTITY_AUDIT_REPORT_TYPES.AUTHENTICATION_ACTIVITY,
  exportFormat: IDENTITY_EXPORT_FORMATS.CSV,
  generatedByUserId: "owner-1",
});
assert.equal(report.reportType, "authentication_activity");
assert.equal(report.exportFormat, "csv");
assert.equal(report.rowCount, 2);
assert.equal(typeof report.reportPayload.data, "string");
assert.ok(reportWrites.some((write) => write.eventType === IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_REPORT_GENERATED));

const recoveryWrites = [];
const workflow = await createIdentityRecoveryWorkflow({
  database: fakeDatabase({ writes: recoveryWrites }),
  organizationId: "org-1",
  targetUserId: "user-1",
  workflowType: RECOVERY_WORKFLOW_TYPES.LOCKOUT_RECOVERY,
  reason: "User locked out during IdP outage",
  requestedByUserId: "owner-1",
});
assert.equal(workflow.workflowType, "lockout_recovery");
assert.equal(workflow.status, "requested");
assert.equal(workflow.mfaRequired, true);
assert.equal(workflow.approvalRequired, true);
assert.ok(recoveryWrites.some((write) => write.eventType === RECOVERY_EVENT_TYPES.REQUESTED));
assert.ok(recoveryWrites.some((write) => write.eventType === IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_RECOVERY_REQUESTED));

const breakGlassWrites = [];
const breakGlass = await createBreakGlassAdministrator({
  database: fakeDatabase({ writes: breakGlassWrites }),
  organizationId: "org-1",
  userId: "admin-1",
  reason: "Emergency administrator readiness",
  approvedByUserId: "owner-1",
  expiresAt: "2026-09-03T00:00:00.000Z",
  status: BREAK_GLASS_STATUSES.DISABLED,
});
assert.equal(breakGlass.status, "disabled");
assert.equal(breakGlass.mfaRequired, true);
assert.ok(breakGlassWrites.some((write) => write.eventType === RECOVERY_EVENT_TYPES.BREAK_GLASS_CREATED));

const metricsPage = await listIdentityMetrics({
  database: fakeDatabase({ selectQueue: [[metricRecord(), metricRecord({ id: "metric-2" })]] }),
  organizationId: "org-1",
  filters: { limit: 1 },
});
assert.equal(metricsPage.items.length, 1);
assert.equal(metricsPage.pageInfo.hasMore, true);

const recoveryState = await listRecoveryState({
  database: fakeDatabase({
    selectQueue: [[workflowRecord()], [breakGlassRecord()], [recoveryEventRecord()]],
  }),
  organizationId: "org-1",
});
assert.equal(recoveryState.workflows.length, 1);
assert.equal(recoveryState.breakGlassAdministrators[0].mfaRequired, true);

const dashboard = await getIdentityObservabilityDashboard({
  database: fakeDatabase({
    selectQueue: [
      [{ success: 9, failure: 1, mfaFailure: 2, total: 12 }],
      [{ total: 4, failed: 1 }],
      [{ total: 5, failed: 0 }],
      [{ total: 10, failed: 1, running: 1 }],
      [{ total: 2, active: 1 }],
      [{ total: 10 }],
      [{ enabled: 8 }],
      [{ active: 2, high: 1, maxScore: 88 }],
      [riskRecord()],
      [reportRecord()],
      [workflowRecord()],
      [breakGlassRecord()],
      [recoveryEventRecord()],
      [metricRecord()],
    ],
  }),
  organizationId: "org-1",
});
assert.ok(dashboard.window.since);
assert.equal(typeof dashboard.executive.loginSuccessRate, "number");
assert.equal(typeof dashboard.executive.mfaAdoptionRate, "number");
assert.ok(Array.isArray(dashboard.reports));
assert.ok(Array.isArray(dashboard.recovery.workflows));

console.log("phase 9 identity hardening tests passed");

function fakeDatabase({ selectQueue = [], writes = [] } = {}) {
  return {
    select() {
      return chain({ result: () => selectQueue.shift() || [] });
    },
    insert() {
      return {
        values(value) {
          writes.push(value);
          const firstValue = Array.isArray(value) ? value[0] : value;
          return {
            async returning() {
              return [insertResult(firstValue)];
            },
          };
        },
      };
    },
    update() {
      return {
        set(value) {
          writes.push(value);
          return chain({ result: () => [insertResult(value)] });
        },
      };
    },
    transaction(callback) {
      return callback(this);
    },
  };
}

function chain({ result }) {
  return {
    from() {
      return this;
    },
    innerJoin() {
      return this;
    },
    leftJoin() {
      return this;
    },
    where() {
      return this;
    },
    groupBy() {
      return this;
    },
    orderBy() {
      return this;
    },
    limit() {
      return this;
    },
    offset() {
      return this;
    },
    async returning() {
      return result();
    },
    then(resolve, reject) {
      return Promise.resolve(result()).then(resolve, reject);
    },
  };
}

function insertResult(value) {
  return {
    id: value.id || "generated-id",
    createdAt: value.createdAt || new Date(),
    updatedAt: value.updatedAt || new Date(),
    generatedAt: value.generatedAt || new Date(),
    requestedAt: value.requestedAt || new Date(),
    ...value,
  };
}

function identityAuditRecord(overrides = {}) {
  return {
    id: "audit-1",
    eventType: "auth.login.success",
    action: "auth.login.success",
    result: "success",
    requestId: "request-1",
    createdAt: new Date("2026-09-02T00:00:00.000Z"),
    ...overrides,
  };
}

function metricRecord(overrides = {}) {
  return {
    id: "metric-1",
    organizationId: "org-1",
    metricType: "login_success_rate",
    metricValue: 99,
    numerator: 99,
    denominator: 100,
    status: "healthy",
    bucketStart: new Date(),
    bucketEnd: new Date(),
    dimensions: {},
    ...overrides,
  };
}

function workflowRecord(overrides = {}) {
  return {
    id: "workflow-1",
    organizationId: "org-1",
    workflowType: "account_recovery",
    status: "requested",
    reason: "Recovery test",
    mfaRequired: true,
    approvalRequired: true,
    requestedAt: new Date(),
    ...overrides,
  };
}

function breakGlassRecord(overrides = {}) {
  return {
    id: "break-glass-1",
    organizationId: "org-1",
    userId: "admin-1",
    status: "disabled",
    reason: "Emergency readiness",
    mfaRequired: true,
    expiresAt: new Date(),
    ...overrides,
  };
}

function recoveryEventRecord(overrides = {}) {
  return {
    id: "recovery-event-1",
    organizationId: "org-1",
    eventType: "recovery.requested",
    result: "success",
    createdAt: new Date(),
    ...overrides,
  };
}

function riskRecord(overrides = {}) {
  return {
    id: "risk-1",
    subjectType: "user",
    subjectId: "user-1",
    score: 88,
    severity: "critical",
    recommendedAction: "alert",
    updatedAt: new Date(),
    ...overrides,
  };
}

function reportRecord(overrides = {}) {
  return {
    id: "report-1",
    organizationId: "org-1",
    reportType: "identity_evidence",
    exportFormat: "json",
    status: "generated",
    rowCount: 4,
    generatedAt: new Date(),
    reportPayload: {},
    ...overrides,
  };
}
