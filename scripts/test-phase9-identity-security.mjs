import assert from "node:assert/strict";
import {
  AUDIT_EVENT_TYPES,
} from "../src/lib/audit/index.js";
import {
  IDENTITY_AUDIT_EVENT_TYPES,
} from "../src/lib/identity/index.js";
import {
  ACCESS_REVIEW_STATUSES,
  ACCESS_REVIEW_TYPES,
  IDENTITY_COMPLIANCE_REPORT_TYPES,
  IDENTITY_RISK_STATUSES,
  IDENTITY_SECURITY_ACTIONS,
  IDENTITY_SECURITY_CATEGORIES,
  IDENTITY_SECURITY_EVENT_TYPES,
  computeIdentityRiskScore,
  createIdentityAccessReview,
  createIdentityComplianceReport,
  listIdentityAccessReviews,
  listIdentityRiskScores,
  recordIdentitySecurityEvent,
  upsertIdentityRiskScore,
} from "../src/lib/identity-security/index.js";
import { PERMISSIONS, DEFAULT_ROLES } from "../src/lib/rbac/catalog.js";

process.env.AUTH_API_KEY_SECRET = "0123456789abcdef0123456789abcdef";
process.env.AUTH_SESSION_SECRET = "abcdef0123456789abcdef0123456789";

assert.equal(AUDIT_EVENT_TYPES.IDENTITY_RISK_DETECTED, "identity.risk.detected");
assert.equal(AUDIT_EVENT_TYPES.IDENTITY_REVIEW_CREATED, "identity.review.created");
assert.equal(AUDIT_EVENT_TYPES.IDENTITY_REVIEW_COMPLETED, "identity.review.completed");
assert.equal(AUDIT_EVENT_TYPES.IDENTITY_ACCOUNT_FLAGGED, "identity.account.flagged");
assert.equal(AUDIT_EVENT_TYPES.IDENTITY_POLICY_CHANGED, "identity.policy.changed");
assert.equal(IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_POLICY_CHANGED, "identity.policy.changed");

assert.equal(PERMISSIONS.IDENTITY_SECURITY_READ, "identity_security.read");
assert.equal(PERMISSIONS.IDENTITY_SECURITY_MANAGE, "identity_security.manage");
assert.equal(PERMISSIONS.ACCESS_REVIEWS_READ, "access_reviews.read");
assert.equal(PERMISSIONS.ACCESS_REVIEWS_MANAGE, "access_reviews.manage");
const owner = DEFAULT_ROLES.find((role) => role.name === "Owner");
const securityAdmin = DEFAULT_ROLES.find((role) => role.name === "Security Admin");
assert.ok(owner.permissions.includes(PERMISSIONS.IDENTITY_SECURITY_MANAGE));
assert.ok(securityAdmin.permissions.includes(PERMISSIONS.ACCESS_REVIEWS_MANAGE));

const computed = computeIdentityRiskScore([
  { type: "failed_login_spike", weight: 35, confidence: 0.8, summary: "Failed login spike" },
  { type: "new_device", weight: 20, confidence: 0.6, summary: "New device" },
  { type: "privilege_change", weight: 30, confidence: 0.9, summary: "New privileged role" },
]);
assert.equal(computed.score, 85);
assert.equal(computed.severity, "critical");
assert.equal(computed.recommendedAction, IDENTITY_SECURITY_ACTIONS.ALERT);
assert.equal(computed.factors.length, 3);

const eventWrites = [];
const event = await recordIdentitySecurityEvent({
  database: fakeDatabase({ writes: eventWrites }),
  organizationId: "org-1",
  userId: "user-1",
  eventType: IDENTITY_SECURITY_EVENT_TYPES.MFA_FAILURE,
  category: IDENTITY_SECURITY_CATEGORIES.MFA,
  result: "failure",
  riskScore: 55,
  summary: "MFA failure burst",
  metadata: { failureCount: 5 },
  auditContext: { userId: "analyst-1", requestId: "request-1" },
});
assert.equal(event.organizationId, "org-1");
assert.equal(event.severity, "medium");
assert.equal(event.action, IDENTITY_SECURITY_ACTIONS.REQUIRE_MFA);
assert.ok(eventWrites.some((write) => write.eventType === IDENTITY_SECURITY_EVENT_TYPES.MFA_FAILURE));
assert.ok(eventWrites.some((write) => write.eventType === IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_RISK_DETECTED));

await assert.rejects(
  () =>
    recordIdentitySecurityEvent({
      database: fakeDatabase(),
      organizationId: "org-1",
      eventType: IDENTITY_SECURITY_EVENT_TYPES.LOGIN_FAILURE,
      category: IDENTITY_SECURITY_CATEGORIES.AUTHENTICATION,
      metadata: { token: "secret-token" },
    }),
  /sensitive field/,
);

const riskWrites = [];
const risk = await upsertIdentityRiskScore({
  database: fakeDatabase({ writes: riskWrites }),
  organizationId: "org-1",
  userId: "user-1",
  signals: [
    { type: "impossible_travel", weight: 45, confidence: 0.7 },
    { type: "sso_failure_spike", weight: 25, confidence: 0.8 },
  ],
  status: IDENTITY_RISK_STATUSES.ACTIVE,
});
assert.equal(risk.score, 70);
assert.equal(risk.severity, "high");
assert.equal(risk.recommendedAction, IDENTITY_SECURITY_ACTIONS.RESTRICT_SESSION);
assert.ok(riskWrites.some((write) => Array.isArray(write.factors)));

const reviewWrites = [];
const review = await createIdentityAccessReview({
  database: fakeDatabase({ writes: reviewWrites }),
  organizationId: "org-1",
  name: "Privileged access review",
  reviewType: ACCESS_REVIEW_TYPES.PRIVILEGED,
  status: ACCESS_REVIEW_STATUSES.OPEN,
  scope: { roles: ["Owner", "Security Admin"] },
  createdByUserId: "owner-1",
});
assert.equal(review.reviewType, "privileged");
assert.equal(review.status, "open");
assert.ok(reviewWrites.some((write) => write.eventType === IDENTITY_AUDIT_EVENT_TYPES.IDENTITY_REVIEW_CREATED));

const reportWrites = [];
const report = await createIdentityComplianceReport({
  database: fakeDatabase({
    writes: reportWrites,
    selectQueue: [
      [{ totalUsers: 10, activeMemberships: 9 }],
      [{ privilegedAssignments: 3 }],
      [{ identityAuditEvents: 12 }],
    ],
  }),
  organizationId: "org-1",
  reportType: IDENTITY_COMPLIANCE_REPORT_TYPES.PRIVILEGED_ACCESS,
  generatedByUserId: "owner-1",
});
assert.equal(report.reportType, "privileged_access");
assert.equal(report.metrics.privilegedAssignments, 3);
assert.ok(report.findings.length >= 1);
assert.equal(JSON.stringify(reportWrites).includes("secret-token"), false);

const riskPage = await listIdentityRiskScores({
  database: fakeDatabase({ selectQueue: [[riskRecord(), riskRecord({ id: "risk-2" })]] }),
  organizationId: "org-1",
  filters: { limit: 1 },
});
assert.equal(riskPage.items.length, 1);
assert.equal(riskPage.pageInfo.hasMore, true);

const reviewPage = await listIdentityAccessReviews({
  database: fakeDatabase({ selectQueue: [[reviewRecord()]] }),
  organizationId: "org-1",
});
assert.equal(reviewPage.items[0].name, "Quarterly access review");

console.log("phase 9 identity security tests passed");

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
          return chain({ result: () => [updateResult(value)] });
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
    ...value,
  };
}

function updateResult(value) {
  return {
    id: "updated-id",
    organizationId: "org-1",
    name: "Updated review",
    reviewType: "periodic",
    status: "completed",
    scope: {},
    findings: [],
    createdAt: new Date(),
    updatedAt: new Date(),
    ...value,
  };
}

function riskRecord(overrides = {}) {
  return {
    id: "risk-1",
    organizationId: "org-1",
    userId: "user-1",
    subjectType: "user",
    subjectId: "user-1",
    score: 82,
    severity: "high",
    confidence: 0.75,
    status: "active",
    recommendedAction: "restrict_session",
    factors: [],
    updatedAt: new Date(),
    ...overrides,
  };
}

function reviewRecord(overrides = {}) {
  return {
    id: "review-1",
    organizationId: "org-1",
    name: "Quarterly access review",
    reviewType: "periodic",
    status: "open",
    scope: {},
    findings: [],
    updatedAt: new Date(),
    ...overrides,
  };
}
