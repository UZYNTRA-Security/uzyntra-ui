import { sql } from "drizzle-orm";
import {
  boolean,
  check,
  foreignKey,
  index,
  integer,
  jsonb,
  pgTable,
  primaryKey,
  real,
  text,
  timestamp,
  uniqueIndex,
  uuid,
  varchar,
} from "drizzle-orm/pg-core";

const timestamps = {
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
};

const deletedAt = {
  deletedAt: timestamp("deleted_at", { withTimezone: true }),
};

const lifecycleStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'disabled', 'deleted')`);

const apiKeyStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'revoked', 'expired', 'disabled', 'deleted')`);

const invitationStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('pending', 'accepted', 'revoked', 'expired')`);

const enrollmentTokenStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('pending', 'used', 'revoked', 'expired')`);

const securityEventSeverityCheck = (name, table) =>
  check(name, sql`${table.severity} in ('low', 'medium', 'high', 'critical')`);

const securityEventActionCheck = (name, table) =>
  check(name, sql`${table.actionTaken} in ('blocked', 'allowed', 'rate_limited', 'challenged')`);

const alertRuleStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'disabled', 'deleted')`);

const alertStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('open', 'acknowledged', 'resolved', 'suppressed')`);

const incidentStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('open', 'investigating', 'contained', 'resolved')`);

const notificationChannelStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'disabled', 'deleted')`);

const deliveryStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('pending', 'claimed', 'delivered', 'retry', 'failed', 'blocked')`);

const detectorConfigStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'observe', 'disabled', 'deleted')`);

const detectionFindingStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('open', 'acknowledged', 'suppressed', 'resolved')`);

const detectorFeedbackTypeCheck = (name, table) =>
  check(name, sql`${table.feedbackType} in ('true_positive', 'false_positive', 'expected_behavior', 'duplicate', 'needs_tuning', 'customer_exception')`);

const threatSourceStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'observe', 'disabled', 'deleted')`);

const threatSourceHealthCheck = (name, table) =>
  check(name, sql`${table.healthStatus} in ('healthy', 'degraded', 'failed', 'unknown')`);

const threatIndicatorTypeCheck = (name, table) =>
  check(name, sql`${table.indicatorType} in ('ip', 'cidr', 'domain', 'url', 'hash', 'asn', 'user_agent')`);

const threatReviewStatusCheck = (name, table) =>
  check(name, sql`${table.reviewStatus} in ('unreviewed', 'confirmed', 'false_positive', 'trusted', 'expired')`);

const zeroTrustPolicyStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'disabled', 'deleted')`);

const zeroTrustPolicyModeCheck = (name, table) =>
  check(name, sql`${table.mode} in ('observe', 'simulate', 'enforce')`);

const zeroTrustPolicyVersionStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('draft', 'active', 'retired', 'rolled_back')`);

const policyDecisionCheck = (name, table) =>
  check(name, sql`${table.decision} in ('allow', 'challenge', 'rate_limit', 'block', 'quarantine')`);

const zeroTrustFailBehaviorCheck = (name, table) =>
  check(name, sql`${table.failBehavior} in ('fail_open', 'fail_closed')`);

const emergencyBypassStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'expired', 'revoked')`);

const protectionRuleStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'disabled', 'deleted')`);

const protectionActionCheck = (name, table) =>
  check(name, sql`${table.action} in ('allow', 'challenge', 'rate_limit', 'block', 'quarantine', 'credential_suspend')`);

const protectionModeCheck = (name, table) =>
  check(name, sql`${table.mode} in ('observe', 'simulation', 'enforcement')`);

const protectionListTypeCheck = (name, table) =>
  check(name, sql`${table.entryType} in ('ip', 'cidr', 'route', 'credential', 'detector', 'indicator')`);

const credentialProtectionStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'suspicious', 'restricted', 'suspended', 'released')`);

const enforcementOutcomeCheck = (name, table) =>
  check(name, sql`${table.outcome} in ('observed', 'simulated', 'applied', 'failed', 'bypassed')`);

const policySimulationModeCheck = (name, table) =>
  check(name, sql`${table.mode} in ('dry_run', 'shadow', 'what_if', 'historical_replay')`);

const policySimulationStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('queued', 'running', 'completed', 'failed', 'cancelled')`);

const policyTestCaseStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'disabled', 'deleted')`);

const policyChangeRequestStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('draft', 'requested', 'approved', 'rejected', 'expired', 'cancelled')`);

const soarPlaybookStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('draft', 'testing', 'active', 'disabled', 'deleted')`);

const soarRiskLevelCheck = (name, table) =>
  check(name, sql`${table.riskLevel} in ('low', 'medium', 'high', 'critical')`);

const soarTriggerTypeCheck = (name, table) =>
  check(name, sql`${table.triggerType} in ('security_event', 'detection_finding', 'correlation_event', 'threat_match', 'policy_decision', 'enforcement_event', 'incident', 'notification_delivery', 'simulation_result', 'manual')`);

const soarAutomationLevelCheck = (name, table) =>
  check(name, sql`${table.automationLevel} between 0 and 4`);

const soarRunStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('queued', 'running', 'approval_required', 'completed', 'failed', 'cancelled', 'skipped')`);

const soarApprovalStateCheck = (name, table) =>
  check(name, sql`${table.approvalState} in ('not_required', 'pending', 'approved', 'rejected', 'expired')`);

const soarResponseActionTypeCheck = (name, table) =>
  check(name, sql`${table.actionType} in ('block_indicator', 'create_incident', 'notify_security_team', 'request_approval', 'collect_evidence', 'quarantine_api_key', 'suspend_service_account', 'increase_rate_limit_restriction')`);

const soarResponseActionStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('recommended', 'pending', 'approval_required', 'approved', 'executing', 'completed', 'failed', 'skipped', 'rolled_back')`);

const investigationCaseStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('open', 'investigating', 'contained', 'resolved', 'closed')`);

const evidenceSourceTypeCheck = (name, table) =>
  check(name, sql`${table.sourceType} in ('security_event', 'detection_finding', 'correlation_event', 'threat_match', 'policy_decision', 'enforcement_event', 'incident', 'notification_delivery', 'simulation_result', 'automation_run', 'response_action', 'manual')`);

const aiSessionStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'archived', 'deleted')`);

const aiMessageRoleCheck = (name, table) =>
  check(name, sql`${table.role} in ('user', 'assistant', 'system')`);

const aiReportTypeCheck = (name, table) =>
  check(name, sql`${table.reportType} in ('executive', 'analyst', 'compliance', 'incident_summary', 'customer_security')`);

const aiFeedbackRatingCheck = (name, table) =>
  check(name, sql`${table.rating} in ('helpful', 'not_helpful', 'unsafe', 'incorrect', 'needs_detail')`);

const organizationRelationshipTypeCheck = (name, table) =>
  check(name, sql`${table.relationshipType} in ('mssp_customer', 'enterprise_child', 'business_unit', 'subsidiary')`);

const organizationRelationshipStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'pending', 'suspended', 'revoked', 'expired')`);

const delegatedAccessStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'pending', 'suspended', 'revoked', 'expired')`);

const delegatedAccessLevelCheck = (name, table) =>
  check(name, sql`${table.accessLevel} in ('viewer', 'analyst', 'responder', 'admin', 'auditor')`);

const tenantLifecycleStatusCheck = (name, table) =>
  check(name, sql`${table.lifecycleStatus} in ('provisioning', 'active', 'suspended', 'pending_deletion', 'deleted', 'archived')`);

const enterprisePlanCheck = (name, table) =>
  check(name, sql`${table.planKey} in ('starter', 'professional', 'enterprise', 'mssp')`);

const customerContactTypeCheck = (name, table) =>
  check(name, sql`${table.contactType} in ('security', 'billing', 'technical', 'executive', 'incident')`);

const complianceReportTypeCheck = (name, table) =>
  check(name, sql`${table.reportType} in ('security_posture', 'incident_summary', 'compliance_summary', 'executive', 'customer_security')`);

const complianceReportStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('draft', 'generated', 'review_required', 'published', 'archived')`);

const usageMetricTypeCheck = (name, table) =>
  check(name, sql`${table.metricType} in ('api_requests', 'security_events', 'alerts', 'incidents', 'firewall_instances', 'api_routes', 'notification_deliveries', 'ai_investigations', 'customer_tenants', 'analyst_seats')`);

const platformRegionStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('planned', 'active', 'degraded', 'maintenance', 'retired')`);

const regionalServiceTypeCheck = (name, table) =>
  check(name, sql`${table.serviceType} in ('control_plane', 'gateway', 'database', 'ingestion', 'notification', 'ai', 'marketplace', 'developer_api')`);

const regionalServiceStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('planned', 'active', 'degraded', 'maintenance', 'failed', 'retired')`);

const residencyPolicyStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'draft', 'disabled', 'retired')`);

const platformHealthStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('healthy', 'degraded', 'down', 'maintenance', 'unknown')`);

const backupJobStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('scheduled', 'running', 'completed', 'failed', 'cancelled')`);

const restoreOperationStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('requested', 'approved', 'running', 'completed', 'failed', 'cancelled')`);

const recoveryEventTypeCheck = (name, table) =>
  check(name, sql`${table.eventType} in ('backup_completed', 'backup_failed', 'restore_requested', 'restore_completed', 'failover_started', 'failover_completed', 'region_degraded', 'region_recovered')`);

const developerAppStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'disabled', 'deleted')`);

const integrationCategoryCheck = (name, table) =>
  check(name, sql`${table.category} in ('siem', 'soar', 'ticketing', 'identity', 'cloud', 'notification', 'threat_intelligence', 'compliance', 'developer')`);

const integrationCatalogStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('draft', 'review', 'active', 'deprecated', 'disabled')`);

const webhookSubscriptionStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'disabled', 'paused', 'deleted')`);

const marketplaceListingStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('draft', 'review', 'published', 'suspended', 'retired')`);

const identityProviderTypeCheck = (name, table) =>
  check(name, sql`${table.providerType} in ('password', 'google', 'github', 'oidc', 'saml')`);

const identityProviderStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'disabled', 'deleted')`);

const externalIdentityStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'unlinked', 'disabled', 'deleted')`);

const emailIdentityStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'revoked', 'expired')`);

const identityAuditResultCheck = (name, table) =>
  check(name, sql`${table.result} in ('success', 'failure', 'denied', 'error')`);

const oauthLoginAttemptStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('pending', 'completed', 'failed', 'expired')`);

const ssoLoginAttemptFlowCheck = (name, table) =>
  check(name, sql`${table.flowType} in ('saml', 'oidc')`);

const ssoLoginAttemptStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('pending', 'completed', 'failed', 'expired')`);

const ssoPolicyModeCheck = (name, table) =>
  check(name, sql`${table.ssoMode} in ('optional', 'required', 'disabled')`);

const scimProviderStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'disabled', 'deleted')`);

const scimTokenStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'revoked', 'expired')`);

const scimSyncOperationCheck = (name, table) =>
  check(name, sql`${table.operationType} in ('user_create', 'user_update', 'user_deactivate', 'group_sync', 'full_sync')`);

const scimSyncStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('queued', 'running', 'completed', 'failed', 'cancelled')`);

const scimEventTypeCheck = (name, table) =>
  check(name, sql`${table.eventType} in ('scim.user.created', 'scim.user.updated', 'scim.user.deactivated', 'scim.group.synced', 'scim.sync.started', 'scim.sync.completed', 'scim.sync.failed')`);

const scimEventResultCheck = (name, table) =>
  check(name, sql`${table.result} in ('success', 'failure', 'denied', 'error')`);

const identitySecurityEventTypeCheck = (name, table) =>
  check(name, sql`${table.eventType} in ('login.success', 'login.failure', 'mfa.failure', 'oauth.failure', 'sso.failure', 'scim.provisioning.failure', 'identity.change.suspicious', 'identity.risk.detected', 'identity.account.flagged')`);

const identitySecurityCategoryCheck = (name, table) =>
  check(name, sql`${table.category} in ('authentication', 'mfa', 'oauth', 'sso', 'scim', 'governance', 'risk')`);

const identitySecurityActionCheck = (name, table) =>
  check(name, sql`${table.action} in ('monitor', 'require_mfa', 'restrict_session', 'alert')`);

const identityRiskSeverityCheck = (name, table) =>
  check(name, sql`${table.severity} in ('low', 'medium', 'high', 'critical')`);

const identityRiskStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'resolved', 'suppressed', 'expired')`);

const identityAccessReviewTypeCheck = (name, table) =>
  check(name, sql`${table.reviewType} in ('periodic', 'privileged', 'inactive_accounts', 'orphaned_identities')`);

const identityAccessReviewStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('draft', 'open', 'in_review', 'completed', 'cancelled', 'expired')`);

const identityComplianceReportTypeCheck = (name, table) =>
  check(name, sql`${table.reportType} in ('user_inventory', 'mfa_status', 'privileged_access', 'sso_configuration', 'provisioning_history')`);

const identityComplianceReportStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('draft', 'generated', 'review_required', 'published', 'archived')`);

const identityMetricTypeCheck = (name, table) =>
  check(name, sql`${table.metricType} in ('login_success_rate', 'login_failure_rate', 'mfa_success_rate', 'mfa_failure_rate', 'oauth_health', 'sso_health', 'scim_health', 'risky_identity_trend')`);

const identityMetricStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('healthy', 'degraded', 'critical', 'unknown')`);

const identityAuditReportTypeCheck = (name, table) =>
  check(name, sql`${table.reportType} in ('administrator_activity', 'authentication_activity', 'provisioning_activity', 'access_review', 'identity_evidence')`);

const identityAuditReportFormatCheck = (name, table) =>
  check(name, sql`${table.exportFormat} in ('csv', 'json', 'evidence_timeline')`);

const identityAuditReportStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('draft', 'generated', 'review_required', 'published', 'archived')`);

const breakGlassAdminStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'disabled', 'expired', 'revoked')`);

const identityRecoveryWorkflowTypeCheck = (name, table) =>
  check(name, sql`${table.workflowType} in ('account_recovery', 'lockout_recovery', 'break_glass_activation', 'identity_disaster_recovery')`);

const identityRecoveryWorkflowStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('draft', 'requested', 'approved', 'active', 'completed', 'rejected', 'expired', 'cancelled')`);

const identityRecoveryEventTypeCheck = (name, table) =>
  check(name, sql`${table.eventType} in ('recovery.requested', 'recovery.approved', 'recovery.completed', 'recovery.rejected', 'break_glass.created', 'break_glass.activated', 'break_glass.revoked', 'recovery.tested')`);

const mfaMethodTypeCheck = (name, table) =>
  check(name, sql`${table.methodType} in ('totp', 'webauthn', 'recovery_codes')`);

const mfaMethodStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('pending', 'active', 'disabled', 'deleted')`);

const mfaChallengeTypeCheck = (name, table) =>
  check(name, sql`${table.challengeType} in ('login', 'step_up', 'registration')`);

const mfaChallengeStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('pending', 'succeeded', 'failed', 'expired')`);

const recoveryCodeStatusCheck = (name, table) =>
  check(name, sql`${table.status} in ('active', 'used', 'revoked')`);

export const organizations = pgTable(
  "organizations",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    name: varchar("name", { length: 255 }).notNull(),
    slug: varchar("slug", { length: 120 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    uniqueIndex("organizations_slug_idx").on(table.slug),
    lifecycleStatusCheck("organizations_status_check", table),
  ],
);

export const organizationSettings = pgTable(
  "organization_settings",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    mfaRequired: boolean("mfa_required").notNull().default(false),
    sessionTimeoutSeconds: integer("session_timeout_seconds").notNull().default(28_800),
    allowedEmailDomains: text("allowed_email_domains")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    ssoMode: varchar("sso_mode", { length: 32 }).notNull().default("optional"),
    ssoAllowedDomains: text("sso_allowed_domains")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    ssoPasswordLoginDisabled: boolean("sso_password_login_disabled").notNull().default(false),
    ssoMfaRequired: boolean("sso_mfa_required").notNull().default(false),
    securityLevel: varchar("security_level", { length: 32 }).notNull().default("standard"),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("organization_settings_organization_id_idx").on(table.organizationId),
    check(
      "organization_settings_security_level_check",
      sql`${table.securityLevel} in ('standard', 'strict', 'enterprise')`,
    ),
    check(
      "organization_settings_session_timeout_seconds_check",
      sql`${table.sessionTimeoutSeconds} between 300 and 2592000`,
    ),
    ssoPolicyModeCheck("organization_settings_sso_mode_check", table),
  ],
);

export const users = pgTable(
  "users",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    email: varchar("email", { length: 320 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
    emailVerifiedAt: timestamp("email_verified_at", { withTimezone: true }),
    lastLoginAt: timestamp("last_login_at", { withTimezone: true }),
    ...deletedAt,
  },
  (table) => [
    uniqueIndex("users_email_idx").on(table.email),
    lifecycleStatusCheck("users_status_check", table),
  ],
);

export const userCredentials = pgTable(
  "user_credentials",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    passwordHash: text("password_hash").notNull(),
    passwordChangedAt: timestamp("password_changed_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    failedAttempts: integer("failed_attempts").notNull().default(0),
    lockedUntil: timestamp("locked_until", { withTimezone: true }),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("user_credentials_user_id_idx").on(table.userId),
    check("user_credentials_failed_attempts_check", sql`${table.failedAttempts} >= 0`),
  ],
);

export const emailVerifications = pgTable(
  "email_verifications",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    email: varchar("email", { length: 320 }).notNull(),
    tokenHash: text("token_hash").notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    verifiedAt: timestamp("verified_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("email_verifications_token_hash_idx").on(table.tokenHash),
    index("email_verifications_user_id_idx").on(table.userId),
    index("email_verifications_expires_at_idx").on(table.expiresAt),
  ],
);

export const identityProviders = pgTable(
  "identity_providers",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").references(() => organizations.id, {
      onDelete: "cascade",
    }),
    providerKey: varchar("provider_key", { length: 80 }).notNull(),
    providerType: varchar("provider_type", { length: 32 }).notNull(),
    displayName: varchar("display_name", { length: 160 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("disabled"),
    issuer: varchar("issuer", { length: 255 }),
    clientId: varchar("client_id", { length: 255 }),
    scopes: text("scopes").array().notNull().default(sql`ARRAY[]::text[]`),
    allowedDomains: text("allowed_domains")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    configurationRef: varchar("configuration_ref", { length: 160 }),
    secretRef: varchar("secret_ref", { length: 160 }),
    authorizationEndpoint: text("authorization_endpoint"),
    tokenEndpoint: text("token_endpoint"),
    userInfoEndpoint: text("user_info_endpoint"),
    configuration: jsonb("configuration").notNull().default(sql`'{}'::jsonb`),
    isSystem: boolean("is_system").notNull().default(false),
    createdByUserId: uuid("created_by_user_id").references(() => users.id, {
      onDelete: "set null",
    }),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    uniqueIndex("identity_providers_org_key_idx").on(table.organizationId, table.providerKey),
    uniqueIndex("identity_providers_global_key_idx")
      .on(table.providerKey)
      .where(sql`organization_id IS NULL`),
    index("identity_providers_org_status_idx").on(table.organizationId, table.status),
    index("identity_providers_type_status_idx").on(table.providerType, table.status),
    index("identity_providers_org_type_idx").on(table.organizationId, table.providerType),
    identityProviderTypeCheck("identity_providers_type_chk", table),
    identityProviderStatusCheck("identity_providers_status_chk", table),
  ],
);

export const oauthLoginAttempts = pgTable(
  "oauth_login_attempts",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    providerId: uuid("provider_id")
      .notNull()
      .references(() => identityProviders.id, { onDelete: "cascade" }),
    stateHash: text("state_hash").notNull(),
    pkceVerifierHash: text("pkce_verifier_hash").notNull(),
    authorizationCodeHash: text("authorization_code_hash"),
    redirectPath: varchar("redirect_path", { length: 255 }).notNull().default("/"),
    status: varchar("status", { length: 32 }).notNull().default("pending"),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    consumedAt: timestamp("consumed_at", { withTimezone: true }),
    ipAddress: varchar("ip_address", { length: 45 }),
    userAgent: text("user_agent"),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("oauth_login_attempts_state_idx").on(table.stateHash),
    uniqueIndex("oauth_login_attempts_code_idx")
      .on(table.authorizationCodeHash)
      .where(sql`authorization_code_hash IS NOT NULL`),
    index("oauth_login_attempts_provider_status_idx").on(table.providerId, table.status),
    index("oauth_login_attempts_expires_idx").on(table.expiresAt),
    oauthLoginAttemptStatusCheck("oauth_login_attempts_status_chk", table),
  ],
);

export const ssoLoginAttempts = pgTable(
  "sso_login_attempts",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    providerId: uuid("provider_id")
      .notNull()
      .references(() => identityProviders.id, { onDelete: "cascade" }),
    flowType: varchar("flow_type", { length: 32 }).notNull(),
    stateHash: text("state_hash").notNull(),
    pkceVerifierHash: text("pkce_verifier_hash"),
    assertionIdHash: text("assertion_id_hash"),
    authorizationCodeHash: text("authorization_code_hash"),
    redirectPath: varchar("redirect_path", { length: 255 }).notNull().default("/"),
    status: varchar("status", { length: 32 }).notNull().default("pending"),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    consumedAt: timestamp("consumed_at", { withTimezone: true }),
    ipAddress: varchar("ip_address", { length: 45 }),
    userAgent: text("user_agent"),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("sso_login_attempts_state_idx").on(table.stateHash),
    uniqueIndex("sso_login_attempts_assertion_idx")
      .on(table.assertionIdHash)
      .where(sql`assertion_id_hash IS NOT NULL`),
    uniqueIndex("sso_login_attempts_code_idx")
      .on(table.authorizationCodeHash)
      .where(sql`authorization_code_hash IS NOT NULL`),
    index("sso_login_attempts_org_provider_status_idx").on(
      table.organizationId,
      table.providerId,
      table.status,
    ),
    index("sso_login_attempts_expires_idx").on(table.expiresAt),
    ssoLoginAttemptFlowCheck("sso_login_attempts_flow_chk", table),
    ssoLoginAttemptStatusCheck("sso_login_attempts_status_chk", table),
  ],
);

export const externalIdentities = pgTable(
  "external_identities",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    providerId: uuid("provider_id")
      .notNull()
      .references(() => identityProviders.id, { onDelete: "restrict" }),
    externalSubjectHash: text("external_subject_hash").notNull(),
    providerEmail: varchar("provider_email", { length: 320 }),
    providerEmailHash: text("provider_email_hash"),
    emailVerified: boolean("email_verified").notNull().default(false),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    linkedAt: timestamp("linked_at", { withTimezone: true }).notNull().defaultNow(),
    unlinkedAt: timestamp("unlinked_at", { withTimezone: true }),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    uniqueIndex("external_identities_provider_subject_idx").on(
      table.providerId,
      table.externalSubjectHash,
    ),
    index("external_identities_org_user_idx").on(table.organizationId, table.userId),
    index("external_identities_org_provider_idx").on(table.organizationId, table.providerId),
    index("external_identities_email_hash_idx").on(table.providerEmailHash),
    externalIdentityStatusCheck("external_identities_status_chk", table),
  ],
);

export const verifiedEmailIdentities = pgTable(
  "verified_email_identities",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    email: varchar("email", { length: 320 }).notNull(),
    emailHash: text("email_hash").notNull(),
    sourceProviderId: uuid("source_provider_id").references(() => identityProviders.id, {
      onDelete: "set null",
    }),
    verificationSource: varchar("verification_source", { length: 32 }).notNull().default("password"),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    verifiedAt: timestamp("verified_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("verified_email_identities_org_email_idx").on(
      table.organizationId,
      table.emailHash,
    ),
    index("verified_email_identities_user_idx").on(table.userId),
    index("verified_email_identities_source_idx").on(table.sourceProviderId),
    emailIdentityStatusCheck("verified_email_identities_status_chk", table),
    check(
      "verified_email_identities_source_chk",
      sql`${table.verificationSource} in ('password', 'google', 'github', 'oidc', 'saml', 'manual')`,
    ),
  ],
);

export const mfaMethods = pgTable(
  "mfa_methods",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    methodType: varchar("method_type", { length: 32 }).notNull(),
    displayName: varchar("display_name", { length: 160 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("pending"),
    verifiedAt: timestamp("verified_at", { withTimezone: true }),
    enabledAt: timestamp("enabled_at", { withTimezone: true }),
    disabledAt: timestamp("disabled_at", { withTimezone: true }),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
    secretCiphertext: jsonb("secret_ciphertext"),
    credentialIdHash: text("credential_id_hash"),
    publicKey: text("public_key"),
    signCount: integer("sign_count").notNull().default(0),
    deviceMetadata: jsonb("device_metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    index("mfa_methods_org_user_idx").on(table.organizationId, table.userId),
    index("mfa_methods_user_status_idx").on(table.userId, table.status),
    uniqueIndex("mfa_methods_credential_id_idx")
      .on(table.credentialIdHash)
      .where(sql`credential_id_hash IS NOT NULL`),
    mfaMethodTypeCheck("mfa_methods_type_chk", table),
    mfaMethodStatusCheck("mfa_methods_status_chk", table),
    check("mfa_methods_sign_count_chk", sql`${table.signCount} >= 0`),
  ],
);

export const mfaChallenges = pgTable(
  "mfa_challenges",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    methodId: uuid("method_id").references(() => mfaMethods.id, { onDelete: "set null" }),
    challengeType: varchar("challenge_type", { length: 32 }).notNull().default("login"),
    challengeHash: text("challenge_hash").notNull(),
    status: varchar("status", { length: 32 }).notNull().default("pending"),
    attemptCount: integer("attempt_count").notNull().default(0),
    maxAttempts: integer("max_attempts").notNull().default(5),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    succeededAt: timestamp("succeeded_at", { withTimezone: true }),
    consumedAt: timestamp("consumed_at", { withTimezone: true }),
    ipAddress: varchar("ip_address", { length: 45 }),
    userAgent: text("user_agent"),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("mfa_challenges_hash_idx").on(table.challengeHash),
    index("mfa_challenges_user_status_idx").on(table.userId, table.status),
    index("mfa_challenges_org_status_idx").on(table.organizationId, table.status),
    index("mfa_challenges_expires_idx").on(table.expiresAt),
    mfaChallengeTypeCheck("mfa_challenges_type_chk", table),
    mfaChallengeStatusCheck("mfa_challenges_status_chk", table),
    check("mfa_challenges_attempt_count_chk", sql`${table.attemptCount} >= 0`),
    check("mfa_challenges_max_attempts_chk", sql`${table.maxAttempts} between 1 and 10`),
  ],
);

export const recoveryCodes = pgTable(
  "recovery_codes",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    methodId: uuid("method_id").references(() => mfaMethods.id, { onDelete: "cascade" }),
    codeHash: text("code_hash").notNull(),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    usedAt: timestamp("used_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("recovery_codes_hash_idx").on(table.codeHash),
    index("recovery_codes_user_status_idx").on(table.userId, table.status),
    index("recovery_codes_org_user_idx").on(table.organizationId, table.userId),
    recoveryCodeStatusCheck("recovery_codes_status_chk", table),
  ],
);

export const passwordResetTokens = pgTable(
  "password_reset_tokens",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    usedAt: timestamp("used_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("password_reset_tokens_token_hash_idx").on(table.tokenHash),
    index("password_reset_tokens_user_id_idx").on(table.userId),
    index("password_reset_tokens_expires_at_idx").on(table.expiresAt),
  ],
);

export const organizationMemberships = pgTable(
  "organization_memberships",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("organization_memberships_org_user_idx").on(table.organizationId, table.userId),
    index("organization_memberships_organization_id_idx").on(table.organizationId),
    index("organization_memberships_user_id_idx").on(table.userId),
  ],
);

export const organizationInvitations = pgTable(
  "organization_invitations",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    email: varchar("email", { length: 320 }).notNull(),
    invitedByUserId: uuid("invited_by_user_id").references(() => users.id, {
      onDelete: "set null",
    }),
    roleId: uuid("role_id").references(() => roles.id, { onDelete: "set null" }),
    tokenHash: text("token_hash").notNull(),
    status: varchar("status", { length: 32 }).notNull().default("pending"),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    acceptedAt: timestamp("accepted_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("organization_invitations_token_hash_idx").on(table.tokenHash),
    index("organization_invitations_organization_id_idx").on(table.organizationId),
    index("organization_invitations_email_idx").on(table.email),
    index("organization_invitations_expires_at_idx").on(table.expiresAt),
    invitationStatusCheck("organization_invitations_status_check", table),
  ],
);

export const roles = pgTable(
  "roles",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").references(() => organizations.id, {
      onDelete: "cascade",
    }),
    name: varchar("name", { length: 120 }).notNull(),
    description: text("description"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("roles_system_name_idx").on(table.name).where(sql`organization_id IS NULL`),
    uniqueIndex("roles_org_name_idx").on(table.organizationId, table.name),
    index("roles_organization_id_idx").on(table.organizationId),
  ],
);

export const permissions = pgTable(
  "permissions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    key: varchar("key", { length: 160 }).notNull(),
    description: text("description"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [uniqueIndex("permissions_key_idx").on(table.key)],
);

export const rolePermissions = pgTable(
  "role_permissions",
  {
    roleId: uuid("role_id")
      .notNull()
      .references(() => roles.id, { onDelete: "cascade" }),
    permissionId: uuid("permission_id")
      .notNull()
      .references(() => permissions.id, { onDelete: "cascade" }),
  },
  (table) => [
    primaryKey({ columns: [table.roleId, table.permissionId] }),
    index("role_permissions_permission_id_idx").on(table.permissionId),
  ],
);

export const userRoles = pgTable(
  "user_roles",
  {
    membershipId: uuid("membership_id")
      .notNull()
      .references(() => organizationMemberships.id, { onDelete: "cascade" }),
    roleId: uuid("role_id")
      .notNull()
      .references(() => roles.id, { onDelete: "cascade" }),
  },
  (table) => [
    primaryKey({ columns: [table.membershipId, table.roleId] }),
    index("user_roles_role_id_idx").on(table.roleId),
  ],
);

export const scimProviders = pgTable(
  "scim_providers",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    name: varchar("name", { length: 160 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("disabled"),
    endpointConfigurationRef: varchar("endpoint_configuration_ref", { length: 160 }),
    baseUrl: text("base_url"),
    createdByUserId: uuid("created_by_user_id").references(() => users.id, {
      onDelete: "set null",
    }),
    lastSyncAt: timestamp("last_sync_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    uniqueIndex("scim_providers_org_name_idx").on(table.organizationId, table.name),
    index("scim_providers_org_status_idx").on(table.organizationId, table.status),
    scimProviderStatusCheck("scim_providers_status_chk", table),
  ],
);

export const scimTokens = pgTable(
  "scim_tokens",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    providerId: uuid("provider_id")
      .notNull()
      .references(() => scimProviders.id, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull(),
    name: varchar("name", { length: 160 }).notNull().default("SCIM token"),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    createdByUserId: uuid("created_by_user_id").references(() => users.id, {
      onDelete: "set null",
    }),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("scim_tokens_hash_idx").on(table.tokenHash),
    index("scim_tokens_org_provider_status_idx").on(table.organizationId, table.providerId, table.status),
    index("scim_tokens_expires_idx").on(table.expiresAt),
    scimTokenStatusCheck("scim_tokens_status_chk", table),
  ],
);

export const scimSyncJobs = pgTable(
  "scim_sync_jobs",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    providerId: uuid("provider_id")
      .references(() => scimProviders.id, { onDelete: "set null" }),
    operationType: varchar("operation_type", { length: 48 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("queued"),
    startedAt: timestamp("started_at", { withTimezone: true }),
    completedAt: timestamp("completed_at", { withTimezone: true }),
    errorSummary: text("error_summary"),
    resourceType: varchar("resource_type", { length: 32 }),
    resourceId: varchar("resource_id", { length: 255 }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    index("scim_sync_jobs_org_status_idx").on(table.organizationId, table.status, table.createdAt),
    index("scim_sync_jobs_provider_status_idx").on(table.providerId, table.status),
    scimSyncOperationCheck("scim_sync_jobs_operation_chk", table),
    scimSyncStatusCheck("scim_sync_jobs_status_chk", table),
  ],
);

export const scimEvents = pgTable(
  "scim_events",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    providerId: uuid("provider_id")
      .references(() => scimProviders.id, { onDelete: "set null" }),
    syncJobId: uuid("sync_job_id").references(() => scimSyncJobs.id, { onDelete: "set null" }),
    userId: uuid("user_id").references(() => users.id, { onDelete: "set null" }),
    membershipId: uuid("membership_id").references(() => organizationMemberships.id, {
      onDelete: "set null",
    }),
    eventType: varchar("event_type", { length: 160 }).notNull(),
    result: varchar("result", { length: 32 }).notNull(),
    externalIdHash: text("external_id_hash"),
    resourceType: varchar("resource_type", { length: 32 }),
    resourceId: varchar("resource_id", { length: 255 }),
    summary: text("summary"),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index("scim_events_org_created_idx").on(table.organizationId, table.createdAt),
    index("scim_events_provider_created_idx").on(table.providerId, table.createdAt),
    index("scim_events_user_created_idx").on(table.userId, table.createdAt),
    index("scim_events_external_idx").on(table.externalIdHash),
    scimEventTypeCheck("scim_events_type_chk", table),
    scimEventResultCheck("scim_events_result_chk", table),
  ],
);

export const scimGroupMappings = pgTable(
  "scim_group_mappings",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    providerId: uuid("provider_id")
      .notNull()
      .references(() => scimProviders.id, { onDelete: "cascade" }),
    externalGroupIdHash: text("external_group_id_hash").notNull(),
    externalDisplayName: varchar("external_display_name", { length: 160 }).notNull(),
    roleId: uuid("role_id").references(() => roles.id, { onDelete: "set null" }),
    status: varchar("status", { length: 32 }).notNull().default("pending"),
    approvedByUserId: uuid("approved_by_user_id").references(() => users.id, {
      onDelete: "set null",
    }),
    approvedAt: timestamp("approved_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("scim_group_mappings_provider_group_idx").on(
      table.providerId,
      table.externalGroupIdHash,
    ),
    index("scim_group_mappings_org_status_idx").on(table.organizationId, table.status),
    index("scim_group_mappings_role_idx").on(table.roleId),
    check("scim_group_mappings_status_chk", sql`${table.status} in ('pending', 'approved', 'disabled', 'deleted')`),
  ],
);

export const identitySecurityEvents = pgTable(
  "identity_security_events",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    userId: uuid("user_id").references(() => users.id, { onDelete: "set null" }),
    actorUserId: uuid("actor_user_id").references(() => users.id, { onDelete: "set null" }),
    providerId: uuid("provider_id").references(() => identityProviders.id, {
      onDelete: "set null",
    }),
    scimProviderId: uuid("scim_provider_id").references(() => scimProviders.id, {
      onDelete: "set null",
    }),
    auditEventId: uuid("audit_event_id").references(() => identityAuditEvents.id, {
      onDelete: "set null",
    }),
    eventType: varchar("event_type", { length: 160 }).notNull(),
    category: varchar("category", { length: 48 }).notNull(),
    result: varchar("result", { length: 32 }).notNull().default("success"),
    severity: varchar("severity", { length: 32 }).notNull().default("low"),
    riskScore: integer("risk_score").notNull().default(0),
    action: varchar("action", { length: 32 }).notNull().default("monitor"),
    ipAddress: varchar("ip_address", { length: 45 }),
    userAgent: text("user_agent"),
    source: varchar("source", { length: 80 }).notNull().default("identity"),
    summary: text("summary"),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index("identity_security_events_org_created_idx").on(table.organizationId, table.createdAt),
    index("identity_security_events_user_created_idx").on(table.userId, table.createdAt),
    index("identity_security_events_type_created_idx").on(table.eventType, table.createdAt),
    index("identity_security_events_risk_idx").on(table.organizationId, table.riskScore),
    identitySecurityEventTypeCheck("identity_security_events_type_chk", table),
    identitySecurityCategoryCheck("identity_security_events_category_chk", table),
    identityAuditResultCheck("identity_security_events_result_chk", table),
    identityRiskSeverityCheck("identity_security_events_severity_chk", table),
    identitySecurityActionCheck("identity_security_events_action_chk", table),
    check("identity_security_events_risk_score_chk", sql`${table.riskScore} between 0 and 100`),
  ],
);

export const identityRiskScores = pgTable(
  "identity_risk_scores",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    userId: uuid("user_id").references(() => users.id, { onDelete: "set null" }),
    subjectType: varchar("subject_type", { length: 48 }).notNull().default("user"),
    subjectId: varchar("subject_id", { length: 160 }),
    score: integer("score").notNull().default(0),
    severity: varchar("severity", { length: 32 }).notNull().default("low"),
    confidence: real("confidence").notNull().default(0),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    recommendedAction: varchar("recommended_action", { length: 32 }).notNull().default("monitor"),
    factors: jsonb("factors").notNull().default(sql`'[]'::jsonb`),
    lastSignalAt: timestamp("last_signal_at", { withTimezone: true }),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    index("identity_risk_scores_org_status_idx").on(table.organizationId, table.status),
    index("identity_risk_scores_org_score_idx").on(table.organizationId, table.score),
    index("identity_risk_scores_user_idx").on(table.userId),
    index("identity_risk_scores_subject_idx").on(table.organizationId, table.subjectType, table.subjectId),
    identityRiskSeverityCheck("identity_risk_scores_severity_chk", table),
    identityRiskStatusCheck("identity_risk_scores_status_chk", table),
    check("identity_risk_scores_action_chk", sql`${table.recommendedAction} in ('monitor', 'require_mfa', 'restrict_session', 'alert')`),
    check("identity_risk_scores_score_chk", sql`${table.score} between 0 and 100`),
    check("identity_risk_scores_confidence_chk", sql`${table.confidence} between 0 and 1`),
    check("identity_risk_scores_subject_type_chk", sql`${table.subjectType} in ('user', 'client', 'provider', 'organization')`),
  ],
);

export const identityAccessReviews = pgTable(
  "identity_access_reviews",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    name: varchar("name", { length: 160 }).notNull(),
    reviewType: varchar("review_type", { length: 48 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("draft"),
    scope: jsonb("scope").notNull().default(sql`'{}'::jsonb`),
    summary: text("summary"),
    findings: jsonb("findings").notNull().default(sql`'[]'::jsonb`),
    createdByUserId: uuid("created_by_user_id").references(() => users.id, {
      onDelete: "set null",
    }),
    assignedToUserId: uuid("assigned_to_user_id").references(() => users.id, {
      onDelete: "set null",
    }),
    dueAt: timestamp("due_at", { withTimezone: true }),
    completedAt: timestamp("completed_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    index("identity_access_reviews_org_status_idx").on(table.organizationId, table.status),
    index("identity_access_reviews_org_due_idx").on(table.organizationId, table.dueAt),
    index("identity_access_reviews_type_idx").on(table.organizationId, table.reviewType),
    identityAccessReviewTypeCheck("identity_access_reviews_type_chk", table),
    identityAccessReviewStatusCheck("identity_access_reviews_status_chk", table),
  ],
);

export const identityComplianceReports = pgTable(
  "identity_compliance_reports",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    reportType: varchar("report_type", { length: 64 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("generated"),
    windowStart: timestamp("window_start", { withTimezone: true }),
    windowEnd: timestamp("window_end", { withTimezone: true }),
    generatedByUserId: uuid("generated_by_user_id").references(() => users.id, {
      onDelete: "set null",
    }),
    generatedAt: timestamp("generated_at", { withTimezone: true }).notNull().defaultNow(),
    metrics: jsonb("metrics").notNull().default(sql`'{}'::jsonb`),
    findings: jsonb("findings").notNull().default(sql`'[]'::jsonb`),
    evidenceRef: varchar("evidence_ref", { length: 160 }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    index("identity_compliance_reports_org_type_idx").on(table.organizationId, table.reportType),
    index("identity_compliance_reports_org_generated_idx").on(table.organizationId, table.generatedAt),
    identityComplianceReportTypeCheck("identity_compliance_reports_type_chk", table),
    identityComplianceReportStatusCheck("identity_compliance_reports_status_chk", table),
  ],
);

export const identityMetrics = pgTable(
  "identity_metrics",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    metricType: varchar("metric_type", { length: 64 }).notNull(),
    metricValue: real("metric_value").notNull().default(0),
    numerator: integer("numerator").notNull().default(0),
    denominator: integer("denominator").notNull().default(0),
    status: varchar("status", { length: 32 }).notNull().default("unknown"),
    bucketStart: timestamp("bucket_start", { withTimezone: true }).notNull(),
    bucketEnd: timestamp("bucket_end", { withTimezone: true }).notNull(),
    dimensions: jsonb("dimensions").notNull().default(sql`'{}'::jsonb`),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    index("identity_metrics_org_type_bucket_idx").on(table.organizationId, table.metricType, table.bucketStart),
    index("identity_metrics_org_status_idx").on(table.organizationId, table.status),
    identityMetricTypeCheck("identity_metrics_type_chk", table),
    identityMetricStatusCheck("identity_metrics_status_chk", table),
    check("identity_metrics_value_chk", sql`${table.metricValue} between 0 and 100`),
    check("identity_metrics_count_chk", sql`${table.numerator} >= 0 and ${table.denominator} >= 0`),
  ],
);

export const identityAuditReports = pgTable(
  "identity_audit_reports",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    reportType: varchar("report_type", { length: 64 }).notNull(),
    exportFormat: varchar("export_format", { length: 32 }).notNull().default("json"),
    status: varchar("status", { length: 32 }).notNull().default("generated"),
    windowStart: timestamp("window_start", { withTimezone: true }),
    windowEnd: timestamp("window_end", { withTimezone: true }),
    generatedByUserId: uuid("generated_by_user_id").references(() => users.id, {
      onDelete: "set null",
    }),
    generatedAt: timestamp("generated_at", { withTimezone: true }).notNull().defaultNow(),
    rowCount: integer("row_count").notNull().default(0),
    reportPayload: jsonb("report_payload").notNull().default(sql`'{}'::jsonb`),
    evidenceRef: varchar("evidence_ref", { length: 160 }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    index("identity_audit_reports_org_type_idx").on(table.organizationId, table.reportType),
    index("identity_audit_reports_org_generated_idx").on(table.organizationId, table.generatedAt),
    identityAuditReportTypeCheck("identity_audit_reports_type_chk", table),
    identityAuditReportFormatCheck("identity_audit_reports_format_chk", table),
    identityAuditReportStatusCheck("identity_audit_reports_status_chk", table),
    check("identity_audit_reports_row_count_chk", sql`${table.rowCount} >= 0`),
  ],
);

export const breakGlassAdministrators = pgTable(
  "break_glass_administrators",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    status: varchar("status", { length: 32 }).notNull().default("disabled"),
    reason: text("reason"),
    mfaRequired: boolean("mfa_required").notNull().default(true),
    approvedByUserId: uuid("approved_by_user_id").references(() => users.id, {
      onDelete: "set null",
    }),
    activatedAt: timestamp("activated_at", { withTimezone: true }),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("break_glass_admins_org_user_idx").on(table.organizationId, table.userId),
    index("break_glass_admins_org_status_idx").on(table.organizationId, table.status),
    index("break_glass_admins_expires_idx").on(table.expiresAt),
    breakGlassAdminStatusCheck("break_glass_admins_status_chk", table),
  ],
);

export const identityRecoveryWorkflows = pgTable(
  "identity_recovery_workflows",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    targetUserId: uuid("target_user_id").references(() => users.id, { onDelete: "set null" }),
    requestedByUserId: uuid("requested_by_user_id").references(() => users.id, {
      onDelete: "set null",
    }),
    approvedByUserId: uuid("approved_by_user_id").references(() => users.id, {
      onDelete: "set null",
    }),
    workflowType: varchar("workflow_type", { length: 64 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("requested"),
    reason: text("reason"),
    mfaRequired: boolean("mfa_required").notNull().default(true),
    approvalRequired: boolean("approval_required").notNull().default(true),
    requestedAt: timestamp("requested_at", { withTimezone: true }).notNull().defaultNow(),
    approvedAt: timestamp("approved_at", { withTimezone: true }),
    completedAt: timestamp("completed_at", { withTimezone: true }),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    index("identity_recovery_workflows_org_status_idx").on(table.organizationId, table.status),
    index("identity_recovery_workflows_target_idx").on(table.targetUserId),
    index("identity_recovery_workflows_expires_idx").on(table.expiresAt),
    identityRecoveryWorkflowTypeCheck("identity_recovery_workflows_type_chk", table),
    identityRecoveryWorkflowStatusCheck("identity_recovery_workflows_status_chk", table),
  ],
);

export const identityRecoveryEvents = pgTable(
  "identity_recovery_events",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    workflowId: uuid("workflow_id").references(() => identityRecoveryWorkflows.id, {
      onDelete: "set null",
    }),
    breakGlassAdministratorId: uuid("break_glass_administrator_id").references(
      () => breakGlassAdministrators.id,
      { onDelete: "set null" },
    ),
    actorUserId: uuid("actor_user_id").references(() => users.id, { onDelete: "set null" }),
    targetUserId: uuid("target_user_id").references(() => users.id, { onDelete: "set null" }),
    eventType: varchar("event_type", { length: 160 }).notNull(),
    result: varchar("result", { length: 32 }).notNull().default("success"),
    summary: text("summary"),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index("identity_recovery_events_org_created_idx").on(table.organizationId, table.createdAt),
    index("identity_recovery_events_workflow_idx").on(table.workflowId),
    index("identity_recovery_events_target_idx").on(table.targetUserId),
    identityRecoveryEventTypeCheck("identity_recovery_events_type_chk", table),
    identityAuditResultCheck("identity_recovery_events_result_chk", table),
  ],
);

export const serviceAccountRoles = pgTable(
  "service_account_roles",
  {
    serviceAccountId: uuid("service_account_id")
      .notNull()
      .references(() => serviceAccounts.id, { onDelete: "cascade" }),
    roleId: uuid("role_id")
      .notNull()
      .references(() => roles.id, { onDelete: "cascade" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    primaryKey({ columns: [table.serviceAccountId, table.roleId] }),
    index("service_account_roles_role_id_idx").on(table.roleId),
  ],
);

export const sessions = pgTable(
  "sessions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    activeFirewallInstanceId: uuid("active_firewall_instance_id").references(
      () => firewallInstances.id,
      { onDelete: "set null" },
    ),
    tokenHash: text("token_hash").notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }),
    ipAddress: varchar("ip_address", { length: 45 }),
    userAgent: text("user_agent"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("sessions_token_hash_idx").on(table.tokenHash),
    index("sessions_user_id_idx").on(table.userId),
    index("sessions_organization_id_idx").on(table.organizationId),
    index("sessions_active_firewall_instance_id_idx").on(table.activeFirewallInstanceId),
    index("sessions_expires_at_idx").on(table.expiresAt),
  ],
);

export const apiKeys = pgTable(
  "api_keys",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    serviceAccountId: uuid("service_account_id").references(() => serviceAccounts.id, {
      onDelete: "set null",
    }),
    name: varchar("name", { length: 160 }).notNull(),
    keyPrefix: varchar("key_prefix", { length: 32 }).notNull(),
    keyHash: text("key_hash").notNull(),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
    ...deletedAt,
  },
  (table) => [
    uniqueIndex("api_keys_key_hash_idx").on(table.keyHash),
    uniqueIndex("api_keys_key_prefix_idx").on(table.keyPrefix),
    index("api_keys_organization_id_idx").on(table.organizationId),
    index("api_keys_service_account_id_idx").on(table.serviceAccountId),
    apiKeyStatusCheck("api_keys_status_check", table),
  ],
);

export const serviceAccounts = pgTable(
  "service_accounts",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    name: varchar("name", { length: 160 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    ...deletedAt,
  },
  (table) => [
    uniqueIndex("service_accounts_org_name_idx").on(table.organizationId, table.name),
    index("service_accounts_organization_id_idx").on(table.organizationId),
    lifecycleStatusCheck("service_accounts_status_check", table),
  ],
);

export const auditActors = pgTable(
  "audit_actors",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    actorType: varchar("actor_type", { length: 32 }).notNull(),
    userId: uuid("user_id").references(() => users.id, { onDelete: "set null" }),
    serviceAccountId: uuid("service_account_id").references(() => serviceAccounts.id, {
      onDelete: "set null",
    }),
    apiKeyId: uuid("api_key_id").references(() => apiKeys.id, { onDelete: "set null" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index("audit_actors_user_id_idx").on(table.userId),
    index("audit_actors_service_account_id_idx").on(table.serviceAccountId),
    index("audit_actors_api_key_id_idx").on(table.apiKeyId),
    check(
      "audit_actors_actor_type_check",
      sql`${table.actorType} in ('user', 'service_account', 'api_key', 'system')`,
    ),
    check(
      "audit_actors_reference_check",
      sql`
        (
          ${table.actorType} = 'user'
          and ${table.userId} is not null
          and ${table.serviceAccountId} is null
          and ${table.apiKeyId} is null
        )
        or (
          ${table.actorType} = 'service_account'
          and ${table.userId} is null
          and ${table.serviceAccountId} is not null
          and ${table.apiKeyId} is null
        )
        or (
          ${table.actorType} = 'api_key'
          and ${table.userId} is null
          and ${table.serviceAccountId} is null
          and ${table.apiKeyId} is not null
        )
        or (
          ${table.actorType} = 'system'
          and ${table.userId} is null
          and ${table.serviceAccountId} is null
          and ${table.apiKeyId} is null
        )
      `,
    ),
  ],
);

export const auditEvents = pgTable(
  "audit_events",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").references(() => organizations.id, {
      onDelete: "set null",
    }),
    userId: uuid("user_id").references(() => users.id, { onDelete: "set null" }),
    serviceAccountId: uuid("service_account_id").references(() => serviceAccounts.id, {
      onDelete: "set null",
    }),
    firewallInstanceId: uuid("firewall_instance_id").references(() => firewallInstances.id, {
      onDelete: "set null",
    }),
    eventType: varchar("event_type", { length: 160 }).notNull(),
    action: varchar("action", { length: 160 }).notNull(),
    resourceType: varchar("resource_type", { length: 120 }),
    resourceId: varchar("resource_id", { length: 160 }),
    result: varchar("result", { length: 32 }).notNull(),
    severity: varchar("severity", { length: 32 }).notNull().default("info"),
    ipAddress: varchar("ip_address", { length: 45 }),
    userAgent: text("user_agent"),
    requestId: varchar("request_id", { length: 160 }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index("audit_events_organization_created_at_idx").on(table.organizationId, table.createdAt),
    index("audit_events_user_created_at_idx").on(table.userId, table.createdAt),
    index("audit_events_service_account_created_at_idx").on(
      table.serviceAccountId,
      table.createdAt,
    ),
    index("audit_events_firewall_instance_created_at_idx").on(
      table.firewallInstanceId,
      table.createdAt,
    ),
    index("audit_events_request_id_idx").on(table.requestId),
    check(
      "audit_events_result_check",
      sql`${table.result} in ('success', 'failure', 'denied', 'error')`,
    ),
    check(
      "audit_events_severity_check",
      sql`${table.severity} in ('info', 'low', 'medium', 'high', 'critical')`,
    ),
  ],
);

export const identityAuditEvents = pgTable(
  "identity_audit_events",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").references(() => organizations.id, {
      onDelete: "set null",
    }),
    userId: uuid("user_id").references(() => users.id, { onDelete: "set null" }),
    actorUserId: uuid("actor_user_id").references(() => users.id, { onDelete: "set null" }),
    providerId: uuid("provider_id").references(() => identityProviders.id, {
      onDelete: "set null",
    }),
    externalIdentityId: uuid("external_identity_id").references(() => externalIdentities.id, {
      onDelete: "set null",
    }),
    eventType: varchar("event_type", { length: 160 }).notNull(),
    action: varchar("action", { length: 160 }).notNull(),
    result: varchar("result", { length: 32 }).notNull(),
    ipAddress: varchar("ip_address", { length: 45 }),
    userAgent: text("user_agent"),
    requestId: varchar("request_id", { length: 160 }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index("identity_audit_events_org_created_idx").on(table.organizationId, table.createdAt),
    index("identity_audit_events_user_created_idx").on(table.userId, table.createdAt),
    index("identity_audit_events_actor_created_idx").on(table.actorUserId, table.createdAt),
    index("identity_audit_events_provider_created_idx").on(table.providerId, table.createdAt),
    index("identity_audit_events_request_id_idx").on(table.requestId),
    identityAuditResultCheck("identity_audit_events_result_chk", table),
  ],
);

export const firewallInstances = pgTable(
  "firewall_instances",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    name: varchar("name", { length: 160 }).notNull(),
    environment: varchar("environment", { length: 64 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    installationIdentifier: varchar("installation_identifier", { length: 160 }),
    hostname: varchar("hostname", { length: 255 }),
    region: varchar("region", { length: 80 }),
    version: varchar("version", { length: 80 }),
    enrolledAt: timestamp("enrolled_at", { withTimezone: true }),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    uniqueIndex("firewall_instances_org_name_idx").on(table.organizationId, table.name),
    uniqueIndex("firewall_instances_installation_identifier_idx")
      .on(table.installationIdentifier)
      .where(sql`installation_identifier IS NOT NULL`),
    index("firewall_instances_organization_id_idx").on(table.organizationId),
    index("firewall_instances_organization_status_idx").on(table.organizationId, table.status),
    lifecycleStatusCheck("firewall_instances_status_check", table),
  ],
);

export const firewallEnrollmentTokens = pgTable(
  "firewall_enrollment_tokens",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id").notNull(),
    tokenHash: text("token_hash").notNull(),
    status: varchar("status", { length: 32 }).notNull().default("pending"),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    usedAt: timestamp("used_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdByUserId: uuid("created_by_user_id"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("firewall_enrollment_tokens_token_hash_idx").on(table.tokenHash),
    index("firewall_enrollment_tokens_organization_id_idx").on(table.organizationId),
    index("firewall_enrollment_tokens_firewall_instance_id_idx").on(table.firewallInstanceId),
    index("firewall_enrollment_tokens_expires_at_idx").on(table.expiresAt),
    foreignKey({
      name: "fet_organization_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "fet_firewall_instance_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "fet_created_by_user_fk",
      columns: [table.createdByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    enrollmentTokenStatusCheck("firewall_enrollment_tokens_status_check", table),
  ],
);

export const securityEvents = pgTable(
  "security_events",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id, { onDelete: "cascade" }),
    firewallInstanceId: uuid("firewall_instance_id")
      .notNull()
      .references(() => firewallInstances.id, { onDelete: "cascade" }),
    eventType: varchar("event_type", { length: 80 }).notNull(),
    attackType: varchar("attack_type", { length: 80 }).notNull(),
    severity: varchar("severity", { length: 32 }).notNull(),
    sourceIp: varchar("source_ip", { length: 45 }),
    requestPath: text("request_path"),
    httpMethod: varchar("http_method", { length: 16 }),
    userAgent: text("user_agent"),
    country: varchar("country", { length: 2 }),
    confidence: real("confidence"),
    detectorId: varchar("detector_id", { length: 80 }),
    detectorIds: text("detector_ids")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    score: real("score"),
    apiRouteId: text("api_route_id"),
    anomalyType: varchar("anomaly_type", { length: 80 }),
    actionTaken: varchar("action_taken", { length: 32 }).notNull(),
    requestId: varchar("request_id", { length: 160 }),
    rawMetadata: jsonb("raw_metadata").notNull().default(sql`'{}'::jsonb`),
    occurredAt: timestamp("occurred_at", { withTimezone: true }).notNull(),
    receivedAt: timestamp("received_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index("security_events_organization_occurred_at_idx").on(
      table.organizationId,
      table.occurredAt,
    ),
    index("security_events_firewall_occurred_at_idx").on(
      table.firewallInstanceId,
      table.occurredAt,
    ),
    index("security_events_organization_severity_occurred_at_idx").on(
      table.organizationId,
      table.severity,
      table.occurredAt,
    ),
    index("security_events_organization_attack_type_occurred_at_idx").on(
      table.organizationId,
      table.attackType,
      table.occurredAt,
    ),
    index("security_events_request_id_idx").on(table.requestId),
    index("security_events_detector_idx").on(table.organizationId, table.detectorId),
    index("security_events_api_route_idx").on(table.organizationId, table.apiRouteId),
    securityEventSeverityCheck("security_events_severity_check", table),
    securityEventActionCheck("security_events_action_taken_check", table),
    check("security_events_confidence_check", sql`${table.confidence} between 0 and 1`),
    check("security_events_score_check", sql`${table.score} between 0 and 100`),
  ],
);

export const apiInventoryRoutes = pgTable(
  "api_inventory_routes",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id").notNull(),
    routeTemplate: text("route_template").notNull(),
    methods: text("methods")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("new"),
    observedRequestCount: integer("observed_request_count").notNull().default(0),
    observedStatusCodes: integer("observed_status_codes")
      .array()
      .notNull()
      .default(sql`ARRAY[]::integer[]`),
    contentTypes: text("content_types")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    learnedSchemaSummary: jsonb("learned_schema_summary").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("api_inventory_route_unique_idx").on(
      table.organizationId,
      table.firewallInstanceId,
      table.routeTemplate,
    ),
    index("api_inventory_org_status_idx").on(table.organizationId, table.status),
    index("api_inventory_firewall_seen_idx").on(table.firewallInstanceId, table.lastSeenAt),
    foreignKey({
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
      name: "api_inventory_routes_org_id_fk",
    }).onDelete("cascade"),
    foreignKey({
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
      name: "api_inventory_routes_fw_id_fk",
    }).onDelete("cascade"),
    check(
      "api_inventory_status_check",
      sql`${table.status} in ('new', 'known', 'approved', 'deprecated', 'unknown')`,
    ),
  ],
);

export const firewallPolicyVersions = pgTable(
  "firewall_policy_versions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id").notNull(),
    version: integer("version").notNull(),
    previousVersion: integer("previous_version"),
    policyMode: varchar("policy_mode", { length: 32 }).notNull().default("balanced"),
    digestSha256: varchar("digest_sha256", { length: 64 }),
    detectorExceptions: jsonb("detector_exceptions").notNull().default(sql`'[]'::jsonb`),
    policySnapshot: jsonb("policy_snapshot").notNull().default(sql`'{}'::jsonb`),
    createdBy: varchar("created_by", { length: 160 }),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("firewall_policy_versions_unique_idx").on(
      table.organizationId,
      table.firewallInstanceId,
      table.version,
    ),
    index("firewall_policy_versions_firewall_idx").on(table.firewallInstanceId, table.createdAt),
    foreignKey({
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
      name: "firewall_policy_versions_org_id_fk",
    }).onDelete("cascade"),
    foreignKey({
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
      name: "firewall_policy_versions_fw_id_fk",
    }).onDelete("cascade"),
    check(
      "firewall_policy_versions_mode_check",
      sql`${table.policyMode} in ('monitor', 'balanced', 'strict')`,
    ),
  ],
);

export const firewallInstanceRoleAssignments = pgTable(
  "firewall_instance_role_assignments",
  {
    firewallInstanceId: uuid("firewall_instance_id")
      .notNull()
      .references(() => firewallInstances.id, { onDelete: "cascade" }),
    membershipId: uuid("membership_id")
      .notNull()
      .references(() => organizationMemberships.id, { onDelete: "cascade" }),
    roleId: uuid("role_id")
      .notNull()
      .references(() => roles.id, { onDelete: "cascade" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    primaryKey({ columns: [table.firewallInstanceId, table.membershipId, table.roleId] }),
    index("firewall_instance_role_assignments_membership_id_idx").on(table.membershipId),
    index("firewall_instance_role_assignments_role_id_idx").on(table.roleId),
  ],
);

export const firewallInstanceServiceAccountRoleAssignments = pgTable(
  "firewall_instance_service_account_role_assignments",
  {
    firewallInstanceId: uuid("firewall_instance_id").notNull(),
    serviceAccountId: uuid("service_account_id").notNull(),
    roleId: uuid("role_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "fisara_pk",
      columns: [table.firewallInstanceId, table.serviceAccountId, table.roleId],
    }),
    foreignKey({
      name: "fisara_firewall_instance_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "fisara_service_account_fk",
      columns: [table.serviceAccountId],
      foreignColumns: [serviceAccounts.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "fisara_role_fk",
      columns: [table.roleId],
      foreignColumns: [roles.id],
    }).onDelete("cascade"),
    index("firewall_instance_service_account_roles_service_account_id_idx").on(
      table.serviceAccountId,
    ),
    index("firewall_instance_service_account_roles_role_id_idx").on(table.roleId),
  ],
);

export const detectorConfigurations = pgTable(
  "detector_configurations",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    detectorId: varchar("detector_id", { length: 80 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    confidenceThreshold: real("confidence_threshold").notNull().default(0.5),
    severityOverride: varchar("severity_override", { length: 32 }),
    tuning: jsonb("tuning").notNull().default(sql`'{}'::jsonb`),
    suppressionRules: jsonb("suppression_rules").notNull().default(sql`'[]'::jsonb`),
    createdByUserId: uuid("created_by_user_id"),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    uniqueIndex("detector_configurations_unique_idx").on(
      table.organizationId,
      table.firewallInstanceId,
      table.detectorId,
    ),
    index("detector_configurations_org_status_idx").on(table.organizationId, table.status),
    index("detector_configurations_firewall_idx").on(table.firewallInstanceId),
    foreignKey({
      name: "detector_configurations_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "detector_configurations_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "detector_configurations_created_by_fk",
      columns: [table.createdByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    detectorConfigStatusCheck("detector_configurations_status_chk", table),
    check(
      "detector_configurations_severity_chk",
      sql`${table.severityOverride} is null or ${table.severityOverride} in ('low', 'medium', 'high', 'critical')`,
    ),
    check("detector_configurations_confidence_chk", sql`${table.confidenceThreshold} between 0 and 1`),
  ],
);

export const behavioralBaselines = pgTable(
  "behavioral_baselines",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id").notNull(),
    baselineType: varchar("baseline_type", { length: 64 }).notNull(),
    baselineKeyHash: varchar("baseline_key_hash", { length: 64 }).notNull(),
    baselineKeyLabel: varchar("baseline_key_label", { length: 160 }),
    windowSeconds: integer("window_seconds").notNull().default(86400),
    sampleCount: integer("sample_count").notNull().default(0),
    requestRatePerMinute: real("request_rate_per_minute").notNull().default(0),
    methodMix: jsonb("method_mix").notNull().default(sql`'{}'::jsonb`),
    routeFrequency: jsonb("route_frequency").notNull().default(sql`'{}'::jsonb`),
    clientFingerprint: varchar("client_fingerprint", { length: 64 }),
    learnedAt: timestamp("learned_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("behavioral_baselines_unique_idx").on(
      table.organizationId,
      table.firewallInstanceId,
      table.baselineType,
      table.baselineKeyHash,
    ),
    index("behavioral_baselines_org_type_idx").on(table.organizationId, table.baselineType),
    index("behavioral_baselines_firewall_learned_idx").on(table.firewallInstanceId, table.learnedAt),
    foreignKey({
      name: "behavioral_baselines_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "behavioral_baselines_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("cascade"),
    check("behavioral_baselines_window_chk", sql`${table.windowSeconds} between 60 and 2592000`),
    check("behavioral_baselines_sample_count_chk", sql`${table.sampleCount} >= 0`),
  ],
);

export const detectionFindings = pgTable(
  "detection_findings",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id").notNull(),
    securityEventId: uuid("security_event_id"),
    findingType: varchar("finding_type", { length: 80 }).notNull(),
    detectorId: varchar("detector_id", { length: 80 }).notNull(),
    severity: varchar("severity", { length: 32 }).notNull(),
    confidence: real("confidence").notNull(),
    riskScore: real("risk_score").notNull(),
    compositeRisk: jsonb("composite_risk").notNull().default(sql`'{}'::jsonb`),
    evidence: jsonb("evidence").notNull().default(sql`'{}'::jsonb`),
    status: varchar("status", { length: 32 }).notNull().default("open"),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull(),
    eventCount: integer("event_count").notNull().default(1),
    dedupeFingerprint: varchar("dedupe_fingerprint", { length: 64 }).notNull(),
    ...timestamps,
  },
  (table) => [
    index("detection_findings_org_status_time_idx").on(table.organizationId, table.status, table.lastSeenAt),
    index("detection_findings_firewall_time_idx").on(table.firewallInstanceId, table.lastSeenAt),
    index("detection_findings_detector_idx").on(table.organizationId, table.detectorId),
    index("detection_findings_dedupe_idx").on(table.organizationId, table.dedupeFingerprint),
    foreignKey({
      name: "detection_findings_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "detection_findings_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "detection_findings_security_event_fk",
      columns: [table.securityEventId],
      foreignColumns: [securityEvents.id],
    }).onDelete("set null"),
    securityEventSeverityCheck("detection_findings_severity_chk", table),
    detectionFindingStatusCheck("detection_findings_status_chk", table),
    check("detection_findings_confidence_chk", sql`${table.confidence} between 0 and 1`),
    check("detection_findings_risk_score_chk", sql`${table.riskScore} between 0 and 100`),
    check("detection_findings_event_count_chk", sql`${table.eventCount} >= 1`),
  ],
);

export const correlationEvents = pgTable(
  "correlation_events",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id").notNull(),
    correlationType: varchar("correlation_type", { length: 80 }).notNull(),
    severity: varchar("severity", { length: 32 }).notNull(),
    confidence: real("confidence").notNull(),
    riskScore: real("risk_score").notNull(),
    relatedEventIds: text("related_event_ids")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    relatedDetectorIds: text("related_detector_ids")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    identityFingerprint: varchar("identity_fingerprint", { length: 64 }),
    routeFingerprint: varchar("route_fingerprint", { length: 64 }),
    evidence: jsonb("evidence").notNull().default(sql`'{}'::jsonb`),
    status: varchar("status", { length: 32 }).notNull().default("open"),
    windowStart: timestamp("window_start", { withTimezone: true }).notNull(),
    windowEnd: timestamp("window_end", { withTimezone: true }).notNull(),
    dedupeFingerprint: varchar("dedupe_fingerprint", { length: 64 }).notNull(),
    ...timestamps,
  },
  (table) => [
    index("correlation_events_org_status_time_idx").on(table.organizationId, table.status, table.windowEnd),
    index("correlation_events_firewall_time_idx").on(table.firewallInstanceId, table.windowEnd),
    index("correlation_events_type_idx").on(table.organizationId, table.correlationType),
    index("correlation_events_dedupe_idx").on(table.organizationId, table.dedupeFingerprint),
    foreignKey({
      name: "correlation_events_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "correlation_events_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("cascade"),
    securityEventSeverityCheck("correlation_events_severity_chk", table),
    detectionFindingStatusCheck("correlation_events_status_chk", table),
    check("correlation_events_confidence_chk", sql`${table.confidence} between 0 and 1`),
    check("correlation_events_risk_score_chk", sql`${table.riskScore} between 0 and 100`),
  ],
);

export const detectorFeedback = pgTable(
  "detector_feedback",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    detectorId: varchar("detector_id", { length: 80 }).notNull(),
    securityEventId: uuid("security_event_id"),
    findingId: uuid("finding_id"),
    feedbackType: varchar("feedback_type", { length: 64 }).notNull(),
    note: text("note"),
    createdByUserId: uuid("created_by_user_id"),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    index("detector_feedback_org_detector_idx").on(table.organizationId, table.detectorId),
    index("detector_feedback_firewall_idx").on(table.firewallInstanceId),
    index("detector_feedback_event_idx").on(table.securityEventId),
    foreignKey({
      name: "detector_feedback_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "detector_feedback_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("set null"),
    foreignKey({
      name: "detector_feedback_security_event_fk",
      columns: [table.securityEventId],
      foreignColumns: [securityEvents.id],
    }).onDelete("set null"),
    foreignKey({
      name: "detector_feedback_finding_fk",
      columns: [table.findingId],
      foreignColumns: [detectionFindings.id],
    }).onDelete("set null"),
    foreignKey({
      name: "detector_feedback_created_by_fk",
      columns: [table.createdByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    detectorFeedbackTypeCheck("detector_feedback_type_chk", table),
  ],
);

export const threatSources = pgTable(
  "threat_sources",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id"),
    name: varchar("name", { length: 160 }).notNull(),
    providerType: varchar("provider_type", { length: 80 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    healthStatus: varchar("health_status", { length: 32 }).notNull().default("unknown"),
    capabilities: text("capabilities")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    configuration: jsonb("configuration").notNull().default(sql`'{}'::jsonb`),
    secretReference: jsonb("secret_reference").notNull().default(sql`'{}'::jsonb`),
    rateLimitPerMinute: integer("rate_limit_per_minute").notNull().default(60),
    timeoutMs: integer("timeout_ms").notNull().default(2500),
    lastSyncAt: timestamp("last_sync_at", { withTimezone: true }),
    lastSuccessAt: timestamp("last_success_at", { withTimezone: true }),
    lastFailureAt: timestamp("last_failure_at", { withTimezone: true }),
    lastFailureCode: varchar("last_failure_code", { length: 80 }),
    createdByUserId: uuid("created_by_user_id"),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    index("threat_sources_org_status_idx").on(table.organizationId, table.status),
    index("threat_sources_provider_status_idx").on(table.providerType, table.status),
    index("threat_sources_health_idx").on(table.healthStatus, table.lastSyncAt),
    foreignKey({
      name: "threat_sources_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "threat_sources_created_by_fk",
      columns: [table.createdByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    threatSourceStatusCheck("threat_sources_status_chk", table),
    threatSourceHealthCheck("threat_sources_health_chk", table),
    check("threat_sources_rate_limit_chk", sql`${table.rateLimitPerMinute} between 1 and 10000`),
    check("threat_sources_timeout_chk", sql`${table.timeoutMs} between 100 and 30000`),
  ],
);

export const threatIndicators = pgTable(
  "threat_indicators",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id"),
    sourceId: uuid("source_id"),
    indicatorType: varchar("indicator_type", { length: 32 }).notNull(),
    indicatorValueHash: varchar("indicator_value_hash", { length: 64 }).notNull(),
    indicatorValueDisplay: varchar("indicator_value_display", { length: 240 }).notNull(),
    category: varchar("category", { length: 80 }).notNull().default("unknown"),
    reputationScore: real("reputation_score").notNull().default(0),
    confidence: real("confidence").notNull().default(0.5),
    severity: varchar("severity", { length: 32 }).notNull().default("medium"),
    tags: text("tags")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    reviewStatus: varchar("review_status", { length: 32 }).notNull().default("unreviewed"),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull().defaultNow(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    sourceMetadata: jsonb("source_metadata").notNull().default(sql`'{}'::jsonb`),
    reviewedByUserId: uuid("reviewed_by_user_id"),
    reviewedAt: timestamp("reviewed_at", { withTimezone: true }),
    analystNote: text("analyst_note"),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    index("threat_indicators_lookup_idx").on(table.indicatorType, table.indicatorValueHash),
    index("threat_indicators_org_lookup_idx").on(
      table.organizationId,
      table.indicatorType,
      table.indicatorValueHash,
    ),
    index("threat_indicators_source_seen_idx").on(table.sourceId, table.lastSeenAt),
    index("threat_indicators_expires_idx").on(table.expiresAt),
    index("threat_indicators_category_score_idx").on(table.category, table.reputationScore),
    foreignKey({
      name: "threat_indicators_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "threat_indicators_source_fk",
      columns: [table.sourceId],
      foreignColumns: [threatSources.id],
    }).onDelete("set null"),
    foreignKey({
      name: "threat_indicators_reviewed_by_fk",
      columns: [table.reviewedByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    threatIndicatorTypeCheck("threat_indicators_type_chk", table),
    threatReviewStatusCheck("threat_indicators_review_status_chk", table),
    securityEventSeverityCheck("threat_indicators_severity_chk", table),
    check("threat_indicators_reputation_chk", sql`${table.reputationScore} between 0 and 100`),
    check("threat_indicators_confidence_chk", sql`${table.confidence} between 0 and 1`),
  ],
);

export const reputationCache = pgTable(
  "reputation_cache",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id"),
    indicatorType: varchar("indicator_type", { length: 32 }).notNull(),
    lookupHash: varchar("lookup_hash", { length: 64 }).notNull(),
    lookupLabel: varchar("lookup_label", { length: 240 }),
    reputationScore: real("reputation_score").notNull().default(0),
    confidence: real("confidence").notNull().default(0),
    categories: text("categories")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    sourceIds: text("source_ids")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    indicatorIds: text("indicator_ids")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    payload: jsonb("payload").notNull().default(sql`'{}'::jsonb`),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    lastRefreshedAt: timestamp("last_refreshed_at", { withTimezone: true }).notNull().defaultNow(),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("reputation_cache_org_lookup_idx").on(
      table.organizationId,
      table.indicatorType,
      table.lookupHash,
    ),
    index("reputation_cache_lookup_idx").on(table.indicatorType, table.lookupHash),
    index("reputation_cache_expires_idx").on(table.expiresAt),
    foreignKey({
      name: "reputation_cache_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    threatIndicatorTypeCheck("reputation_cache_type_chk", table),
    check("reputation_cache_score_chk", sql`${table.reputationScore} between 0 and 100`),
    check("reputation_cache_confidence_chk", sql`${table.confidence} between 0 and 1`),
  ],
);

export const threatMatches = pgTable(
  "threat_matches",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id").notNull(),
    securityEventId: uuid("security_event_id"),
    detectionFindingId: uuid("detection_finding_id"),
    correlationEventId: uuid("correlation_event_id"),
    indicatorId: uuid("indicator_id"),
    indicatorType: varchar("indicator_type", { length: 32 }).notNull(),
    matchValueHash: varchar("match_value_hash", { length: 64 }).notNull(),
    matchLabel: varchar("match_label", { length: 240 }),
    matchContext: varchar("match_context", { length: 80 }).notNull(),
    riskDelta: real("risk_delta").notNull().default(0),
    confidenceDelta: real("confidence_delta").notNull().default(0),
    sourceId: uuid("source_id"),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    matchedAt: timestamp("matched_at", { withTimezone: true }).notNull().defaultNow(),
    ...timestamps,
  },
  (table) => [
    index("threat_matches_org_time_idx").on(table.organizationId, table.matchedAt),
    index("threat_matches_firewall_time_idx").on(table.firewallInstanceId, table.matchedAt),
    index("threat_matches_event_idx").on(table.securityEventId),
    index("threat_matches_indicator_time_idx").on(table.indicatorId, table.matchedAt),
    index("threat_matches_lookup_idx").on(table.indicatorType, table.matchValueHash),
    foreignKey({
      name: "threat_matches_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "threat_matches_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "threat_matches_security_event_fk",
      columns: [table.securityEventId],
      foreignColumns: [securityEvents.id],
    }).onDelete("set null"),
    foreignKey({
      name: "threat_matches_detection_finding_fk",
      columns: [table.detectionFindingId],
      foreignColumns: [detectionFindings.id],
    }).onDelete("set null"),
    foreignKey({
      name: "threat_matches_correlation_event_fk",
      columns: [table.correlationEventId],
      foreignColumns: [correlationEvents.id],
    }).onDelete("set null"),
    foreignKey({
      name: "threat_matches_indicator_fk",
      columns: [table.indicatorId],
      foreignColumns: [threatIndicators.id],
    }).onDelete("set null"),
    foreignKey({
      name: "threat_matches_source_fk",
      columns: [table.sourceId],
      foreignColumns: [threatSources.id],
    }).onDelete("set null"),
    threatIndicatorTypeCheck("threat_matches_type_chk", table),
    check("threat_matches_risk_delta_chk", sql`${table.riskDelta} between -100 and 100`),
    check("threat_matches_confidence_delta_chk", sql`${table.confidenceDelta} between -1 and 1`),
  ],
);

export const threatFeedStatus = pgTable(
  "threat_feed_status",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    sourceId: uuid("source_id").notNull(),
    feedName: varchar("feed_name", { length: 160 }).notNull(),
    syncCursor: text("sync_cursor"),
    syncStatus: varchar("sync_status", { length: 32 }).notNull().default("idle"),
    lastStartedAt: timestamp("last_started_at", { withTimezone: true }),
    lastCompletedAt: timestamp("last_completed_at", { withTimezone: true }),
    lastErrorCode: varchar("last_error_code", { length: 80 }),
    itemsProcessed: integer("items_processed").notNull().default(0),
    itemsRejected: integer("items_rejected").notNull().default(0),
    itemsExpired: integer("items_expired").notNull().default(0),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("threat_feed_status_source_feed_idx").on(table.sourceId, table.feedName),
    index("threat_feed_status_source_status_idx").on(table.sourceId, table.syncStatus),
    index("threat_feed_status_completed_idx").on(table.lastCompletedAt),
    foreignKey({
      name: "threat_feed_status_source_fk",
      columns: [table.sourceId],
      foreignColumns: [threatSources.id],
    }).onDelete("cascade"),
    check("threat_feed_status_status_chk", sql`${table.syncStatus} in ('idle', 'running', 'success', 'failed', 'rate_limited')`),
    check("threat_feed_status_counts_chk", sql`${table.itemsProcessed} >= 0 and ${table.itemsRejected} >= 0 and ${table.itemsExpired} >= 0`),
  ],
);

export const zeroTrustPolicies = pgTable(
  "zero_trust_policies",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    name: varchar("name", { length: 160 }).notNull(),
    description: text("description"),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    mode: varchar("mode", { length: 32 }).notNull().default("observe"),
    failBehavior: varchar("fail_behavior", { length: 32 }).notNull().default("fail_open"),
    activeVersionId: uuid("active_version_id"),
    createdByUserId: uuid("created_by_user_id"),
    activatedAt: timestamp("activated_at", { withTimezone: true }),
    deactivatedAt: timestamp("deactivated_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    uniqueIndex("zero_trust_policies_org_name_idx").on(table.organizationId, table.name),
    index("zero_trust_policies_org_status_idx").on(table.organizationId, table.status),
    index("zero_trust_policies_firewall_status_idx").on(table.firewallInstanceId, table.status),
    foreignKey({
      name: "zero_trust_policies_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "zero_trust_policies_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "zero_trust_policies_created_by_fk",
      columns: [table.createdByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    zeroTrustPolicyStatusCheck("zero_trust_policies_status_chk", table),
    zeroTrustPolicyModeCheck("zero_trust_policies_mode_chk", table),
    zeroTrustFailBehaviorCheck("zero_trust_policies_fail_behavior_chk", table),
  ],
);

export const zeroTrustPolicyVersions = pgTable(
  "zero_trust_policy_versions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    policyId: uuid("policy_id").notNull(),
    versionNumber: integer("version_number").notNull(),
    previousVersionId: uuid("previous_version_id"),
    rollbackFromVersionId: uuid("rollback_from_version_id"),
    status: varchar("status", { length: 32 }).notNull().default("draft"),
    policySnapshot: jsonb("policy_snapshot").notNull().default(sql`'{}'::jsonb`),
    policyDigest: varchar("policy_digest", { length: 64 }).notNull(),
    createdByUserId: uuid("created_by_user_id"),
    activatedAt: timestamp("activated_at", { withTimezone: true }),
    retiredAt: timestamp("retired_at", { withTimezone: true }),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("zero_trust_policy_versions_policy_number_idx").on(table.policyId, table.versionNumber),
    index("zero_trust_policy_versions_org_status_idx").on(table.organizationId, table.status),
    index("zero_trust_policy_versions_policy_status_idx").on(table.policyId, table.status),
    foreignKey({
      name: "ztpv_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "ztpv_policy_fk",
      columns: [table.policyId],
      foreignColumns: [zeroTrustPolicies.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "ztpv_previous_version_fk",
      columns: [table.previousVersionId],
      foreignColumns: [table.id],
    }).onDelete("set null"),
    foreignKey({
      name: "ztpv_rollback_from_fk",
      columns: [table.rollbackFromVersionId],
      foreignColumns: [table.id],
    }).onDelete("set null"),
    foreignKey({
      name: "ztpv_created_by_fk",
      columns: [table.createdByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    zeroTrustPolicyVersionStatusCheck("zero_trust_policy_versions_status_chk", table),
    check("zero_trust_policy_versions_number_chk", sql`${table.versionNumber} >= 1`),
  ],
);

export const policyDecisions = pgTable(
  "policy_decisions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    securityEventId: uuid("security_event_id"),
    policyId: uuid("policy_id"),
    policyVersionId: uuid("policy_version_id"),
    correlationEventId: uuid("correlation_event_id"),
    alertId: uuid("alert_id"),
    incidentId: uuid("incident_id"),
    decision: varchar("decision", { length: 32 }).notNull(),
    decisionReason: varchar("decision_reason", { length: 240 }).notNull(),
    mode: varchar("mode", { length: 32 }).notNull().default("observe"),
    failBehavior: varchar("fail_behavior", { length: 32 }).notNull().default("fail_open"),
    riskScore: real("risk_score").notNull().default(0),
    confidence: real("confidence").notNull().default(0),
    identityContext: jsonb("identity_context").notNull().default(sql`'{}'::jsonb`),
    requestContext: jsonb("request_context").notNull().default(sql`'{}'::jsonb`),
    detectorReferences: text("detector_references")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    threatIntelReferences: text("threat_intel_references")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    enforcementMetadata: jsonb("enforcement_metadata").notNull().default(sql`'{}'::jsonb`),
    explanation: jsonb("explanation").notNull().default(sql`'{}'::jsonb`),
    evaluatedAt: timestamp("evaluated_at", { withTimezone: true }).notNull().defaultNow(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index("policy_decisions_org_time_idx").on(table.organizationId, table.evaluatedAt),
    index("policy_decisions_firewall_time_idx").on(table.firewallInstanceId, table.evaluatedAt),
    index("policy_decisions_policy_time_idx").on(table.policyId, table.evaluatedAt),
    index("policy_decisions_event_idx").on(table.securityEventId),
    foreignKey({
      name: "policy_decisions_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "policy_decisions_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("set null"),
    foreignKey({
      name: "policy_decisions_security_event_fk",
      columns: [table.securityEventId],
      foreignColumns: [securityEvents.id],
    }).onDelete("set null"),
    foreignKey({
      name: "policy_decisions_policy_fk",
      columns: [table.policyId],
      foreignColumns: [zeroTrustPolicies.id],
    }).onDelete("set null"),
    foreignKey({
      name: "policy_decisions_policy_version_fk",
      columns: [table.policyVersionId],
      foreignColumns: [zeroTrustPolicyVersions.id],
    }).onDelete("set null"),
    foreignKey({
      name: "policy_decisions_correlation_fk",
      columns: [table.correlationEventId],
      foreignColumns: [correlationEvents.id],
    }).onDelete("set null"),
    policyDecisionCheck("policy_decisions_decision_chk", table),
    zeroTrustPolicyModeCheck("policy_decisions_mode_chk", table),
    zeroTrustFailBehaviorCheck("policy_decisions_fail_behavior_chk", table),
    check("policy_decisions_risk_score_chk", sql`${table.riskScore} between 0 and 100`),
    check("policy_decisions_confidence_chk", sql`${table.confidence} between 0 and 1`),
  ],
);

export const emergencyBypasses = pgTable(
  "emergency_bypasses",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    reason: text("reason").notNull(),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    createdByUserId: uuid("created_by_user_id"),
    revokedByUserId: uuid("revoked_by_user_id"),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    usedAt: timestamp("used_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    index("emergency_bypasses_org_status_expires_idx").on(table.organizationId, table.status, table.expiresAt),
    index("emergency_bypasses_firewall_status_idx").on(table.firewallInstanceId, table.status),
    foreignKey({
      name: "emergency_bypasses_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "emergency_bypasses_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "emergency_bypasses_created_by_fk",
      columns: [table.createdByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    foreignKey({
      name: "emergency_bypasses_revoked_by_fk",
      columns: [table.revokedByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    emergencyBypassStatusCheck("emergency_bypasses_status_chk", table),
    check("emergency_bypasses_expiry_chk", sql`${table.expiresAt} > ${table.createdAt}`),
  ],
);

export const alertRules = pgTable(
  "alert_rules",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    name: varchar("name", { length: 160 }).notNull(),
    description: text("description"),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    severityThreshold: varchar("severity_threshold", { length: 32 }).notNull().default("high"),
    confidenceThreshold: real("confidence_threshold"),
    scoreThreshold: real("score_threshold"),
    detectorIds: text("detector_ids")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    attackTypes: text("attack_types")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    anomalyTypes: text("anomaly_types")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    actions: text("actions")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    routePatterns: text("route_patterns")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    aggregationWindowSeconds: integer("aggregation_window_seconds").notNull().default(300),
    thresholdCount: integer("threshold_count").notNull().default(1),
    cooldownSeconds: integer("cooldown_seconds").notNull().default(300),
    autoCreateIncident: boolean("auto_create_incident").notNull().default(false),
    createdByUserId: uuid("created_by_user_id"),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    index("alert_rules_org_status_idx").on(table.organizationId, table.status),
    index("alert_rules_firewall_idx").on(table.firewallInstanceId),
    foreignKey({
      name: "alert_rules_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "alert_rules_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "alert_rules_created_by_fk",
      columns: [table.createdByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    alertRuleStatusCheck("alert_rules_status_chk", table),
    check(
      "alert_rules_severity_chk",
      sql`${table.severityThreshold} in ('low', 'medium', 'high', 'critical')`,
    ),
    check("alert_rules_confidence_chk", sql`${table.confidenceThreshold} is null or ${table.confidenceThreshold} between 0 and 1`),
    check("alert_rules_score_chk", sql`${table.scoreThreshold} is null or ${table.scoreThreshold} between 0 and 100`),
    check("alert_rules_threshold_chk", sql`${table.thresholdCount} between 1 and 1000`),
    check("alert_rules_window_chk", sql`${table.aggregationWindowSeconds} between 30 and 86400`),
    check("alert_rules_cooldown_chk", sql`${table.cooldownSeconds} between 0 and 86400`),
  ],
);

export const alertSuppressions = pgTable(
  "alert_suppressions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    alertRuleId: uuid("alert_rule_id"),
    scopeType: varchar("scope_type", { length: 32 }).notNull(),
    scopeValue: text("scope_value"),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    reason: text("reason").notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    createdByUserId: uuid("created_by_user_id"),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    index("alert_suppressions_org_status_idx").on(table.organizationId, table.status),
    index("alert_suppressions_scope_idx").on(table.organizationId, table.scopeType),
    foreignKey({
      name: "alert_suppressions_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "alert_suppressions_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "alert_suppressions_rule_fk",
      columns: [table.alertRuleId],
      foreignColumns: [alertRules.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "alert_suppressions_created_by_fk",
      columns: [table.createdByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    check("alert_suppressions_status_chk", sql`${table.status} in ('active', 'expired', 'deleted')`),
    check("alert_suppressions_scope_chk", sql`${table.scopeType} in ('rule', 'detector', 'firewall', 'route', 'source_ip')`),
  ],
);

export const alerts = pgTable(
  "alerts",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id").notNull(),
    alertRuleId: uuid("alert_rule_id"),
    incidentId: uuid("incident_id"),
    dedupeFingerprint: varchar("dedupe_fingerprint", { length: 64 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("open"),
    severity: varchar("severity", { length: 32 }).notNull(),
    title: varchar("title", { length: 240 }).notNull(),
    summary: text("summary").notNull(),
    detectorId: varchar("detector_id", { length: 80 }),
    attackType: varchar("attack_type", { length: 80 }),
    anomalyType: varchar("anomaly_type", { length: 80 }),
    sourceIp: varchar("source_ip", { length: 45 }),
    route: text("route"),
    eventCount: integer("event_count").notNull().default(1),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull(),
    lastNotifiedAt: timestamp("last_notified_at", { withTimezone: true }),
    acknowledgedAt: timestamp("acknowledged_at", { withTimezone: true }),
    acknowledgedByUserId: uuid("acknowledged_by_user_id"),
    resolvedAt: timestamp("resolved_at", { withTimezone: true }),
    resolvedByUserId: uuid("resolved_by_user_id"),
    resolutionNote: text("resolution_note"),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("alerts_open_dedupe_idx")
      .on(table.organizationId, table.dedupeFingerprint)
      .where(sql`status in ('open', 'acknowledged')`),
    index("alerts_org_status_time_idx").on(table.organizationId, table.status, table.lastSeenAt),
    index("alerts_firewall_time_idx").on(table.firewallInstanceId, table.lastSeenAt),
    index("alerts_rule_time_idx").on(table.alertRuleId, table.lastSeenAt),
    foreignKey({
      name: "alerts_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "alerts_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "alerts_rule_fk",
      columns: [table.alertRuleId],
      foreignColumns: [alertRules.id],
    }).onDelete("set null"),
    foreignKey({
      name: "alerts_ack_user_fk",
      columns: [table.acknowledgedByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    foreignKey({
      name: "alerts_res_user_fk",
      columns: [table.resolvedByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    alertStatusCheck("alerts_status_chk", table),
    securityEventSeverityCheck("alerts_severity_chk", table),
    check("alerts_event_count_chk", sql`${table.eventCount} >= 1`),
  ],
);

export const incidents = pgTable(
  "incidents",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    title: varchar("title", { length: 240 }).notNull(),
    summary: text("summary"),
    severity: varchar("severity", { length: 32 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("open"),
    assignedToUserId: uuid("assigned_to_user_id"),
    createdByUserId: uuid("created_by_user_id"),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull(),
    acknowledgedAt: timestamp("acknowledged_at", { withTimezone: true }),
    resolvedAt: timestamp("resolved_at", { withTimezone: true }),
    resolution: text("resolution"),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    index("incidents_org_status_time_idx").on(table.organizationId, table.status, table.lastSeenAt),
    index("incidents_firewall_time_idx").on(table.firewallInstanceId, table.lastSeenAt),
    foreignKey({
      name: "incidents_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "incidents_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("set null"),
    foreignKey({
      name: "incidents_assigned_user_fk",
      columns: [table.assignedToUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    foreignKey({
      name: "incidents_created_by_fk",
      columns: [table.createdByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    incidentStatusCheck("incidents_status_chk", table),
    securityEventSeverityCheck("incidents_severity_chk", table),
  ],
);

export const incidentAlerts = pgTable(
  "incident_alerts",
  {
    incidentId: uuid("incident_id").notNull(),
    alertId: uuid("alert_id").notNull(),
    linkedByUserId: uuid("linked_by_user_id"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    primaryKey({ name: "incident_alerts_pk", columns: [table.incidentId, table.alertId] }),
    index("incident_alerts_alert_idx").on(table.alertId),
    foreignKey({
      name: "incident_alerts_incident_fk",
      columns: [table.incidentId],
      foreignColumns: [incidents.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "incident_alerts_alert_fk",
      columns: [table.alertId],
      foreignColumns: [alerts.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "incident_alerts_linked_by_fk",
      columns: [table.linkedByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
  ],
);

export const notificationChannels = pgTable(
  "notification_channels",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    type: varchar("type", { length: 32 }).notNull(),
    name: varchar("name", { length: 160 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    configuration: jsonb("configuration").notNull().default(sql`'{}'::jsonb`),
    secretReference: jsonb("secret_reference").notNull().default(sql`'{}'::jsonb`),
    selectedEvents: text("selected_events")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    createdByUserId: uuid("created_by_user_id"),
    lastSuccessAt: timestamp("last_success_at", { withTimezone: true }),
    lastFailureAt: timestamp("last_failure_at", { withTimezone: true }),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    index("notification_channels_org_status_idx").on(table.organizationId, table.status),
    foreignKey({
      name: "notification_channels_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "notification_channels_created_by_fk",
      columns: [table.createdByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    notificationChannelStatusCheck("notification_channels_status_chk", table),
    check("notification_channels_type_chk", sql`${table.type} in ('webhook', 'email', 'siem')`),
  ],
);

export const notificationDeliveries = pgTable(
  "notification_deliveries",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    channelId: uuid("channel_id").notNull(),
    alertId: uuid("alert_id"),
    incidentId: uuid("incident_id"),
    eventType: varchar("event_type", { length: 80 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("pending"),
    attemptCount: integer("attempt_count").notNull().default(0),
    maxAttempts: integer("max_attempts").notNull().default(5),
    responseStatus: integer("response_status"),
    lastErrorCode: varchar("last_error_code", { length: 80 }),
    nextAttemptAt: timestamp("next_attempt_at", { withTimezone: true }),
    claimedAt: timestamp("claimed_at", { withTimezone: true }),
    deliveredAt: timestamp("delivered_at", { withTimezone: true }),
    payload: jsonb("payload").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    index("notification_deliveries_pending_idx").on(table.status, table.nextAttemptAt),
    index("notification_deliveries_org_time_idx").on(table.organizationId, table.createdAt),
    index("notification_deliveries_channel_idx").on(table.channelId, table.createdAt),
    foreignKey({
      name: "notification_deliveries_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "notification_deliveries_channel_fk",
      columns: [table.channelId],
      foreignColumns: [notificationChannels.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "notification_deliveries_alert_fk",
      columns: [table.alertId],
      foreignColumns: [alerts.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "notification_deliveries_incident_fk",
      columns: [table.incidentId],
      foreignColumns: [incidents.id],
    }).onDelete("cascade"),
    deliveryStatusCheck("notification_deliveries_status_chk", table),
    check("notification_deliveries_attempts_chk", sql`${table.attemptCount} >= 0 and ${table.maxAttempts} between 1 and 10`),
  ],
);

export const scheduledReports = pgTable(
  "scheduled_reports",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    reportType: varchar("report_type", { length: 80 }).notNull(),
    schedule: varchar("schedule", { length: 80 }).notNull(),
    channelId: uuid("channel_id"),
    status: varchar("status", { length: 32 }).notNull().default("disabled"),
    lastRunAt: timestamp("last_run_at", { withTimezone: true }),
    nextRunAt: timestamp("next_run_at", { withTimezone: true }),
    createdByUserId: uuid("created_by_user_id"),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    index("scheduled_reports_org_status_idx").on(table.organizationId, table.status),
    foreignKey({
      name: "scheduled_reports_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "scheduled_reports_channel_fk",
      columns: [table.channelId],
      foreignColumns: [notificationChannels.id],
    }).onDelete("set null"),
    foreignKey({
      name: "scheduled_reports_created_by_fk",
      columns: [table.createdByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    check("scheduled_reports_status_chk", sql`${table.status} in ('active', 'disabled', 'deleted')`),
  ],
);

export const protectionRules = pgTable(
  "protection_rules",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    name: varchar("name", { length: 160 }).notNull(),
    description: text("description"),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    mode: varchar("mode", { length: 32 }).notNull().default("observe"),
    action: varchar("action", { length: 32 }).notNull(),
    precedence: integer("precedence").notNull().default(500),
    conditions: jsonb("conditions").notNull().default(sql`'[]'::jsonb`),
    ttlSeconds: integer("ttl_seconds"),
    rateLimitPolicyId: uuid("rate_limit_policy_id"),
    createdByUserId: uuid("created_by_user_id"),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    uniqueIndex("protection_rules_org_name_idx").on(table.organizationId, table.name),
    index("protection_rules_org_status_idx").on(table.organizationId, table.status),
    index("protection_rules_firewall_idx").on(table.firewallInstanceId, table.status),
    index("protection_rules_action_idx").on(table.organizationId, table.action),
    foreignKey({
      name: "protection_rules_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "protection_rules_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "protection_rules_created_by_fk",
      columns: [table.createdByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    protectionRuleStatusCheck("protection_rules_status_chk", table),
    protectionModeCheck("protection_rules_mode_chk", table),
    protectionActionCheck("protection_rules_action_chk", table),
    check("protection_rules_precedence_chk", sql`${table.precedence} between 1 and 10000`),
    check("protection_rules_ttl_chk", sql`${table.ttlSeconds} is null or ${table.ttlSeconds} between 60 and 2592000`),
  ],
);

export const rateLimitPolicies = pgTable(
  "rate_limit_policies",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    name: varchar("name", { length: 160 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    dimension: varchar("dimension", { length: 32 }).notNull().default("source"),
    limitCount: integer("limit_count").notNull(),
    windowSeconds: integer("window_seconds").notNull(),
    burstCount: integer("burst_count"),
    createdByUserId: uuid("created_by_user_id"),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    uniqueIndex("rate_limit_policies_org_name_idx").on(table.organizationId, table.name),
    index("rate_limit_policies_org_status_idx").on(table.organizationId, table.status),
    index("rate_limit_policies_firewall_idx").on(table.firewallInstanceId, table.status),
    foreignKey({
      name: "rate_limit_policies_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "rate_limit_policies_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "rate_limit_policies_created_by_fk",
      columns: [table.createdByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    protectionRuleStatusCheck("rate_limit_policies_status_chk", table),
    check("rate_limit_policies_dimension_chk", sql`${table.dimension} in ('organization', 'firewall', 'route', 'credential', 'source')`),
    check("rate_limit_policies_limit_chk", sql`${table.limitCount} between 1 and 100000`),
    check("rate_limit_policies_window_chk", sql`${table.windowSeconds} between 10 and 86400`),
    check("rate_limit_policies_burst_chk", sql`${table.burstCount} is null or ${table.burstCount} between 1 and 100000`),
  ],
);

export const rateLimitState = pgTable(
  "rate_limit_state",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    rateLimitPolicyId: uuid("rate_limit_policy_id").notNull(),
    dimension: varchar("dimension", { length: 32 }).notNull(),
    keyHash: varchar("key_hash", { length: 64 }).notNull(),
    keyLabel: varchar("key_label", { length: 240 }),
    count: integer("count").notNull().default(0),
    windowStart: timestamp("window_start", { withTimezone: true }).notNull(),
    windowEnd: timestamp("window_end", { withTimezone: true }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("rate_limit_state_unique_idx").on(table.rateLimitPolicyId, table.dimension, table.keyHash, table.windowStart),
    index("rate_limit_state_org_expires_idx").on(table.organizationId, table.expiresAt),
    index("rate_limit_state_firewall_idx").on(table.firewallInstanceId, table.windowEnd),
    foreignKey({
      name: "rate_limit_state_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "rate_limit_state_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "rate_limit_state_policy_fk",
      columns: [table.rateLimitPolicyId],
      foreignColumns: [rateLimitPolicies.id],
    }).onDelete("cascade"),
    check("rate_limit_state_count_chk", sql`${table.count} >= 0`),
    check("rate_limit_state_window_chk", sql`${table.windowEnd} > ${table.windowStart}`),
  ],
);

export const protectionBlocklists = pgTable(
  "protection_blocklists",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    entryType: varchar("entry_type", { length: 32 }).notNull(),
    entryHash: varchar("entry_hash", { length: 64 }).notNull(),
    entryLabel: varchar("entry_label", { length: 240 }).notNull(),
    reason: text("reason").notNull(),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    sourceDecisionId: uuid("source_decision_id"),
    createdByUserId: uuid("created_by_user_id"),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    uniqueIndex("protection_blocklists_unique_idx").on(table.organizationId, table.firewallInstanceId, table.entryType, table.entryHash),
    index("protection_blocklists_org_status_idx").on(table.organizationId, table.status),
    index("protection_blocklists_expires_idx").on(table.expiresAt),
    foreignKey({
      name: "protection_blocklists_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "protection_blocklists_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "protection_blocklists_decision_fk",
      columns: [table.sourceDecisionId],
      foreignColumns: [policyDecisions.id],
    }).onDelete("set null"),
    foreignKey({
      name: "protection_blocklists_created_by_fk",
      columns: [table.createdByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    protectionRuleStatusCheck("protection_blocklists_status_chk", table),
    protectionListTypeCheck("protection_blocklists_type_chk", table),
  ],
);

export const protectionAllowlists = pgTable(
  "protection_allowlists",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    entryType: varchar("entry_type", { length: 32 }).notNull(),
    entryHash: varchar("entry_hash", { length: 64 }).notNull(),
    entryLabel: varchar("entry_label", { length: 240 }).notNull(),
    reason: text("reason").notNull(),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    createdByUserId: uuid("created_by_user_id"),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    uniqueIndex("protection_allowlists_unique_idx").on(table.organizationId, table.firewallInstanceId, table.entryType, table.entryHash),
    index("protection_allowlists_org_status_idx").on(table.organizationId, table.status),
    index("protection_allowlists_expires_idx").on(table.expiresAt),
    foreignKey({
      name: "protection_allowlists_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "protection_allowlists_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "protection_allowlists_created_by_fk",
      columns: [table.createdByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    protectionRuleStatusCheck("protection_allowlists_status_chk", table),
    protectionListTypeCheck("protection_allowlists_type_chk", table),
  ],
);

export const credentialProtectionState = pgTable(
  "credential_protection_state",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    apiKeyId: uuid("api_key_id"),
    credentialFingerprint: varchar("credential_fingerprint", { length: 64 }).notNull(),
    credentialLabel: varchar("credential_label", { length: 160 }),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    reason: text("reason"),
    sourceDecisionId: uuid("source_decision_id"),
    createdByUserId: uuid("created_by_user_id"),
    releasedByUserId: uuid("released_by_user_id"),
    restrictedUntil: timestamp("restricted_until", { withTimezone: true }),
    releasedAt: timestamp("released_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("credential_protection_state_unique_idx").on(table.organizationId, table.credentialFingerprint),
    index("credential_protection_state_org_status_idx").on(table.organizationId, table.status),
    index("credential_protection_state_firewall_idx").on(table.firewallInstanceId, table.status),
    foreignKey({
      name: "credential_protection_state_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "credential_protection_state_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("set null"),
    foreignKey({
      name: "credential_protection_state_api_key_fk",
      columns: [table.apiKeyId],
      foreignColumns: [apiKeys.id],
    }).onDelete("set null"),
    foreignKey({
      name: "credential_protection_state_decision_fk",
      columns: [table.sourceDecisionId],
      foreignColumns: [policyDecisions.id],
    }).onDelete("set null"),
    foreignKey({
      name: "credential_protection_state_created_by_fk",
      columns: [table.createdByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    foreignKey({
      name: "credential_protection_state_released_by_fk",
      columns: [table.releasedByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    credentialProtectionStatusCheck("credential_protection_state_status_chk", table),
  ],
);

export const enforcementEvents = pgTable(
  "enforcement_events",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    policyDecisionId: uuid("policy_decision_id"),
    policyId: uuid("policy_id"),
    policyVersionId: uuid("policy_version_id"),
    protectionRuleId: uuid("protection_rule_id"),
    rateLimitPolicyId: uuid("rate_limit_policy_id"),
    credentialProtectionStateId: uuid("credential_protection_state_id"),
    alertId: uuid("alert_id"),
    incidentId: uuid("incident_id"),
    action: varchar("action", { length: 32 }).notNull(),
    mode: varchar("mode", { length: 32 }).notNull(),
    outcome: varchar("outcome", { length: 32 }).notNull(),
    reason: varchar("reason", { length: 240 }).notNull(),
    riskScore: real("risk_score").notNull().default(0),
    confidence: real("confidence").notNull().default(0),
    detectorReferences: text("detector_references")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    enforcementKeyHash: varchar("enforcement_key_hash", { length: 64 }),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    requestContext: jsonb("request_context").notNull().default(sql`'{}'::jsonb`),
    explanation: jsonb("explanation").notNull().default(sql`'{}'::jsonb`),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index("enforcement_events_org_time_idx").on(table.organizationId, table.createdAt),
    index("enforcement_events_firewall_time_idx").on(table.firewallInstanceId, table.createdAt),
    index("enforcement_events_decision_idx").on(table.policyDecisionId),
    index("enforcement_events_action_idx").on(table.organizationId, table.action),
    foreignKey({
      name: "enforcement_events_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "enforcement_events_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("set null"),
    foreignKey({
      name: "enforcement_events_decision_fk",
      columns: [table.policyDecisionId],
      foreignColumns: [policyDecisions.id],
    }).onDelete("set null"),
    foreignKey({
      name: "enforcement_events_policy_fk",
      columns: [table.policyId],
      foreignColumns: [zeroTrustPolicies.id],
    }).onDelete("set null"),
    foreignKey({
      name: "enforcement_events_policy_version_fk",
      columns: [table.policyVersionId],
      foreignColumns: [zeroTrustPolicyVersions.id],
    }).onDelete("set null"),
    foreignKey({
      name: "enforcement_events_rule_fk",
      columns: [table.protectionRuleId],
      foreignColumns: [protectionRules.id],
    }).onDelete("set null"),
    foreignKey({
      name: "enforcement_events_rate_limit_fk",
      columns: [table.rateLimitPolicyId],
      foreignColumns: [rateLimitPolicies.id],
    }).onDelete("set null"),
    foreignKey({
      name: "enforcement_events_credential_state_fk",
      columns: [table.credentialProtectionStateId],
      foreignColumns: [credentialProtectionState.id],
    }).onDelete("set null"),
    foreignKey({
      name: "enforcement_events_alert_fk",
      columns: [table.alertId],
      foreignColumns: [alerts.id],
    }).onDelete("set null"),
    foreignKey({
      name: "enforcement_events_incident_fk",
      columns: [table.incidentId],
      foreignColumns: [incidents.id],
    }).onDelete("set null"),
    protectionActionCheck("enforcement_events_action_chk", table),
    protectionModeCheck("enforcement_events_mode_chk", table),
    enforcementOutcomeCheck("enforcement_events_outcome_chk", table),
    check("enforcement_events_risk_score_chk", sql`${table.riskScore} between 0 and 100`),
    check("enforcement_events_confidence_chk", sql`${table.confidence} between 0 and 1`),
  ],
);

export const policySimulations = pgTable(
  "policy_simulations",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    policyId: uuid("policy_id"),
    policyVersionId: uuid("policy_version_id"),
    sourceSecurityEventId: uuid("source_security_event_id"),
    sourcePolicyDecisionId: uuid("source_policy_decision_id"),
    sourceEnforcementEventId: uuid("source_enforcement_event_id"),
    mode: varchar("mode", { length: 32 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("completed"),
    inputContext: jsonb("input_context").notNull().default(sql`'{}'::jsonb`),
    simulationConfig: jsonb("simulation_config").notNull().default(sql`'{}'::jsonb`),
    impactSummary: jsonb("impact_summary").notNull().default(sql`'{}'::jsonb`),
    summary: text("summary"),
    errorMessage: text("error_message"),
    createdByUserId: uuid("created_by_user_id"),
    startedAt: timestamp("started_at", { withTimezone: true }).notNull().defaultNow(),
    completedAt: timestamp("completed_at", { withTimezone: true }),
    ...timestamps,
  },
  (table) => [
    index("policy_simulations_org_time_idx").on(table.organizationId, table.createdAt),
    index("policy_simulations_firewall_time_idx").on(table.firewallInstanceId, table.createdAt),
    index("policy_simulations_policy_time_idx").on(table.policyId, table.createdAt),
    index("policy_simulations_status_idx").on(table.organizationId, table.status),
    foreignKey({
      name: "policy_simulations_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "policy_simulations_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("set null"),
    foreignKey({
      name: "policy_simulations_policy_fk",
      columns: [table.policyId],
      foreignColumns: [zeroTrustPolicies.id],
    }).onDelete("set null"),
    foreignKey({
      name: "policy_simulations_policy_version_fk",
      columns: [table.policyVersionId],
      foreignColumns: [zeroTrustPolicyVersions.id],
    }).onDelete("set null"),
    foreignKey({
      name: "policy_simulations_security_event_fk",
      columns: [table.sourceSecurityEventId],
      foreignColumns: [securityEvents.id],
    }).onDelete("set null"),
    foreignKey({
      name: "policy_simulations_decision_fk",
      columns: [table.sourcePolicyDecisionId],
      foreignColumns: [policyDecisions.id],
    }).onDelete("set null"),
    foreignKey({
      name: "policy_simulations_enforcement_fk",
      columns: [table.sourceEnforcementEventId],
      foreignColumns: [enforcementEvents.id],
    }).onDelete("set null"),
    foreignKey({
      name: "policy_simulations_created_by_fk",
      columns: [table.createdByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    policySimulationModeCheck("policy_simulations_mode_chk", table),
    policySimulationStatusCheck("policy_simulations_status_chk", table),
  ],
);

export const simulationResults = pgTable(
  "simulation_results",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    simulationId: uuid("simulation_id").notNull(),
    policyId: uuid("policy_id"),
    policyVersionId: uuid("policy_version_id"),
    policyDecisionId: uuid("policy_decision_id"),
    enforcementEventId: uuid("enforcement_event_id"),
    expectedDecision: varchar("expected_decision", { length: 32 }).notNull(),
    expectedAction: varchar("expected_action", { length: 32 }).notNull(),
    actualAction: varchar("actual_action", { length: 32 }),
    riskScore: real("risk_score").notNull().default(0),
    confidence: real("confidence").notNull().default(0),
    matchedPolicyRuleId: varchar("matched_policy_rule_id", { length: 160 }),
    matchedProtectionRuleId: uuid("matched_protection_rule_id"),
    reasonCodes: text("reason_codes")
      .array()
      .notNull()
      .default(sql`ARRAY[]::text[]`),
    explanation: jsonb("explanation").notNull().default(sql`'{}'::jsonb`),
    regressionStatus: varchar("regression_status", { length: 32 }).notNull().default("not_applicable"),
    falsePositiveRisk: real("false_positive_risk").notNull().default(0),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index("simulation_results_org_time_idx").on(table.organizationId, table.createdAt),
    index("simulation_results_simulation_idx").on(table.simulationId),
    index("simulation_results_policy_idx").on(table.policyId, table.policyVersionId),
    foreignKey({
      name: "simulation_results_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "simulation_results_simulation_fk",
      columns: [table.simulationId],
      foreignColumns: [policySimulations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "simulation_results_policy_fk",
      columns: [table.policyId],
      foreignColumns: [zeroTrustPolicies.id],
    }).onDelete("set null"),
    foreignKey({
      name: "simulation_results_policy_version_fk",
      columns: [table.policyVersionId],
      foreignColumns: [zeroTrustPolicyVersions.id],
    }).onDelete("set null"),
    foreignKey({
      name: "simulation_results_decision_fk",
      columns: [table.policyDecisionId],
      foreignColumns: [policyDecisions.id],
    }).onDelete("set null"),
    foreignKey({
      name: "simulation_results_enforcement_fk",
      columns: [table.enforcementEventId],
      foreignColumns: [enforcementEvents.id],
    }).onDelete("set null"),
    check("simulation_results_decision_chk", sql`${table.expectedDecision} in ('allow', 'challenge', 'rate_limit', 'block', 'quarantine')`),
    protectionActionCheck("simulation_results_expected_action_chk", { action: table.expectedAction }),
    check("simulation_results_actual_action_chk", sql`${table.actualAction} is null or ${table.actualAction} in ('allow', 'challenge', 'rate_limit', 'block', 'quarantine', 'credential_suspend')`),
    check("simulation_results_regression_status_chk", sql`${table.regressionStatus} in ('not_applicable', 'passed', 'failed')`),
    check("simulation_results_risk_score_chk", sql`${table.riskScore} between 0 and 100`),
    check("simulation_results_confidence_chk", sql`${table.confidence} between 0 and 1`),
    check("simulation_results_false_positive_chk", sql`${table.falsePositiveRisk} between 0 and 1`),
  ],
);

export const policyTestCases = pgTable(
  "policy_test_cases",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    policyId: uuid("policy_id"),
    policyVersionId: uuid("policy_version_id"),
    name: varchar("name", { length: 160 }).notNull(),
    description: text("description"),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    inputContext: jsonb("input_context").notNull().default(sql`'{}'::jsonb`),
    expectedDecision: varchar("expected_decision", { length: 32 }).notNull(),
    expectedAction: varchar("expected_action", { length: 32 }).notNull(),
    lastResult: varchar("last_result", { length: 32 }),
    lastRunAt: timestamp("last_run_at", { withTimezone: true }),
    createdByUserId: uuid("created_by_user_id"),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    uniqueIndex("policy_test_cases_org_name_idx").on(table.organizationId, table.name),
    index("policy_test_cases_org_status_idx").on(table.organizationId, table.status),
    index("policy_test_cases_policy_idx").on(table.policyId, table.policyVersionId),
    foreignKey({
      name: "policy_test_cases_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "policy_test_cases_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("set null"),
    foreignKey({
      name: "policy_test_cases_policy_fk",
      columns: [table.policyId],
      foreignColumns: [zeroTrustPolicies.id],
    }).onDelete("set null"),
    foreignKey({
      name: "policy_test_cases_policy_version_fk",
      columns: [table.policyVersionId],
      foreignColumns: [zeroTrustPolicyVersions.id],
    }).onDelete("set null"),
    foreignKey({
      name: "policy_test_cases_created_by_fk",
      columns: [table.createdByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    policyTestCaseStatusCheck("policy_test_cases_status_chk", table),
    policyDecisionCheck("policy_test_cases_decision_chk", { decision: table.expectedDecision }),
    protectionActionCheck("policy_test_cases_action_chk", { action: table.expectedAction }),
    check("policy_test_cases_last_result_chk", sql`${table.lastResult} is null or ${table.lastResult} in ('passed', 'failed')`),
  ],
);

export const policyChangeRequests = pgTable(
  "policy_change_requests",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    policyId: uuid("policy_id").notNull(),
    policyVersionId: uuid("policy_version_id"),
    simulationId: uuid("simulation_id"),
    requestedAction: varchar("requested_action", { length: 32 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("requested"),
    reason: text("reason").notNull(),
    reviewerUserId: uuid("reviewer_user_id"),
    requestedByUserId: uuid("requested_by_user_id"),
    decidedAt: timestamp("decided_at", { withTimezone: true }),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    decisionNote: text("decision_note"),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    index("policy_change_requests_org_status_idx").on(table.organizationId, table.status),
    index("policy_change_requests_policy_idx").on(table.policyId, table.policyVersionId),
    index("policy_change_requests_reviewer_idx").on(table.reviewerUserId, table.status),
    foreignKey({
      name: "policy_change_requests_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "policy_change_requests_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("set null"),
    foreignKey({
      name: "policy_change_requests_policy_fk",
      columns: [table.policyId],
      foreignColumns: [zeroTrustPolicies.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "policy_change_requests_policy_version_fk",
      columns: [table.policyVersionId],
      foreignColumns: [zeroTrustPolicyVersions.id],
    }).onDelete("set null"),
    foreignKey({
      name: "policy_change_requests_simulation_fk",
      columns: [table.simulationId],
      foreignColumns: [policySimulations.id],
    }).onDelete("set null"),
    foreignKey({
      name: "policy_change_requests_reviewer_fk",
      columns: [table.reviewerUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    foreignKey({
      name: "policy_change_requests_requested_by_fk",
      columns: [table.requestedByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    policyChangeRequestStatusCheck("policy_change_requests_status_chk", table),
    check("policy_change_requests_action_chk", sql`${table.requestedAction} in ('create', 'update', 'activate', 'rollback', 'promote_to_enforce')`),
    check("policy_change_requests_expiry_chk", sql`${table.expiresAt} is null or ${table.expiresAt} > ${table.createdAt}`),
  ],
);

export const securityPlaybooks = pgTable(
  "security_playbooks",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    name: varchar("name", { length: 160 }).notNull(),
    description: text("description"),
    triggerType: varchar("trigger_type", { length: 40 }).notNull(),
    triggerConditions: jsonb("trigger_conditions").notNull().default(sql`'{}'::jsonb`),
    automationLevel: integer("automation_level").notNull().default(1),
    riskLevel: varchar("risk_level", { length: 32 }).notNull().default("medium"),
    requiresApproval: boolean("requires_approval").notNull().default(true),
    actionSequence: jsonb("action_sequence").notNull().default(sql`'[]'::jsonb`),
    rollbackPlan: jsonb("rollback_plan").notNull().default(sql`'{}'::jsonb`),
    status: varchar("status", { length: 32 }).notNull().default("draft"),
    version: integer("version").notNull().default(1),
    maxRunsPerHour: integer("max_runs_per_hour").notNull().default(20),
    cooldownSeconds: integer("cooldown_seconds").notNull().default(300),
    createdByUserId: uuid("created_by_user_id"),
    approvedByUserId: uuid("approved_by_user_id"),
    approvedAt: timestamp("approved_at", { withTimezone: true }),
    lastRunAt: timestamp("last_run_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    uniqueIndex("security_playbooks_org_name_idx").on(table.organizationId, table.name),
    index("security_playbooks_org_status_idx").on(table.organizationId, table.status),
    index("security_playbooks_trigger_idx").on(table.organizationId, table.triggerType, table.status),
    index("security_playbooks_firewall_idx").on(table.firewallInstanceId, table.status),
    foreignKey({
      name: "security_playbooks_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "security_playbooks_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("set null"),
    foreignKey({
      name: "security_playbooks_created_by_fk",
      columns: [table.createdByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    foreignKey({
      name: "security_playbooks_approved_by_fk",
      columns: [table.approvedByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    soarPlaybookStatusCheck("security_playbooks_status_chk", table),
    soarTriggerTypeCheck("security_playbooks_trigger_chk", table),
    soarAutomationLevelCheck("security_playbooks_level_chk", table),
    soarRiskLevelCheck("security_playbooks_risk_chk", table),
    check("security_playbooks_version_chk", sql`${table.version} >= 1`),
    check("security_playbooks_budget_chk", sql`${table.maxRunsPerHour} between 1 and 500 and ${table.cooldownSeconds} between 0 and 86400`),
  ],
);

export const playbookSteps = pgTable(
  "playbook_steps",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    playbookId: uuid("playbook_id").notNull(),
    stepOrder: integer("step_order").notNull().default(1),
    name: varchar("name", { length: 160 }).notNull(),
    actionType: varchar("action_type", { length: 48 }).notNull(),
    approvalRequired: boolean("approval_required").notNull().default(false),
    configuration: jsonb("configuration").notNull().default(sql`'{}'::jsonb`),
    rollbackConfiguration: jsonb("rollback_configuration").notNull().default(sql`'{}'::jsonb`),
    timeoutSeconds: integer("timeout_seconds").notNull().default(30),
    maxAttempts: integer("max_attempts").notNull().default(1),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("playbook_steps_order_idx").on(table.playbookId, table.stepOrder),
    index("playbook_steps_org_idx").on(table.organizationId, table.playbookId),
    foreignKey({
      name: "playbook_steps_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "playbook_steps_playbook_fk",
      columns: [table.playbookId],
      foreignColumns: [securityPlaybooks.id],
    }).onDelete("cascade"),
    lifecycleStatusCheck("playbook_steps_status_chk", table),
    soarResponseActionTypeCheck("playbook_steps_action_chk", table),
    check("playbook_steps_order_chk", sql`${table.stepOrder} between 1 and 100`),
    check("playbook_steps_attempts_chk", sql`${table.maxAttempts} between 1 and 10 and ${table.timeoutSeconds} between 1 and 3600`),
  ],
);

export const automationRuns = pgTable(
  "automation_runs",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    playbookId: uuid("playbook_id"),
    incidentId: uuid("incident_id"),
    alertId: uuid("alert_id"),
    securityEventId: uuid("security_event_id"),
    detectionFindingId: uuid("detection_finding_id"),
    correlationEventId: uuid("correlation_event_id"),
    threatMatchId: uuid("threat_match_id"),
    policyDecisionId: uuid("policy_decision_id"),
    enforcementEventId: uuid("enforcement_event_id"),
    notificationDeliveryId: uuid("notification_delivery_id"),
    simulationResultId: uuid("simulation_result_id"),
    triggerType: varchar("trigger_type", { length: 40 }).notNull(),
    triggerFingerprint: varchar("trigger_fingerprint", { length: 64 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("queued"),
    automationLevel: integer("automation_level").notNull().default(1),
    approvalState: varchar("approval_state", { length: 32 }).notNull().default("not_required"),
    idempotencyKey: varchar("idempotency_key", { length: 160 }).notNull(),
    playbookVersion: integer("playbook_version").notNull().default(1),
    startedByUserId: uuid("started_by_user_id"),
    approvedByUserId: uuid("approved_by_user_id"),
    startedAt: timestamp("started_at", { withTimezone: true }).notNull().defaultNow(),
    completedAt: timestamp("completed_at", { withTimezone: true }),
    resultSummary: text("result_summary"),
    failureReason: text("failure_reason"),
    evidenceSummary: jsonb("evidence_summary").notNull().default(sql`'{}'::jsonb`),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("automation_runs_idempotency_idx").on(table.organizationId, table.idempotencyKey),
    index("automation_runs_org_status_idx").on(table.organizationId, table.status, table.startedAt),
    index("automation_runs_playbook_idx").on(table.playbookId, table.startedAt),
    index("automation_runs_firewall_idx").on(table.firewallInstanceId, table.startedAt),
    foreignKey({
      name: "automation_runs_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "automation_runs_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("set null"),
    foreignKey({
      name: "automation_runs_playbook_fk",
      columns: [table.playbookId],
      foreignColumns: [securityPlaybooks.id],
    }).onDelete("set null"),
    foreignKey({
      name: "automation_runs_incident_fk",
      columns: [table.incidentId],
      foreignColumns: [incidents.id],
    }).onDelete("set null"),
    foreignKey({
      name: "automation_runs_alert_fk",
      columns: [table.alertId],
      foreignColumns: [alerts.id],
    }).onDelete("set null"),
    foreignKey({
      name: "automation_runs_security_event_fk",
      columns: [table.securityEventId],
      foreignColumns: [securityEvents.id],
    }).onDelete("set null"),
    foreignKey({
      name: "automation_runs_detection_fk",
      columns: [table.detectionFindingId],
      foreignColumns: [detectionFindings.id],
    }).onDelete("set null"),
    foreignKey({
      name: "automation_runs_correlation_fk",
      columns: [table.correlationEventId],
      foreignColumns: [correlationEvents.id],
    }).onDelete("set null"),
    foreignKey({
      name: "automation_runs_threat_match_fk",
      columns: [table.threatMatchId],
      foreignColumns: [threatMatches.id],
    }).onDelete("set null"),
    foreignKey({
      name: "automation_runs_decision_fk",
      columns: [table.policyDecisionId],
      foreignColumns: [policyDecisions.id],
    }).onDelete("set null"),
    foreignKey({
      name: "automation_runs_enforcement_fk",
      columns: [table.enforcementEventId],
      foreignColumns: [enforcementEvents.id],
    }).onDelete("set null"),
    foreignKey({
      name: "automation_runs_delivery_fk",
      columns: [table.notificationDeliveryId],
      foreignColumns: [notificationDeliveries.id],
    }).onDelete("set null"),
    foreignKey({
      name: "automation_runs_sim_result_fk",
      columns: [table.simulationResultId],
      foreignColumns: [simulationResults.id],
    }).onDelete("set null"),
    foreignKey({
      name: "automation_runs_started_by_fk",
      columns: [table.startedByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    foreignKey({
      name: "automation_runs_approved_by_fk",
      columns: [table.approvedByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    soarTriggerTypeCheck("automation_runs_trigger_chk", table),
    soarRunStatusCheck("automation_runs_status_chk", table),
    soarAutomationLevelCheck("automation_runs_level_chk", table),
    soarApprovalStateCheck("automation_runs_approval_chk", table),
  ],
);

export const responseActions = pgTable(
  "response_actions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    automationRunId: uuid("automation_run_id"),
    playbookStepId: uuid("playbook_step_id"),
    incidentId: uuid("incident_id"),
    policyDecisionId: uuid("policy_decision_id"),
    enforcementEventId: uuid("enforcement_event_id"),
    actionType: varchar("action_type", { length: 48 }).notNull(),
    targetType: varchar("target_type", { length: 80 }),
    targetRef: varchar("target_ref", { length: 240 }),
    status: varchar("status", { length: 32 }).notNull().default("pending"),
    approvalState: varchar("approval_state", { length: 32 }).notNull().default("not_required"),
    riskLevel: varchar("risk_level", { length: 32 }).notNull().default("medium"),
    idempotencyKey: varchar("idempotency_key", { length: 160 }).notNull(),
    reason: text("reason").notNull(),
    requestedByUserId: uuid("requested_by_user_id"),
    approvedByUserId: uuid("approved_by_user_id"),
    executedByUserId: uuid("executed_by_user_id"),
    executionResult: jsonb("execution_result").notNull().default(sql`'{}'::jsonb`),
    rollbackPlan: jsonb("rollback_plan").notNull().default(sql`'{}'::jsonb`),
    rollbackState: jsonb("rollback_state").notNull().default(sql`'{}'::jsonb`),
    errorMessage: text("error_message"),
    executedAt: timestamp("executed_at", { withTimezone: true }),
    completedAt: timestamp("completed_at", { withTimezone: true }),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("response_actions_idempotency_idx").on(table.organizationId, table.idempotencyKey),
    index("response_actions_org_status_idx").on(table.organizationId, table.status, table.createdAt),
    index("response_actions_run_idx").on(table.automationRunId, table.createdAt),
    index("response_actions_incident_idx").on(table.incidentId, table.createdAt),
    foreignKey({
      name: "response_actions_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "response_actions_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("set null"),
    foreignKey({
      name: "response_actions_run_fk",
      columns: [table.automationRunId],
      foreignColumns: [automationRuns.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "response_actions_step_fk",
      columns: [table.playbookStepId],
      foreignColumns: [playbookSteps.id],
    }).onDelete("set null"),
    foreignKey({
      name: "response_actions_incident_fk",
      columns: [table.incidentId],
      foreignColumns: [incidents.id],
    }).onDelete("set null"),
    foreignKey({
      name: "response_actions_decision_fk",
      columns: [table.policyDecisionId],
      foreignColumns: [policyDecisions.id],
    }).onDelete("set null"),
    foreignKey({
      name: "response_actions_enforcement_fk",
      columns: [table.enforcementEventId],
      foreignColumns: [enforcementEvents.id],
    }).onDelete("set null"),
    foreignKey({
      name: "response_actions_requested_by_fk",
      columns: [table.requestedByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    foreignKey({
      name: "response_actions_approved_by_fk",
      columns: [table.approvedByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    foreignKey({
      name: "response_actions_executed_by_fk",
      columns: [table.executedByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    soarResponseActionTypeCheck("response_actions_type_chk", table),
    soarResponseActionStatusCheck("response_actions_status_chk", table),
    soarApprovalStateCheck("response_actions_approval_chk", table),
    soarRiskLevelCheck("response_actions_risk_chk", table),
  ],
);

export const investigationCases = pgTable(
  "investigation_cases",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    incidentId: uuid("incident_id"),
    automationRunId: uuid("automation_run_id"),
    title: varchar("title", { length: 240 }).notNull(),
    summary: text("summary"),
    severity: varchar("severity", { length: 32 }).notNull().default("medium"),
    status: varchar("status", { length: 32 }).notNull().default("open"),
    assignedToUserId: uuid("assigned_to_user_id"),
    createdByUserId: uuid("created_by_user_id"),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true }).notNull().defaultNow(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true }).notNull().defaultNow(),
    slaDueAt: timestamp("sla_due_at", { withTimezone: true }),
    resolvedAt: timestamp("resolved_at", { withTimezone: true }),
    resolution: text("resolution"),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    index("investigation_cases_org_status_idx").on(table.organizationId, table.status, table.lastSeenAt),
    index("investigation_cases_firewall_idx").on(table.firewallInstanceId, table.lastSeenAt),
    index("investigation_cases_incident_idx").on(table.incidentId),
    foreignKey({
      name: "investigation_cases_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "investigation_cases_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("set null"),
    foreignKey({
      name: "investigation_cases_incident_fk",
      columns: [table.incidentId],
      foreignColumns: [incidents.id],
    }).onDelete("set null"),
    foreignKey({
      name: "investigation_cases_run_fk",
      columns: [table.automationRunId],
      foreignColumns: [automationRuns.id],
    }).onDelete("set null"),
    foreignKey({
      name: "investigation_cases_assigned_user_fk",
      columns: [table.assignedToUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    foreignKey({
      name: "investigation_cases_created_by_fk",
      columns: [table.createdByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    investigationCaseStatusCheck("investigation_cases_status_chk", table),
    securityEventSeverityCheck("investigation_cases_severity_chk", table),
  ],
);

export const evidenceItems = pgTable(
  "evidence_items",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    investigationCaseId: uuid("investigation_case_id"),
    incidentId: uuid("incident_id"),
    automationRunId: uuid("automation_run_id"),
    responseActionId: uuid("response_action_id"),
    sourceType: varchar("source_type", { length: 48 }).notNull(),
    sourceRefId: uuid("source_ref_id"),
    evidenceType: varchar("evidence_type", { length: 80 }).notNull(),
    evidenceHash: varchar("evidence_hash", { length: 64 }).notNull(),
    occurredAt: timestamp("occurred_at", { withTimezone: true }).notNull().defaultNow(),
    collectedByUserId: uuid("collected_by_user_id"),
    retentionClass: varchar("retention_class", { length: 40 }).notNull().default("incident_1y"),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    index("evidence_items_org_time_idx").on(table.organizationId, table.occurredAt),
    index("evidence_items_case_idx").on(table.investigationCaseId, table.occurredAt),
    index("evidence_items_run_idx").on(table.automationRunId, table.occurredAt),
    index("evidence_items_source_idx").on(table.sourceType, table.sourceRefId),
    foreignKey({
      name: "evidence_items_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "evidence_items_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("set null"),
    foreignKey({
      name: "evidence_items_case_fk",
      columns: [table.investigationCaseId],
      foreignColumns: [investigationCases.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "evidence_items_incident_fk",
      columns: [table.incidentId],
      foreignColumns: [incidents.id],
    }).onDelete("set null"),
    foreignKey({
      name: "evidence_items_run_fk",
      columns: [table.automationRunId],
      foreignColumns: [automationRuns.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "evidence_items_action_fk",
      columns: [table.responseActionId],
      foreignColumns: [responseActions.id],
    }).onDelete("set null"),
    foreignKey({
      name: "evidence_items_collected_by_fk",
      columns: [table.collectedByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    evidenceSourceTypeCheck("evidence_items_source_type_chk", table),
    check("evidence_items_retention_chk", sql`${table.retentionClass} in ('incident_90d', 'incident_1y', 'audit_1y', 'customer_policy')`),
  ],
);

export const aiSessions = pgTable(
  "ai_sessions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    userId: uuid("user_id").notNull(),
    firewallInstanceId: uuid("firewall_instance_id"),
    title: varchar("title", { length: 200 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    purpose: varchar("purpose", { length: 80 }).notNull().default("security_analysis"),
    lastMessageAt: timestamp("last_message_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    index("ai_sessions_org_status_idx").on(table.organizationId, table.status, table.updatedAt),
    index("ai_sessions_user_time_idx").on(table.userId, table.updatedAt),
    index("ai_sessions_firewall_idx").on(table.firewallInstanceId, table.updatedAt),
    foreignKey({
      name: "ai_sessions_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "ai_sessions_user_fk",
      columns: [table.userId],
      foreignColumns: [users.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "ai_sessions_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("set null"),
    aiSessionStatusCheck("ai_sessions_status_chk", table),
  ],
);

export const aiMessages = pgTable(
  "ai_messages",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    sessionId: uuid("session_id").notNull(),
    userId: uuid("user_id"),
    role: varchar("role", { length: 24 }).notNull(),
    content: text("content").notNull(),
    sanitizedContext: jsonb("sanitized_context").notNull().default(sql`'{}'::jsonb`),
    evidenceRefs: jsonb("evidence_refs").notNull().default(sql`'[]'::jsonb`),
    guardrailResult: jsonb("guardrail_result").notNull().default(sql`'{}'::jsonb`),
    provider: varchar("provider", { length: 80 }).notNull().default("local_advisory"),
    model: varchar("model", { length: 120 }).notNull().default("deterministic-summary"),
    confidence: real("confidence").notNull().default(0.6),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index("ai_messages_org_time_idx").on(table.organizationId, table.createdAt),
    index("ai_messages_session_time_idx").on(table.sessionId, table.createdAt),
    foreignKey({
      name: "ai_messages_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "ai_messages_session_fk",
      columns: [table.sessionId],
      foreignColumns: [aiSessions.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "ai_messages_user_fk",
      columns: [table.userId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    aiMessageRoleCheck("ai_messages_role_chk", table),
    check("ai_messages_confidence_chk", sql`${table.confidence} between 0 and 1`),
  ],
);

export const aiAnalysisReports = pgTable(
  "ai_analysis_reports",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    userId: uuid("user_id"),
    sessionId: uuid("session_id"),
    incidentId: uuid("incident_id"),
    firewallInstanceId: uuid("firewall_instance_id"),
    reportType: varchar("report_type", { length: 40 }).notNull(),
    title: varchar("title", { length: 240 }).notNull(),
    summary: text("summary").notNull(),
    findings: jsonb("findings").notNull().default(sql`'[]'::jsonb`),
    recommendations: jsonb("recommendations").notNull().default(sql`'[]'::jsonb`),
    evidenceRefs: jsonb("evidence_refs").notNull().default(sql`'[]'::jsonb`),
    guardrailResult: jsonb("guardrail_result").notNull().default(sql`'{}'::jsonb`),
    provider: varchar("provider", { length: 80 }).notNull().default("local_advisory"),
    model: varchar("model", { length: 120 }).notNull().default("deterministic-summary"),
    confidence: real("confidence").notNull().default(0.6),
    generatedAt: timestamp("generated_at", { withTimezone: true }).notNull().defaultNow(),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    index("ai_reports_org_type_time_idx").on(table.organizationId, table.reportType, table.generatedAt),
    index("ai_reports_incident_idx").on(table.incidentId, table.generatedAt),
    index("ai_reports_session_idx").on(table.sessionId, table.generatedAt),
    foreignKey({
      name: "ai_reports_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "ai_reports_user_fk",
      columns: [table.userId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    foreignKey({
      name: "ai_reports_session_fk",
      columns: [table.sessionId],
      foreignColumns: [aiSessions.id],
    }).onDelete("set null"),
    foreignKey({
      name: "ai_reports_incident_fk",
      columns: [table.incidentId],
      foreignColumns: [incidents.id],
    }).onDelete("set null"),
    foreignKey({
      name: "ai_reports_firewall_fk",
      columns: [table.firewallInstanceId],
      foreignColumns: [firewallInstances.id],
    }).onDelete("set null"),
    aiReportTypeCheck("ai_reports_type_chk", table),
    check("ai_reports_confidence_chk", sql`${table.confidence} between 0 and 1`),
  ],
);

export const aiFeedback = pgTable(
  "ai_feedback",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    messageId: uuid("message_id"),
    reportId: uuid("report_id"),
    userId: uuid("user_id").notNull(),
    rating: varchar("rating", { length: 32 }).notNull(),
    feedback: text("feedback"),
    reviewedByUserId: uuid("reviewed_by_user_id"),
    reviewedAt: timestamp("reviewed_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    index("ai_feedback_org_rating_idx").on(table.organizationId, table.rating, table.createdAt),
    index("ai_feedback_message_idx").on(table.messageId),
    index("ai_feedback_report_idx").on(table.reportId),
    foreignKey({
      name: "ai_feedback_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "ai_feedback_message_fk",
      columns: [table.messageId],
      foreignColumns: [aiMessages.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "ai_feedback_report_fk",
      columns: [table.reportId],
      foreignColumns: [aiAnalysisReports.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "ai_feedback_user_fk",
      columns: [table.userId],
      foreignColumns: [users.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "ai_feedback_reviewed_by_fk",
      columns: [table.reviewedByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    aiFeedbackRatingCheck("ai_feedback_rating_chk", table),
    check("ai_feedback_target_chk", sql`${table.messageId} is not null or ${table.reportId} is not null`),
  ],
);

export const organizationHierarchy = pgTable(
  "organization_hierarchy",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    parentOrganizationId: uuid("parent_organization_id").notNull(),
    childOrganizationId: uuid("child_organization_id").notNull(),
    relationshipType: varchar("relationship_type", { length: 40 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    delegationMode: varchar("delegation_mode", { length: 40 }).notNull().default("explicit"),
    createdByUserId: uuid("created_by_user_id"),
    approvedByUserId: uuid("approved_by_user_id"),
    approvedAt: timestamp("approved_at", { withTimezone: true }),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("organization_hierarchy_parent_child_idx").on(
      table.parentOrganizationId,
      table.childOrganizationId,
    ),
    index("organization_hierarchy_parent_status_idx").on(table.parentOrganizationId, table.status),
    index("organization_hierarchy_child_status_idx").on(table.childOrganizationId, table.status),
    foreignKey({
      name: "organization_hierarchy_parent_fk",
      columns: [table.parentOrganizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "organization_hierarchy_child_fk",
      columns: [table.childOrganizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "organization_hierarchy_created_by_fk",
      columns: [table.createdByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    foreignKey({
      name: "organization_hierarchy_approved_by_fk",
      columns: [table.approvedByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    organizationRelationshipTypeCheck("organization_hierarchy_type_chk", table),
    organizationRelationshipStatusCheck("organization_hierarchy_status_chk", table),
    check("organization_hierarchy_no_self_parent_chk", sql`${table.parentOrganizationId} <> ${table.childOrganizationId}`),
  ],
);

export const delegatedAccessGrants = pgTable(
  "delegated_access_grants",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    providerOrganizationId: uuid("provider_organization_id").notNull(),
    customerOrganizationId: uuid("customer_organization_id").notNull(),
    userId: uuid("user_id"),
    accessLevel: varchar("access_level", { length: 32 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("pending"),
    permissions: jsonb("permissions").notNull().default(sql`'[]'::jsonb`),
    approvalState: varchar("approval_state", { length: 32 }).notNull().default("pending_customer_approval"),
    justification: text("justification"),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    approvedByUserId: uuid("approved_by_user_id"),
    revokedByUserId: uuid("revoked_by_user_id"),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    index("delegated_access_provider_status_idx").on(table.providerOrganizationId, table.status),
    index("delegated_access_customer_status_idx").on(table.customerOrganizationId, table.status),
    index("delegated_access_user_status_idx").on(table.userId, table.status),
    foreignKey({
      name: "delegated_access_provider_fk",
      columns: [table.providerOrganizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "delegated_access_customer_fk",
      columns: [table.customerOrganizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "delegated_access_user_fk",
      columns: [table.userId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    foreignKey({
      name: "delegated_access_approved_by_fk",
      columns: [table.approvedByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    foreignKey({
      name: "delegated_access_revoked_by_fk",
      columns: [table.revokedByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    delegatedAccessLevelCheck("delegated_access_level_chk", table),
    delegatedAccessStatusCheck("delegated_access_status_chk", table),
    check("delegated_access_distinct_orgs_chk", sql`${table.providerOrganizationId} <> ${table.customerOrganizationId}`),
  ],
);

export const tenantSettings = pgTable(
  "tenant_settings",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    planKey: varchar("plan_key", { length: 40 }).notNull().default("starter"),
    lifecycleStatus: varchar("lifecycle_status", { length: 40 }).notNull().default("provisioning"),
    dataResidency: varchar("data_residency", { length: 80 }).notNull().default("global"),
    retentionDays: integer("retention_days").notNull().default(90),
    msspEnabled: boolean("mssp_enabled").notNull().default(false),
    delegatedAccessRequiresApproval: boolean("delegated_access_requires_approval").notNull().default(true),
    maxFirewalls: integer("max_firewalls").notNull().default(5),
    maxUsers: integer("max_users").notNull().default(10),
    features: jsonb("features").notNull().default(sql`'{}'::jsonb`),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("tenant_settings_organization_idx").on(table.organizationId),
    index("tenant_settings_plan_status_idx").on(table.planKey, table.lifecycleStatus),
    foreignKey({
      name: "tenant_settings_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    enterprisePlanCheck("tenant_settings_plan_chk", table),
    tenantLifecycleStatusCheck("tenant_settings_lifecycle_chk", table),
    check("tenant_settings_retention_days_chk", sql`${table.retentionDays} between 7 and 2555`),
    check("tenant_settings_max_firewalls_chk", sql`${table.maxFirewalls} >= 0`),
    check("tenant_settings_max_users_chk", sql`${table.maxUsers} >= 0`),
  ],
);

export const customerContacts = pgTable(
  "customer_contacts",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    parentOrganizationId: uuid("parent_organization_id"),
    contactType: varchar("contact_type", { length: 32 }).notNull(),
    name: varchar("name", { length: 160 }).notNull(),
    email: varchar("email", { length: 320 }).notNull(),
    phone: varchar("phone", { length: 64 }),
    escalationPriority: integer("escalation_priority").notNull().default(1),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    index("customer_contacts_org_type_idx").on(table.organizationId, table.contactType),
    index("customer_contacts_parent_idx").on(table.parentOrganizationId),
    foreignKey({
      name: "customer_contacts_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "customer_contacts_parent_fk",
      columns: [table.parentOrganizationId],
      foreignColumns: [organizations.id],
    }).onDelete("set null"),
    customerContactTypeCheck("customer_contacts_type_chk", table),
    lifecycleStatusCheck("customer_contacts_status_chk", table),
    check("customer_contacts_escalation_priority_chk", sql`${table.escalationPriority} between 1 and 5`),
  ],
);

export const complianceReports = pgTable(
  "compliance_reports",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    requestedByUserId: uuid("requested_by_user_id"),
    reportType: varchar("report_type", { length: 48 }).notNull(),
    framework: varchar("framework", { length: 80 }).notNull().default("nist_csf"),
    status: varchar("status", { length: 32 }).notNull().default("draft"),
    title: varchar("title", { length: 240 }).notNull(),
    periodStart: timestamp("period_start", { withTimezone: true }).notNull(),
    periodEnd: timestamp("period_end", { withTimezone: true }).notNull(),
    summary: text("summary").notNull(),
    evidenceRefs: jsonb("evidence_refs").notNull().default(sql`'[]'::jsonb`),
    controlMappings: jsonb("control_mappings").notNull().default(sql`'[]'::jsonb`),
    generatedAiReportId: uuid("generated_ai_report_id"),
    publishedAt: timestamp("published_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    index("compliance_reports_org_type_time_idx").on(table.organizationId, table.reportType, table.periodEnd),
    index("compliance_reports_status_idx").on(table.organizationId, table.status, table.updatedAt),
    foreignKey({
      name: "compliance_reports_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "compliance_reports_requested_by_fk",
      columns: [table.requestedByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    foreignKey({
      name: "compliance_reports_ai_report_fk",
      columns: [table.generatedAiReportId],
      foreignColumns: [aiAnalysisReports.id],
    }).onDelete("set null"),
    complianceReportTypeCheck("compliance_reports_type_chk", table),
    complianceReportStatusCheck("compliance_reports_status_chk", table),
    check("compliance_reports_period_chk", sql`${table.periodEnd} >= ${table.periodStart}`),
  ],
);

export const usageRecords = pgTable(
  "usage_records",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    metricType: varchar("metric_type", { length: 64 }).notNull(),
    quantity: integer("quantity").notNull().default(0),
    periodStart: timestamp("period_start", { withTimezone: true }).notNull(),
    periodEnd: timestamp("period_end", { withTimezone: true }).notNull(),
    source: varchar("source", { length: 80 }).notNull().default("system"),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    index("usage_records_org_metric_period_idx").on(table.organizationId, table.metricType, table.periodStart),
    index("usage_records_period_idx").on(table.periodStart, table.periodEnd),
    foreignKey({
      name: "usage_records_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    usageMetricTypeCheck("usage_records_metric_type_chk", table),
    check("usage_records_quantity_chk", sql`${table.quantity} >= 0`),
    check("usage_records_period_chk", sql`${table.periodEnd} >= ${table.periodStart}`),
  ],
);

export const platformRegions = pgTable(
  "platform_regions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    regionKey: varchar("region_key", { length: 80 }).notNull(),
    name: varchar("name", { length: 160 }).notNull(),
    geography: varchar("geography", { length: 120 }).notNull(),
    provider: varchar("provider", { length: 80 }).notNull().default("multi_provider"),
    status: varchar("status", { length: 32 }).notNull().default("planned"),
    dataResidencyClass: varchar("data_residency_class", { length: 80 }).notNull().default("standard"),
    primaryControlPlane: boolean("primary_control_plane").notNull().default(false),
    failoverAllowed: boolean("failover_allowed").notNull().default(false),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("platform_regions_key_idx").on(table.regionKey),
    index("platform_regions_status_idx").on(table.status),
    platformRegionStatusCheck("platform_regions_status_chk", table),
  ],
);

export const tenantRegionAssignments = pgTable(
  "tenant_region_assignments",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    regionId: uuid("region_id").notNull(),
    assignmentType: varchar("assignment_type", { length: 40 }).notNull().default("home"),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    routingPriority: integer("routing_priority").notNull().default(100),
    residencyLocked: boolean("residency_locked").notNull().default(true),
    failoverRegionIds: jsonb("failover_region_ids").notNull().default(sql`'[]'::jsonb`),
    assignedByUserId: uuid("assigned_by_user_id"),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("tenant_region_assignments_org_region_type_idx").on(
      table.organizationId,
      table.regionId,
      table.assignmentType,
    ),
    index("tenant_region_assignments_org_status_idx").on(table.organizationId, table.status),
    index("tenant_region_assignments_region_status_idx").on(table.regionId, table.status),
    foreignKey({
      name: "tenant_region_assignments_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "tenant_region_assignments_region_fk",
      columns: [table.regionId],
      foreignColumns: [platformRegions.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "tenant_region_assignments_assigned_by_fk",
      columns: [table.assignedByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    check("tenant_region_assignments_type_chk", sql`${table.assignmentType} in ('home', 'failover', 'processing', 'archive')`),
    lifecycleStatusCheck("tenant_region_assignments_status_chk", table),
    check("tenant_region_assignments_priority_chk", sql`${table.routingPriority} between 1 and 1000`),
  ],
);

export const regionalServices = pgTable(
  "regional_services",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    regionId: uuid("region_id").notNull(),
    organizationId: uuid("organization_id"),
    serviceType: varchar("service_type", { length: 48 }).notNull(),
    name: varchar("name", { length: 160 }).notNull(),
    provider: varchar("provider", { length: 80 }).notNull().default("unknown"),
    status: varchar("status", { length: 32 }).notNull().default("planned"),
    endpointHost: varchar("endpoint_host", { length: 255 }),
    healthCheckPath: varchar("health_check_path", { length: 160 }).notNull().default("/healthz"),
    lastHealthyAt: timestamp("last_healthy_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    index("regional_services_region_type_idx").on(table.regionId, table.serviceType),
    index("regional_services_org_type_idx").on(table.organizationId, table.serviceType),
    index("regional_services_status_idx").on(table.status),
    foreignKey({
      name: "regional_services_region_fk",
      columns: [table.regionId],
      foreignColumns: [platformRegions.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "regional_services_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    regionalServiceTypeCheck("regional_services_type_chk", table),
    regionalServiceStatusCheck("regional_services_status_chk", table),
  ],
);

export const residencyPolicies = pgTable(
  "residency_policies",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    homeRegionId: uuid("home_region_id").notNull(),
    policyName: varchar("policy_name", { length: 160 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("draft"),
    allowedRegionIds: jsonb("allowed_region_ids").notNull().default(sql`'[]'::jsonb`),
    restrictedDataClasses: jsonb("restricted_data_classes").notNull().default(sql`'[]'::jsonb`),
    crossRegionExportAllowed: boolean("cross_region_export_allowed").notNull().default(false),
    aiProcessingRegionLocked: boolean("ai_processing_region_locked").notNull().default(true),
    approvedByUserId: uuid("approved_by_user_id"),
    approvedAt: timestamp("approved_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    index("residency_policies_org_status_idx").on(table.organizationId, table.status),
    index("residency_policies_home_region_idx").on(table.homeRegionId),
    foreignKey({
      name: "residency_policies_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "residency_policies_region_fk",
      columns: [table.homeRegionId],
      foreignColumns: [platformRegions.id],
    }).onDelete("restrict"),
    foreignKey({
      name: "residency_policies_approved_by_fk",
      columns: [table.approvedByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    residencyPolicyStatusCheck("residency_policies_status_chk", table),
  ],
);

export const platformHealthRecords = pgTable(
  "platform_health_records",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id"),
    regionId: uuid("region_id"),
    serviceId: uuid("service_id"),
    serviceType: varchar("service_type", { length: 48 }).notNull(),
    status: varchar("status", { length: 32 }).notNull(),
    availabilityPercent: real("availability_percent").notNull().default(100),
    latencyP95Ms: integer("latency_p95_ms").notNull().default(0),
    errorRatePercent: real("error_rate_percent").notNull().default(0),
    checkedAt: timestamp("checked_at", { withTimezone: true }).notNull().defaultNow(),
    details: jsonb("details").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    index("platform_health_org_time_idx").on(table.organizationId, table.checkedAt),
    index("platform_health_region_time_idx").on(table.regionId, table.checkedAt),
    index("platform_health_service_status_idx").on(table.serviceType, table.status, table.checkedAt),
    foreignKey({
      name: "platform_health_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "platform_health_region_fk",
      columns: [table.regionId],
      foreignColumns: [platformRegions.id],
    }).onDelete("set null"),
    foreignKey({
      name: "platform_health_service_fk",
      columns: [table.serviceId],
      foreignColumns: [regionalServices.id],
    }).onDelete("set null"),
    regionalServiceTypeCheck("platform_health_service_type_chk", table),
    platformHealthStatusCheck("platform_health_status_chk", table),
    check("platform_health_availability_chk", sql`${table.availabilityPercent} between 0 and 100`),
    check("platform_health_latency_chk", sql`${table.latencyP95Ms} >= 0`),
    check("platform_health_error_rate_chk", sql`${table.errorRatePercent} between 0 and 100`),
  ],
);

export const backupJobs = pgTable(
  "backup_jobs",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    regionId: uuid("region_id"),
    backupType: varchar("backup_type", { length: 40 }).notNull().default("database"),
    status: varchar("status", { length: 32 }).notNull().default("scheduled"),
    startedAt: timestamp("started_at", { withTimezone: true }),
    completedAt: timestamp("completed_at", { withTimezone: true }),
    rpoMinutes: integer("rpo_minutes").notNull().default(1440),
    retentionDays: integer("retention_days").notNull().default(30),
    storageLocationRef: varchar("storage_location_ref", { length: 160 }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    index("backup_jobs_org_status_idx").on(table.organizationId, table.status, table.createdAt),
    index("backup_jobs_region_status_idx").on(table.regionId, table.status),
    foreignKey({
      name: "backup_jobs_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "backup_jobs_region_fk",
      columns: [table.regionId],
      foreignColumns: [platformRegions.id],
    }).onDelete("set null"),
    backupJobStatusCheck("backup_jobs_status_chk", table),
    check("backup_jobs_type_chk", sql`${table.backupType} in ('database', 'event_archive', 'configuration', 'evidence_bundle')`),
    check("backup_jobs_rpo_chk", sql`${table.rpoMinutes} >= 0`),
    check("backup_jobs_retention_chk", sql`${table.retentionDays} between 1 and 3650`),
  ],
);

export const restoreOperations = pgTable(
  "restore_operations",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    backupJobId: uuid("backup_job_id"),
    targetRegionId: uuid("target_region_id"),
    status: varchar("status", { length: 32 }).notNull().default("requested"),
    requestedByUserId: uuid("requested_by_user_id"),
    approvedByUserId: uuid("approved_by_user_id"),
    startedAt: timestamp("started_at", { withTimezone: true }),
    completedAt: timestamp("completed_at", { withTimezone: true }),
    validationResult: jsonb("validation_result").notNull().default(sql`'{}'::jsonb`),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    index("restore_operations_org_status_idx").on(table.organizationId, table.status, table.createdAt),
    index("restore_operations_backup_idx").on(table.backupJobId),
    foreignKey({
      name: "restore_operations_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "restore_operations_backup_fk",
      columns: [table.backupJobId],
      foreignColumns: [backupJobs.id],
    }).onDelete("set null"),
    foreignKey({
      name: "restore_operations_region_fk",
      columns: [table.targetRegionId],
      foreignColumns: [platformRegions.id],
    }).onDelete("set null"),
    foreignKey({
      name: "restore_operations_requested_by_fk",
      columns: [table.requestedByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    foreignKey({
      name: "restore_operations_approved_by_fk",
      columns: [table.approvedByUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    restoreOperationStatusCheck("restore_operations_status_chk", table),
  ],
);

export const recoveryEvents = pgTable(
  "recovery_events",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    regionId: uuid("region_id"),
    backupJobId: uuid("backup_job_id"),
    restoreOperationId: uuid("restore_operation_id"),
    eventType: varchar("event_type", { length: 48 }).notNull(),
    severity: varchar("severity", { length: 32 }).notNull().default("info"),
    summary: text("summary").notNull(),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => [
    index("recovery_events_org_time_idx").on(table.organizationId, table.createdAt),
    index("recovery_events_region_type_idx").on(table.regionId, table.eventType),
    foreignKey({
      name: "recovery_events_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "recovery_events_region_fk",
      columns: [table.regionId],
      foreignColumns: [platformRegions.id],
    }).onDelete("set null"),
    foreignKey({
      name: "recovery_events_backup_fk",
      columns: [table.backupJobId],
      foreignColumns: [backupJobs.id],
    }).onDelete("set null"),
    foreignKey({
      name: "recovery_events_restore_fk",
      columns: [table.restoreOperationId],
      foreignColumns: [restoreOperations.id],
    }).onDelete("set null"),
    recoveryEventTypeCheck("recovery_events_type_chk", table),
    check("recovery_events_severity_chk", sql`${table.severity} in ('info', 'low', 'medium', 'high', 'critical')`),
  ],
);

export const developerApps = pgTable(
  "developer_apps",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    ownerUserId: uuid("owner_user_id"),
    name: varchar("name", { length: 160 }).notNull(),
    slug: varchar("slug", { length: 120 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    appType: varchar("app_type", { length: 48 }).notNull().default("api_consumer"),
    callbackUrls: jsonb("callback_urls").notNull().default(sql`'[]'::jsonb`),
    allowedScopes: jsonb("allowed_scopes").notNull().default(sql`'[]'::jsonb`),
    rateLimitPerMinute: integer("rate_limit_per_minute").notNull().default(60),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    uniqueIndex("developer_apps_org_slug_idx").on(table.organizationId, table.slug),
    index("developer_apps_org_status_idx").on(table.organizationId, table.status),
    foreignKey({
      name: "developer_apps_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "developer_apps_owner_fk",
      columns: [table.ownerUserId],
      foreignColumns: [users.id],
    }).onDelete("set null"),
    developerAppStatusCheck("developer_apps_status_chk", table),
    check("developer_apps_type_chk", sql`${table.appType} in ('api_consumer', 'webhook_app', 'partner_integration', 'internal_tool')`),
    check("developer_apps_rate_limit_chk", sql`${table.rateLimitPerMinute} between 1 and 100000`),
  ],
);

export const integrationCatalog = pgTable(
  "integration_catalog",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id"),
    publisherOrganizationId: uuid("publisher_organization_id"),
    name: varchar("name", { length: 160 }).notNull(),
    slug: varchar("slug", { length: 120 }).notNull(),
    category: varchar("category", { length: 48 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("draft"),
    capabilityManifest: jsonb("capability_manifest").notNull().default(sql`'{}'::jsonb`),
    permissionManifest: jsonb("permission_manifest").notNull().default(sql`'[]'::jsonb`),
    securityReviewStatus: varchar("security_review_status", { length: 40 }).notNull().default("not_started"),
    version: varchar("version", { length: 40 }).notNull().default("0.1.0"),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    uniqueIndex("integration_catalog_slug_idx").on(table.slug),
    index("integration_catalog_category_status_idx").on(table.category, table.status),
    index("integration_catalog_org_idx").on(table.organizationId),
    foreignKey({
      name: "integration_catalog_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "integration_catalog_publisher_fk",
      columns: [table.publisherOrganizationId],
      foreignColumns: [organizations.id],
    }).onDelete("set null"),
    integrationCategoryCheck("integration_catalog_category_chk", table),
    integrationCatalogStatusCheck("integration_catalog_status_chk", table),
    check("integration_catalog_security_review_chk", sql`${table.securityReviewStatus} in ('not_started', 'in_review', 'approved', 'rejected', 'expired')`),
  ],
);

export const webhookSubscriptions = pgTable(
  "webhook_subscriptions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    organizationId: uuid("organization_id").notNull(),
    developerAppId: uuid("developer_app_id"),
    integrationId: uuid("integration_id"),
    name: varchar("name", { length: 160 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("active"),
    eventTypes: jsonb("event_types").notNull().default(sql`'[]'::jsonb`),
    endpointHost: varchar("endpoint_host", { length: 255 }).notNull(),
    signingKeyRef: varchar("signing_key_ref", { length: 160 }),
    retryPolicy: jsonb("retry_policy").notNull().default(sql`'{}'::jsonb`),
    lastDeliveryAt: timestamp("last_delivery_at", { withTimezone: true }),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    index("webhook_subscriptions_org_status_idx").on(table.organizationId, table.status),
    index("webhook_subscriptions_app_idx").on(table.developerAppId),
    foreignKey({
      name: "webhook_subscriptions_org_fk",
      columns: [table.organizationId],
      foreignColumns: [organizations.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "webhook_subscriptions_app_fk",
      columns: [table.developerAppId],
      foreignColumns: [developerApps.id],
    }).onDelete("set null"),
    foreignKey({
      name: "webhook_subscriptions_integration_fk",
      columns: [table.integrationId],
      foreignColumns: [integrationCatalog.id],
    }).onDelete("set null"),
    webhookSubscriptionStatusCheck("webhook_subscriptions_status_chk", table),
  ],
);

export const marketplaceListings = pgTable(
  "marketplace_listings",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    integrationId: uuid("integration_id").notNull(),
    publisherOrganizationId: uuid("publisher_organization_id"),
    name: varchar("name", { length: 160 }).notNull(),
    category: varchar("category", { length: 48 }).notNull(),
    status: varchar("status", { length: 32 }).notNull().default("draft"),
    summary: text("summary").notNull(),
    capabilities: jsonb("capabilities").notNull().default(sql`'[]'::jsonb`),
    pricingModel: varchar("pricing_model", { length: 48 }).notNull().default("bring_your_own_license"),
    securityReviewStatus: varchar("security_review_status", { length: 40 }).notNull().default("not_started"),
    metadata: jsonb("metadata").notNull().default(sql`'{}'::jsonb`),
    ...timestamps,
  },
  (table) => [
    index("marketplace_listings_category_status_idx").on(table.category, table.status),
    index("marketplace_listings_publisher_idx").on(table.publisherOrganizationId),
    foreignKey({
      name: "marketplace_listings_integration_fk",
      columns: [table.integrationId],
      foreignColumns: [integrationCatalog.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "marketplace_listings_publisher_fk",
      columns: [table.publisherOrganizationId],
      foreignColumns: [organizations.id],
    }).onDelete("set null"),
    integrationCategoryCheck("marketplace_listings_category_chk", table),
    marketplaceListingStatusCheck("marketplace_listings_status_chk", table),
    check("marketplace_listings_security_review_chk", sql`${table.securityReviewStatus} in ('not_started', 'in_review', 'approved', 'rejected', 'expired')`),
  ],
);
