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
