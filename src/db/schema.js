import { sql } from "drizzle-orm";
import {
  boolean,
  check,
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

const securityEventSeverityCheck = (name, table) =>
  check(name, sql`${table.severity} in ('low', 'medium', 'high', 'critical')`);

const securityEventActionCheck = (name, table) =>
  check(name, sql`${table.actionTaken} in ('blocked', 'allowed', 'rate_limited', 'challenged')`);

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
    ...timestamps,
    ...deletedAt,
  },
  (table) => [
    uniqueIndex("firewall_instances_org_name_idx").on(table.organizationId, table.name),
    index("firewall_instances_organization_id_idx").on(table.organizationId),
    lifecycleStatusCheck("firewall_instances_status_check", table),
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
    securityEventSeverityCheck("security_events_severity_check", table),
    securityEventActionCheck("security_events_action_taken_check", table),
    check("security_events_confidence_check", sql`${table.confidence} between 0 and 1`),
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
