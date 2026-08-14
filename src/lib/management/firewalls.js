import "server-only";

import crypto from "node:crypto";
import { and, eq, isNull, sql } from "drizzle-orm";
import { db } from "../../db/client.js";
import {
  firewallEnrollmentTokens,
  firewallInstanceRoleAssignments,
  firewallInstances,
  serviceAccounts,
  userRoles,
} from "../../db/schema.js";
import {
  AUDIT_EVENT_TYPES,
  AUDIT_RESULTS,
  AUDIT_SEVERITIES,
  createAuditEvent,
} from "../audit/index.js";
import { createApiKey } from "../api-keys/index.js";
import { updateSessionActiveFirewall } from "../auth/session.js";
import { boundedLimit, generateOneTimeToken, hashOneTimeToken, safeString } from "./tokens.js";

export const ENROLLMENT_TOKEN_TTL_SECONDS = 15 * 60;

export async function listFirewalls({ database = db(), organizationId, limit } = {}) {
  return database
    .select()
    .from(firewallInstances)
    .where(and(eq(firewallInstances.organizationId, organizationId), isNull(firewallInstances.deletedAt)))
    .limit(boundedLimit(limit, 100, 200));
}

export async function registerFirewall({
  database = db(),
  organizationId,
  name,
  environment,
  region,
  hostname,
  membershipId,
  auditContext,
} = {}) {
  const values = {
    organizationId,
    name: safeString(name, 160),
    environment: safeString(environment, 64) || "production",
    region: safeString(region, 80),
    hostname: safeString(hostname, 255),
    status: "disabled",
  };

  if (!values.organizationId || !values.name) {
    throw new Error("organizationId and firewall name are required");
  }

  return database.transaction(async (tx) => {
    const [created] = await tx.insert(firewallInstances).values(values).returning();

    if (membershipId) {
      const [role] = await tx
        .select({ roleId: userRoles.roleId })
        .from(userRoles)
        .where(eq(userRoles.membershipId, membershipId))
        .limit(1);

      if (role?.roleId) {
        await tx
          .insert(firewallInstanceRoleAssignments)
          .values({
            firewallInstanceId: created.id,
            membershipId,
            roleId: role.roleId,
          })
          .onConflictDoNothing();
      }
    }

    await recordFirewallAudit(
      tx,
      AUDIT_EVENT_TYPES.FIREWALL_REGISTERED,
      created,
      auditContext,
    );
    return created;
  });
}

export async function createFirewallEnrollmentToken({
  database = db(),
  organizationId,
  firewallInstanceId,
  createdByUserId,
  auditContext,
  now = new Date(),
} = {}) {
  const firewall = await getOrganizationFirewall(database, organizationId, firewallInstanceId);
  if (!firewall || firewall.deletedAt || firewall.status === "deleted") {
    return null;
  }

  const plaintextToken = generateOneTimeToken("enroll");
  const tokenHash = hashOneTimeToken(plaintextToken);
  const expiresAt = new Date(now.getTime() + ENROLLMENT_TOKEN_TTL_SECONDS * 1000);

  const [token] = await database
    .insert(firewallEnrollmentTokens)
    .values({
      organizationId,
      firewallInstanceId,
      tokenHash,
      status: "pending",
      expiresAt,
      createdByUserId,
    })
    .returning();

  await recordFirewallAudit(
    database,
    AUDIT_EVENT_TYPES.FIREWALL_ENROLLMENT_TOKEN_CREATED,
    firewall,
    auditContext,
    {
      enrollmentCredentialId: token.id,
      expiresAt: expiresAt.toISOString(),
    },
  );

  return { enrollmentToken: publicEnrollmentToken(token), plaintextToken };
}

export async function enrollFirewall({
  database = db(),
  plaintextToken,
  installationIdentifier,
  hostname,
  version,
  region,
  metadata,
  auditContext,
  now = new Date(),
} = {}) {
  const tokenHash = hashOneTimeToken(plaintextToken);

  return database.transaction(async (tx) => {
    await lockEnrollmentToken(tx, tokenHash);

    const [token] = await tx
      .select()
      .from(firewallEnrollmentTokens)
      .where(and(eq(firewallEnrollmentTokens.tokenHash, tokenHash), eq(firewallEnrollmentTokens.status, "pending")))
      .limit(1);

    if (!token || new Date(token.expiresAt).getTime() <= now.getTime()) {
      await createAuditEvent({
        database: tx,
        eventType: AUDIT_EVENT_TYPES.FIREWALL_ENROLLMENT_FAILED,
        action: AUDIT_EVENT_TYPES.FIREWALL_ENROLLMENT_FAILED,
        result: AUDIT_RESULTS.FAILURE,
        severity: AUDIT_SEVERITIES.MEDIUM,
        requestId: auditContext?.requestId,
        ipAddress: auditContext?.ipAddress,
        userAgent: auditContext?.userAgent,
        metadata: { reason: "invalid_or_expired" },
      });
      return null;
    }

    const [claimedToken] = await tx
      .update(firewallEnrollmentTokens)
      .set({ status: "used", usedAt: now })
      .where(
        and(
          eq(firewallEnrollmentTokens.id, token.id),
          eq(firewallEnrollmentTokens.status, "pending"),
        ),
      )
      .returning();

    if (!claimedToken) {
      return null;
    }

    const [firewall] = await tx
      .update(firewallInstances)
      .set({
        status: "active",
        installationIdentifier: safeString(installationIdentifier, 160) || crypto.randomUUID(),
        hostname: safeString(hostname, 255),
        version: safeString(version, 80),
        region: safeString(region, 80),
        metadata: normalizeMetadata(metadata),
        enrolledAt: now,
        lastSeenAt: now,
        updatedAt: now,
      })
      .where(
        and(
          eq(firewallInstances.id, token.firewallInstanceId),
          eq(firewallInstances.organizationId, token.organizationId),
          isNull(firewallInstances.deletedAt),
        ),
      )
      .returning();

    if (!firewall) {
      return null;
    }

    const [serviceAccount] = await tx
      .insert(serviceAccounts)
      .values({
        organizationId: firewall.organizationId,
        name: `${firewall.name} agent`,
        status: "active",
      })
      .onConflictDoUpdate({
        target: [serviceAccounts.organizationId, serviceAccounts.name],
        set: { status: "active", deletedAt: null },
      })
      .returning();

    const apiKey = await createApiKey({
      database: tx,
      organizationId: firewall.organizationId,
      serviceAccountId: serviceAccount.id,
      name: `${firewall.name} ingestion key`,
      auditContext,
    });

    await recordFirewallAudit(tx, AUDIT_EVENT_TYPES.FIREWALL_ENROLLED, firewall, auditContext, {
      serviceAccountId: serviceAccount.id,
      apiKeyPrefix: apiKey.apiKey.keyPrefix,
    });

    return { firewall, serviceAccount, apiKey };
  });
}

async function lockEnrollmentToken(database, tokenHash) {
  if (!database?.execute) {
    return;
  }

  await database.execute(sql`select pg_advisory_xact_lock(hashtext(${tokenHash}))`);
}

export async function disableFirewall({
  database = db(),
  organizationId,
  firewallInstanceId,
  auditContext,
  now = new Date(),
} = {}) {
  const [updated] = await database
    .update(firewallInstances)
    .set({ status: "disabled", updatedAt: now })
    .where(
      and(
        eq(firewallInstances.id, firewallInstanceId),
        eq(firewallInstances.organizationId, organizationId),
        isNull(firewallInstances.deletedAt),
      ),
    )
    .returning();

  if (updated) {
    await recordFirewallAudit(database, AUDIT_EVENT_TYPES.FIREWALL_DISABLED, updated, auditContext);
  }

  return updated || null;
}

export async function selectActiveFirewall({
  database = db(),
  organizationId,
  sessionId,
  firewallInstanceId,
} = {}) {
  if (firewallInstanceId) {
    const firewall = await getOrganizationFirewall(database, organizationId, firewallInstanceId);
    if (!firewall || firewall.status !== "active" || firewall.deletedAt) {
      return null;
    }
  }

  return updateSessionActiveFirewall({ database, sessionId, firewallInstanceId });
}

export async function getOrganizationFirewall(database, organizationId, firewallInstanceId) {
  const [firewall] = await database
    .select()
    .from(firewallInstances)
    .where(
      and(
        eq(firewallInstances.id, firewallInstanceId),
        eq(firewallInstances.organizationId, organizationId),
      ),
    )
    .limit(1);

  return firewall || null;
}

export function publicEnrollmentToken(token) {
  if (!token) return null;
  const { tokenHash, ...safeToken } = token;
  return safeToken;
}

async function recordFirewallAudit(database, eventType, firewall, auditContext, metadata = {}) {
  await createAuditEvent({
    database,
    eventType,
    action: eventType,
    result: AUDIT_RESULTS.SUCCESS,
    severity: AUDIT_SEVERITIES.INFO,
    organizationId: firewall.organizationId,
    userId: auditContext?.userId,
    firewallInstanceId: firewall.id,
    resourceType: "firewall_instance",
    resourceId: firewall.id,
    requestId: auditContext?.requestId,
    ipAddress: auditContext?.ipAddress,
    userAgent: auditContext?.userAgent,
    metadata,
  });
}

function normalizeMetadata(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }

  return JSON.parse(JSON.stringify(value));
}
