import { and, asc, eq, isNull } from "drizzle-orm";
import { cookies, headers } from "next/headers";
import { db } from "../../../../db/client.js";
import {
  organizationMemberships,
  organizationSettings,
  organizations,
  userCredentials,
  users,
} from "../../../../db/schema.js";
import {
  AUTH_ERROR,
  authError,
  authJson,
  clientIp,
  isLocked,
  nextFailedCredentialState,
  normalizeEmail,
  readJson,
  recordAuthAuditEvent,
  requestId,
  userAgent,
  validateSameOriginWrite,
} from "../../../../lib/auth/api.js";
import { verifyPassword } from "../../../../lib/auth/password.js";
import {
  completePrimaryAuthentication,
  mfaChallengeIdCookieName,
  mfaChallengeTokenCookieName,
  mfaCookieOptions,
} from "../../../../lib/auth/mfa.js";
import {
  sessionCookieName,
  sessionCookieOptions,
} from "../../../../lib/auth/session.js";

const DUMMY_PASSWORD_HASH =
  "$argon2id$v=19$m=65536,p=4,t=3$/I/QuMcFPDyIrlyuCjz1FA$55Ka6v+dDm5/CaMoWjrZZDUByLSuqnG/ccRbptZMppY";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request) {
  const id = requestId();
  const headersList = await headers();
  const ipAddress = clientIp(headersList);
  const agent = userAgent(headersList);

  if (!validateSameOriginWrite(request)) {
    recordAuthAuditEvent({
      action: "login",
      result: "failure",
      requestId: id,
      ipAddress,
      userAgent: agent,
      reason: "cross_origin",
    });
    return authError(AUTH_ERROR);
  }

  const body = await readJson(request);
  if (body.error) {
    return body.error;
  }

  const email = normalizeEmail(body.data?.email);
  const password = body.data?.password;
  if (!email || typeof password !== "string" || !password) {
    recordAuthAuditEvent({
      action: "login",
      result: "failure",
      email,
      requestId: id,
      ipAddress,
      userAgent: agent,
      reason: "invalid_input",
    });
    return authError(AUTH_ERROR);
  }

  try {
    const database = db();
    const now = new Date();
    const [identity] = await database
      .select({ user: users, credential: userCredentials })
      .from(users)
      .innerJoin(userCredentials, eq(userCredentials.userId, users.id))
      .where(eq(users.email, email))
      .limit(1);

    if (!identity) {
      await verifyPassword(password, DUMMY_PASSWORD_HASH);
      recordAuthAuditEvent({
        action: "login",
        result: "failure",
        email,
        requestId: id,
        ipAddress,
        userAgent: agent,
        reason: "invalid_credentials",
      });
      return authError(AUTH_ERROR);
    }

    const { user, credential } = identity;
    if (user.status !== "active" || user.deletedAt || isLocked(credential, now)) {
      recordAuthAuditEvent({
        action: "login",
        result: "failure",
        actorId: user.id,
        email,
        requestId: id,
        ipAddress,
        userAgent: agent,
        reason: isLocked(credential, now) ? "locked" : "inactive",
      });
      return authError(AUTH_ERROR);
    }

    const passwordValid = await verifyPassword(password, credential.passwordHash);
    if (!passwordValid) {
      await database
        .update(userCredentials)
        .set({ ...nextFailedCredentialState(credential, now), updatedAt: now })
        .where(eq(userCredentials.id, credential.id));
      recordAuthAuditEvent({
        action: "login",
        result: "failure",
        actorId: user.id,
        email,
        requestId: id,
        ipAddress,
        userAgent: agent,
        reason: "invalid_credentials",
      });
      return authError(AUTH_ERROR);
    }

    const [membership] = await database
      .select({
        membership: organizationMemberships,
        organization: organizations,
        settings: organizationSettings,
      })
      .from(organizationMemberships)
      .innerJoin(organizations, eq(organizations.id, organizationMemberships.organizationId))
      .leftJoin(
        organizationSettings,
        eq(organizationSettings.organizationId, organizationMemberships.organizationId),
      )
      .where(
        and(
          eq(organizationMemberships.userId, user.id),
          eq(organizationMemberships.status, "active"),
          eq(organizations.status, "active"),
          isNull(organizations.deletedAt),
        ),
      )
      .orderBy(asc(organizationMemberships.createdAt))
      .limit(1);

    if (!membership) {
      recordAuthAuditEvent({
        action: "login",
        result: "failure",
        actorId: user.id,
        email,
        requestId: id,
        ipAddress,
        userAgent: agent,
        reason: "no_active_organization",
      });
      return authError(AUTH_ERROR);
    }

    const authResult = await database.transaction(async (tx) => {
      await tx
        .update(userCredentials)
        .set({ failedAttempts: 0, lockedUntil: null, updatedAt: now })
        .where(eq(userCredentials.id, credential.id));
      await tx.update(users).set({ lastLoginAt: now, updatedAt: now }).where(eq(users.id, user.id));

      return completePrimaryAuthentication({
        database: tx,
        userId: user.id,
        organizationId: membership.organization.id,
        settings: membership.settings,
        ipAddress,
        userAgent: agent,
        requestId: id,
        now,
      });
    });

    const cookieStore = await cookies();
    if (authResult.mfaRequired) {
      cookieStore.set(
        mfaChallengeIdCookieName(),
        authResult.challenge.id,
        mfaCookieOptions(authResult.challenge.expiresAt),
      );
      cookieStore.set(
        mfaChallengeTokenCookieName(),
        authResult.challenge.token,
        mfaCookieOptions(authResult.challenge.expiresAt),
      );
      recordAuthAuditEvent({
        action: "login",
        result: "success",
        actorId: user.id,
        email,
        requestId: id,
        ipAddress,
        userAgent: agent,
        reason: "mfa_required",
      });
      return authJson({
        success: true,
        mfaRequired: true,
        methods: authResult.methods,
      });
    }

    cookieStore.set(
      sessionCookieName(),
      authResult.token,
      sessionCookieOptions(authResult.session.expiresAt),
    );
    recordAuthAuditEvent({
      action: "login",
      result: "success",
      actorId: user.id,
      email,
      requestId: id,
      ipAddress,
      userAgent: agent,
    });

    return authJson({ success: true });
  } catch (error) {
    console.error("Authentication login failed", error);
    recordAuthAuditEvent({
      action: "login",
      result: "failure",
      email,
      requestId: id,
      ipAddress,
      userAgent: agent,
      reason: "server_error",
    });
    return authError("Authentication unavailable", 500);
  }
}
