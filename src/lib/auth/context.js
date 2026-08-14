import "server-only";

import { and, eq, isNull } from "drizzle-orm";
import { cookies } from "next/headers";
import { db } from "../../db/client.js";
import {
  firewallInstances,
  organizationMemberships,
  organizations,
  users,
} from "../../db/schema.js";
import { getActiveSessionByToken, sessionCookieName, touchSession } from "./session.js";

export async function getAuthenticatedContext({ database = db(), requireActive = true } = {}) {
  const cookieStore = await cookies();
  const token = cookieStore.get(sessionCookieName())?.value;
  if (!token) {
    return null;
  }

  const session = await getActiveSessionByToken(token, { database });
  if (!session) {
    return null;
  }

  const [context] = await database
    .select({
      userId: users.id,
      email: users.email,
      organizationId: organizations.id,
      organizationName: organizations.name,
      organizationSlug: organizations.slug,
      membershipId: organizationMemberships.id,
      activeFirewallInstanceId: firewallInstances.id,
      activeFirewallName: firewallInstances.name,
    })
    .from(users)
    .innerJoin(
      organizationMemberships,
      and(
        eq(organizationMemberships.userId, users.id),
        eq(organizationMemberships.organizationId, session.organizationId),
      ),
    )
    .innerJoin(organizations, eq(organizations.id, session.organizationId))
    .leftJoin(
      firewallInstances,
      and(
        eq(firewallInstances.id, session.activeFirewallInstanceId),
        eq(firewallInstances.organizationId, organizations.id),
        eq(firewallInstances.status, "active"),
        isNull(firewallInstances.deletedAt),
      ),
    )
    .where(
      and(
        eq(users.id, session.userId),
        eq(users.status, "active"),
        isNull(users.deletedAt),
        eq(organizationMemberships.status, "active"),
        eq(organizations.status, "active"),
        isNull(organizations.deletedAt),
      ),
    )
    .limit(1);

  if (!context && requireActive) {
    return null;
  }

  await touchSession(session.id, { database });
  return context ? { ...context, sessionId: session.id, session } : { session };
}

export function contextIdentity(context) {
  if (!context) {
    return null;
  }

  return {
    userId: context.userId,
    organizationId: context.organizationId,
    sessionId: context.sessionId,
    activeFirewallInstanceId: context.activeFirewallInstanceId || null,
  };
}
