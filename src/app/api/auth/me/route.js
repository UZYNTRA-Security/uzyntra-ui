import { and, eq, isNull } from "drizzle-orm";
import { cookies } from "next/headers";
import { db } from "../../../../db/client.js";
import { organizationMemberships, organizations, users } from "../../../../db/schema.js";
import { authError, authJson } from "../../../../lib/auth/api.js";
import {
  getActiveSessionByToken,
  sessionCookieName,
  touchSession,
} from "../../../../lib/auth/session.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET() {
  const cookieStore = await cookies();
  const token = cookieStore.get(sessionCookieName())?.value;
  if (!token) {
    return authError("Unauthorized", 401);
  }

  try {
    const database = db();
    const session = await getActiveSessionByToken(token, { database });
    if (!session) {
      return authError("Unauthorized", 401);
    }

    const [context] = await database
      .select({
        userId: users.id,
        email: users.email,
        organizationId: organizations.id,
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

    if (!context) {
      return authError("Unauthorized", 401);
    }

    await touchSession(session.id, { database });

    return authJson(context);
  } catch (error) {
    console.error("Authentication context lookup failed", error);
    return authError("Authentication unavailable", 500);
  }
}
