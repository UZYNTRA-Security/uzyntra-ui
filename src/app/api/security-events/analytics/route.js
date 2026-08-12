import { cookies } from "next/headers";
import { db } from "../../../../db/client.js";
import {
  getActiveSessionByToken,
  sessionCookieName,
  touchSession,
} from "../../../../lib/auth/session.js";
import { handleSecurityEventAnalyticsRequest } from "../../../../lib/security-events/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request) {
  const database = db();
  return handleSecurityEventAnalyticsRequest({
    request,
    database,
    resolveIdentity: () => authenticatedIdentity(database),
  });
}

async function authenticatedIdentity(database) {
  const cookieStore = await cookies();
  const token = cookieStore.get(sessionCookieName())?.value;
  if (!token) {
    return null;
  }

  try {
    const session = await getActiveSessionByToken(token, { database });
    if (!session) {
      return null;
    }

    await touchSession(session.id, { database });

    return {
      userId: session.userId,
      organizationId: session.organizationId,
      sessionId: session.id,
    };
  } catch (error) {
    console.error("Security event analytics session resolution failed", error);
    return null;
  }
}
