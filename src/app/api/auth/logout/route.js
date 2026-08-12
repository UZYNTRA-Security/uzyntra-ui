import { cookies, headers } from "next/headers";
import {
  authError,
  authJson,
  clientIp,
  recordAuthAuditEvent,
  requestId,
  userAgent,
  validateSameOriginWrite,
} from "../../../../lib/auth/api.js";
import {
  expiredSessionCookieOptions,
  getActiveSessionByToken,
  revokeSessionById,
  sessionCookieName,
} from "../../../../lib/auth/session.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request) {
  const id = requestId();
  const headersList = await headers();
  const ipAddress = clientIp(headersList);
  const agent = userAgent(headersList);
  const cookieStore = await cookies();
  const token = cookieStore.get(sessionCookieName())?.value;

  if (!validateSameOriginWrite(request)) {
    recordAuthAuditEvent({
      action: "logout",
      result: "failure",
      requestId: id,
      ipAddress,
      userAgent: agent,
      reason: "cross_origin",
    });
    return authError("Invalid request", 403);
  }

  try {
    const session = token ? await getActiveSessionByToken(token) : null;
    if (session) {
      await revokeSessionById(session.id);
      recordAuthAuditEvent({
        action: "logout",
        result: "success",
        actorId: session.userId,
        requestId: id,
        ipAddress,
        userAgent: agent,
      });
      recordAuthAuditEvent({
        action: "session.revoked",
        result: "success",
        actorId: session.userId,
        requestId: id,
        ipAddress,
        userAgent: agent,
        reason: "logout",
      });
    } else {
      recordAuthAuditEvent({
        action: "logout",
        result: "success",
        requestId: id,
        ipAddress,
        userAgent: agent,
        reason: "no_active_session",
      });
    }

    cookieStore.set(sessionCookieName(), "", expiredSessionCookieOptions());
    return authJson({ success: true });
  } catch (error) {
    console.error("Authentication logout failed", error);
    cookieStore.set(sessionCookieName(), "", expiredSessionCookieOptions());
    recordAuthAuditEvent({
      action: "logout",
      result: "failure",
      requestId: id,
      ipAddress,
      userAgent: agent,
      reason: "server_error",
    });
    return authError("Authentication unavailable", 500);
  }
}
