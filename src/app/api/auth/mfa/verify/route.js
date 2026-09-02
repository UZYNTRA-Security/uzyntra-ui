import { cookies, headers } from "next/headers";
import { authError, authJson, clientIp, requestId, userAgent } from "../../../../../lib/auth/api.js";
import {
  expiredMfaCookieOptions,
  mfaChallengeIdCookieName,
  mfaChallengeTokenCookieName,
  verifyMfaChallengeAndCreateSession,
} from "../../../../../lib/auth/mfa.js";
import { sessionCookieName, sessionCookieOptions } from "../../../../../lib/auth/session.js";
import { db } from "../../../../../db/client.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request) {
  const id = requestId();
  const headersList = await headers();
  const cookieStore = await cookies();

  try {
    const body = await request.json().catch(() => ({}));
    const result = await verifyMfaChallengeAndCreateSession({
      database: db(),
      challengeId: cookieStore.get(mfaChallengeIdCookieName())?.value || body.challengeId,
      challengeToken: cookieStore.get(mfaChallengeTokenCookieName())?.value || body.challengeToken,
      methodId: body.methodId,
      code: body.code,
      recoveryCode: body.recoveryCode,
      ipAddress: clientIp(headersList),
      userAgent: userAgent(headersList),
      requestId: id,
    });

    cookieStore.set(mfaChallengeIdCookieName(), "", expiredMfaCookieOptions());
    cookieStore.set(mfaChallengeTokenCookieName(), "", expiredMfaCookieOptions());
    cookieStore.set(sessionCookieName(), result.token, sessionCookieOptions(result.session.expiresAt));

    return authJson({ success: true });
  } catch (error) {
    console.error("MFA verification failed", { message: error?.message || "mfa failed" });
    return authError("MFA verification failed", 401);
  }
}
