import { headers } from "next/headers";
import { db } from "../../../../../db/client.js";
import { clientIp, requestId, userAgent } from "../../../../../lib/auth/api.js";
import { createWebAuthnRegistrationChallenge } from "../../../../../lib/auth/mfa.js";
import { json, requireAuthenticatedManagement, routeError } from "../../../../../lib/management/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request) {
  const database = db();
  const auth = await requireAuthenticatedManagement(request, { database });
  if (auth.error) return auth.error;
  const headersList = await headers();

  try {
    const challenge = await createWebAuthnRegistrationChallenge({
      database,
      organizationId: auth.context.organizationId,
      userId: auth.context.userId,
      ipAddress: clientIp(headersList),
      userAgent: userAgent(headersList),
      requestId: requestId(),
    });

    return json({ success: true, data: { challenge } }, 201);
  } catch (error) {
    return routeError(error);
  }
}
