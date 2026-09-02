import { db } from "../../../../../db/client.js";
import { enrollTotpMethod } from "../../../../../lib/auth/mfa.js";
import { json, requireAuthenticatedManagement, routeError } from "../../../../../lib/management/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request) {
  const database = db();
  const auth = await requireAuthenticatedManagement(request, { database });
  if (auth.error) return auth.error;

  try {
    const enrollment = await enrollTotpMethod({
      database,
      organizationId: auth.context.organizationId,
      userId: auth.context.userId,
      accountName: auth.context.email,
      auditContext: auth.auditContext,
    });

    return json({ success: true, data: enrollment }, 201);
  } catch (error) {
    return routeError(error);
  }
}
