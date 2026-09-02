import { db } from "../../../../db/client.js";
import { generateRecoveryCodes } from "../../../../lib/auth/mfa.js";
import { json, requireAuthenticatedManagement, routeError } from "../../../../lib/management/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request) {
  const database = db();
  const auth = await requireAuthenticatedManagement(request, { database });
  if (auth.error) return auth.error;

  try {
    const result = await generateRecoveryCodes({
      database,
      organizationId: auth.context.organizationId,
      userId: auth.context.userId,
      auditContext: auth.auditContext,
    });

    return json({ success: true, data: result }, 201);
  } catch (error) {
    return routeError(error);
  }
}
