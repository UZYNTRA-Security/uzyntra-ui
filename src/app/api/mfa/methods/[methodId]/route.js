import { db } from "../../../../../db/client.js";
import { disableMfaMethod } from "../../../../../lib/auth/mfa.js";
import { json, requireAuthenticatedManagement, routeError } from "../../../../../lib/management/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function DELETE(request, context) {
  const database = db();
  const auth = await requireAuthenticatedManagement(request, { database });
  if (auth.error) return auth.error;
  const { methodId } = await context.params;

  try {
    const method = await disableMfaMethod({
      database,
      organizationId: auth.context.organizationId,
      userId: auth.context.userId,
      methodId,
      auditContext: auth.auditContext,
    });

    return json({ success: true, data: { method } });
  } catch (error) {
    return routeError(error);
  }
}
