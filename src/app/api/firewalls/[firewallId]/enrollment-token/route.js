import { db } from "../../../../../db/client.js";
import { PERMISSIONS } from "../../../../../lib/rbac/catalog.js";
import { createFirewallEnrollmentToken } from "../../../../../lib/management/firewalls.js";
import {
  json,
  jsonError,
  requireManagementPermission,
  routeError,
} from "../../../../../lib/management/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request, context) {
  const database = db();
  const auth = await requireManagementPermission(request, PERMISSIONS.FIREWALLS_MANAGE, {
    database,
  });
  if (auth.error) return auth.error;

  const { firewallId } = await context.params;

  try {
    const created = await createFirewallEnrollmentToken({
      database,
      organizationId: auth.context.organizationId,
      firewallInstanceId: firewallId,
      createdByUserId: auth.context.userId,
      auditContext: auth.auditContext,
    });

    if (!created) return jsonError("not found", 404);
    return json({ success: true, data: created }, 201);
  } catch (error) {
    return routeError(error);
  }
}
