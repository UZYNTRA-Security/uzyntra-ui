import { db } from "../../../../db/client.js";
import { PERMISSIONS } from "../../../../lib/rbac/catalog.js";
import { updateMembershipStatus } from "../../../../lib/management/members.js";
import {
  json,
  jsonError,
  readJson,
  requireManagementPermission,
  routeError,
} from "../../../../lib/management/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function PATCH(request, context) {
  const database = db();
  const auth = await requireManagementPermission(request, PERMISSIONS.USERS_MANAGE, { database });
  if (auth.error) return auth.error;

  const body = await readJson(request);
  if (body.error) return body.error;

  const { membershipId } = await context.params;
  if (!membershipId) return jsonError("not found", 404);

  try {
    const membership = await updateMembershipStatus({
      database,
      organizationId: auth.context.organizationId,
      membershipId,
      status: body.data?.status,
      auditContext: auth.auditContext,
    });

    if (!membership) return jsonError("not found", 404);
    return json({ success: true, data: { membership } });
  } catch (error) {
    return routeError(error);
  }
}
