import { db } from "../../../../../db/client.js";
import { PERMISSIONS } from "../../../../../lib/rbac/catalog.js";
import {
  assignMembershipRole,
  removeMembershipRole,
} from "../../../../../lib/management/members.js";
import {
  json,
  jsonError,
  readJson,
  requireManagementPermission,
  routeError,
} from "../../../../../lib/management/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request, context) {
  return changeRole(request, context, "assign");
}

export async function DELETE(request, context) {
  return changeRole(request, context, "remove");
}

async function changeRole(request, context, operation) {
  const database = db();
  const auth = await requireManagementPermission(request, PERMISSIONS.ROLES_MANAGE, { database });
  if (auth.error) return auth.error;

  const body = await readJson(request);
  if (body.error) return body.error;

  const { membershipId } = await context.params;
  if (!membershipId) return jsonError("not found", 404);

  try {
    const change =
      operation === "assign"
        ? await assignMembershipRole({
            database,
            organizationId: auth.context.organizationId,
            membershipId,
            roleId: body.data?.roleId,
            auditContext: auth.auditContext,
          })
        : await removeMembershipRole({
            database,
            organizationId: auth.context.organizationId,
            membershipId,
            roleId: body.data?.roleId,
            auditContext: auth.auditContext,
          });

    if (!change) return jsonError("not found", 404);
    return json({ success: true, data: change });
  } catch (error) {
    return routeError(error);
  }
}
