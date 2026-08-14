import { db } from "../../../../../db/client.js";
import { PERMISSIONS } from "../../../../../lib/rbac/catalog.js";
import { revokeInvitation } from "../../../../../lib/management/members.js";
import {
  json,
  jsonError,
  requireManagementPermission,
} from "../../../../../lib/management/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request, context) {
  const database = db();
  const auth = await requireManagementPermission(request, PERMISSIONS.USERS_MANAGE, { database });
  if (auth.error) return auth.error;

  const { invitationId } = await context.params;
  const invitation = await revokeInvitation({
    database,
    organizationId: auth.context.organizationId,
    invitationId,
    auditContext: auth.auditContext,
  });

  if (!invitation) return jsonError("not found", 404);
  return json({ success: true, data: { invitation } });
}
