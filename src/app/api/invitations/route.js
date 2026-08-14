import { db } from "../../../db/client.js";
import { PERMISSIONS } from "../../../lib/rbac/catalog.js";
import {
  createInvitation,
  listInvitations,
} from "../../../lib/management/members.js";
import {
  json,
  readJson,
  requireAuthenticatedManagement,
  requireManagementPermission,
  routeError,
} from "../../../lib/management/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request) {
  const database = db();
  const auth = await requireAuthenticatedManagement(request, { database });
  if (auth.error) return auth.error;

  const invitations = await listInvitations({
    database,
    organizationId: auth.context.organizationId,
  });

  return json({ success: true, data: { invitations } });
}

export async function POST(request) {
  const database = db();
  const auth = await requireManagementPermission(request, PERMISSIONS.USERS_MANAGE, { database });
  if (auth.error) return auth.error;

  const body = await readJson(request);
  if (body.error) return body.error;

  try {
    const invitation = await createInvitation({
      database,
      organizationId: auth.context.organizationId,
      invitedByUserId: auth.context.userId,
      email: body.data?.email,
      roleId: body.data?.roleId,
      auditContext: auth.auditContext,
    });

    return json({ success: true, data: invitation }, 201);
  } catch (error) {
    return routeError(error);
  }
}
