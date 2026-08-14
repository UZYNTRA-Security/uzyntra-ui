import { db } from "../../../../db/client.js";
import { PERMISSIONS } from "../../../../lib/rbac/catalog.js";
import { disableFirewall } from "../../../../lib/management/firewalls.js";
import {
  json,
  jsonError,
  requireManagementPermission,
} from "../../../../lib/management/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function PATCH(request, context) {
  const database = db();
  const auth = await requireManagementPermission(request, PERMISSIONS.FIREWALLS_MANAGE, {
    database,
  });
  if (auth.error) return auth.error;

  const { firewallId } = await context.params;
  const firewall = await disableFirewall({
    database,
    organizationId: auth.context.organizationId,
    firewallInstanceId: firewallId,
    auditContext: auth.auditContext,
  });

  if (!firewall) return jsonError("not found", 404);
  return json({ success: true, data: { firewall } });
}
