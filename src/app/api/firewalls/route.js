import { db } from "../../../db/client.js";
import { PERMISSIONS } from "../../../lib/rbac/catalog.js";
import {
  listFirewalls,
  registerFirewall,
} from "../../../lib/management/firewalls.js";
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

  const firewalls = await listFirewalls({
    database,
    organizationId: auth.context.organizationId,
  });

  return json({
    success: true,
    data: {
      firewalls,
      activeFirewallInstanceId: auth.context.activeFirewallInstanceId,
    },
  });
}

export async function POST(request) {
  const database = db();
  const auth = await requireManagementPermission(request, PERMISSIONS.FIREWALLS_MANAGE, {
    database,
  });
  if (auth.error) return auth.error;

  const body = await readJson(request);
  if (body.error) return body.error;

  try {
    const firewall = await registerFirewall({
      database,
      organizationId: auth.context.organizationId,
      name: body.data?.name,
      environment: body.data?.environment,
      region: body.data?.region,
      hostname: body.data?.hostname,
      membershipId: auth.context.membershipId,
      auditContext: auth.auditContext,
    });

    return json({ success: true, data: { firewall } }, 201);
  } catch (error) {
    return routeError(error);
  }
}
