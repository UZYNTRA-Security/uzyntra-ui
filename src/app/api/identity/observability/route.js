import { db } from "../../../../db/client.js";
import { getIdentityObservabilityDashboard } from "../../../../lib/identity-hardening/index.js";
import { json, requireManagementPermission, routeError } from "../../../../lib/management/api.js";
import { PERMISSIONS } from "../../../../lib/rbac/catalog.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request) {
  const database = db();
  const auth = await requireManagementPermission(request, PERMISSIONS.IDENTITY_SECURITY_READ, { database });
  if (auth.error) return auth.error;

  try {
    const data = await getIdentityObservabilityDashboard({
      database,
      organizationId: auth.context.organizationId,
      filters: Object.fromEntries(new URL(request.url).searchParams.entries()),
    });
    return json({ success: true, data });
  } catch (error) {
    return routeError(error);
  }
}
