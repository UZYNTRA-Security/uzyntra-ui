import { db } from "../../../../db/client.js";
import { getAlertAnalytics } from "../../../../lib/alerts/index.js";
import { errorResponse, json, requirePermission } from "../../../../lib/alerts/api.js";
import { PERMISSIONS } from "../../../../lib/rbac/catalog.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request) {
  const database = db();
  const auth = await requirePermission({ database, request, permission: PERMISSIONS.ALERTS_READ, route: "alerts/analytics", method: "GET" });
  if (auth.response) return auth.response;
  try {
    const result = await getAlertAnalytics({ database, organizationId: auth.identity.organizationId });
    return json({ success: true, data: result }, 200, auth.requestId);
  } catch (error) {
    return errorResponse(error, auth.requestId);
  }
}
