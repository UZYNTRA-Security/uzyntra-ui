import { db } from "../../../../../db/client.js";
import { resolveAlert } from "../../../../../lib/alerts/index.js";
import { errorResponse, json, readJson, requirePermission } from "../../../../../lib/alerts/api.js";
import { PERMISSIONS } from "../../../../../lib/rbac/catalog.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request, { params }) {
  const database = db();
  const auth = await requirePermission({ database, request, permission: PERMISSIONS.INCIDENTS_MANAGE, route: "alerts/:id/resolve", method: "POST" });
  if (auth.response) return auth.response;
  try {
    const body = await readJson(request).catch(() => ({}));
    const updated = await resolveAlert({ database, organizationId: auth.identity.organizationId, userId: auth.identity.userId, alertId: (await params).alertId, note: body.note });
    return json({ success: true, data: updated }, 200, auth.requestId);
  } catch (error) {
    return errorResponse(error, auth.requestId);
  }
}
