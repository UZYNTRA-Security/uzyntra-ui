import { db } from "../../../../db/client.js";
import { updateIncident } from "../../../../lib/alerts/index.js";
import { errorResponse, json, readJson, requirePermission } from "../../../../lib/alerts/api.js";
import { PERMISSIONS } from "../../../../lib/rbac/catalog.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function PATCH(request, { params }) {
  const database = db();
  const auth = await requirePermission({ database, request, permission: PERMISSIONS.INCIDENTS_MANAGE, route: "incidents/:id", method: "PATCH" });
  if (auth.response) return auth.response;
  try {
    const updated = await updateIncident({ database, organizationId: auth.identity.organizationId, userId: auth.identity.userId, incidentId: (await params).incidentId, input: await readJson(request) });
    return json({ success: true, data: updated }, 200, auth.requestId);
  } catch (error) {
    return errorResponse(error, auth.requestId);
  }
}
