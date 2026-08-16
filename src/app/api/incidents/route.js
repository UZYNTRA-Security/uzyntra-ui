import { db } from "../../../db/client.js";
import { createIncidentFromAlerts, listIncidents } from "../../../lib/alerts/index.js";
import { errorResponse, json, readJson, requirePermission, searchParams } from "../../../lib/alerts/api.js";
import { PERMISSIONS } from "../../../lib/rbac/catalog.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request) {
  const database = db();
  const auth = await requirePermission({ database, request, permission: PERMISSIONS.INCIDENTS_READ, route: "incidents", method: "GET" });
  if (auth.response) return auth.response;
  try {
    const result = await listIncidents({ database, organizationId: auth.identity.organizationId, filters: searchParams(request) });
    return json({ success: true, data: result }, 200, auth.requestId);
  } catch (error) {
    return errorResponse(error, auth.requestId);
  }
}

export async function POST(request) {
  const database = db();
  const auth = await requirePermission({ database, request, permission: PERMISSIONS.INCIDENTS_MANAGE, route: "incidents", method: "POST" });
  if (auth.response) return auth.response;
  try {
    const body = await readJson(request);
    const created = await createIncidentFromAlerts({ database, organizationId: auth.identity.organizationId, userId: auth.identity.userId, alertIds: body.alertIds || [], title: body.title, summary: body.summary });
    return json({ success: true, data: created }, 201, auth.requestId);
  } catch (error) {
    return errorResponse(error, auth.requestId);
  }
}
