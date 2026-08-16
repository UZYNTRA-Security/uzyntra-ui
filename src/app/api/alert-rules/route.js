import { db } from "../../../db/client.js";
import { createAlertRule, listAlertRules } from "../../../lib/alerts/index.js";
import { errorResponse, json, readJson, requirePermission, searchParams } from "../../../lib/alerts/api.js";
import { PERMISSIONS } from "../../../lib/rbac/catalog.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request) {
  const database = db();
  const auth = await requirePermission({ database, request, permission: PERMISSIONS.ALERTS_READ, route: "alert-rules", method: "GET" });
  if (auth.response) return auth.response;
  try {
    const result = await listAlertRules({ database, organizationId: auth.identity.organizationId, filters: searchParams(request) });
    return json({ success: true, data: result }, 200, auth.requestId);
  } catch (error) {
    return errorResponse(error, auth.requestId);
  }
}

export async function POST(request) {
  const database = db();
  const auth = await requirePermission({ database, request, permission: PERMISSIONS.ALERTS_MANAGE, route: "alert-rules", method: "POST" });
  if (auth.response) return auth.response;
  try {
    const created = await createAlertRule({
      database,
      organizationId: auth.identity.organizationId,
      userId: auth.identity.userId,
      input: await readJson(request),
    });
    return json({ success: true, data: created }, 201, auth.requestId);
  } catch (error) {
    return errorResponse(error, auth.requestId);
  }
}
