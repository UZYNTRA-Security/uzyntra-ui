import { db } from "../../../../db/client.js";
import { updateAlertRule } from "../../../../lib/alerts/index.js";
import { errorResponse, json, readJson, requirePermission } from "../../../../lib/alerts/api.js";
import { PERMISSIONS } from "../../../../lib/rbac/catalog.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function PATCH(request, { params }) {
  const database = db();
  const auth = await requirePermission({ database, request, permission: PERMISSIONS.ALERTS_MANAGE, route: "alert-rules/:id", method: "PATCH" });
  if (auth.response) return auth.response;
  try {
    const updated = await updateAlertRule({
      database,
      organizationId: auth.identity.organizationId,
      userId: auth.identity.userId,
      ruleId: (await params).alertRuleId,
      input: await readJson(request),
    });
    return json({ success: true, data: updated }, 200, auth.requestId);
  } catch (error) {
    return errorResponse(error, auth.requestId);
  }
}

export async function DELETE(request, { params }) {
  const database = db();
  const auth = await requirePermission({ database, request, permission: PERMISSIONS.ALERTS_MANAGE, route: "alert-rules/:id", method: "DELETE" });
  if (auth.response) return auth.response;
  try {
    const body = await readJson(request).catch(() => ({}));
    const deleted = await updateAlertRule({
      database,
      organizationId: auth.identity.organizationId,
      userId: auth.identity.userId,
      ruleId: (await params).alertRuleId,
      input: { ...body, status: "deleted", name: body.name || "deleted rule", matchAll: true },
    });
    return json({ success: true, data: deleted }, 200, auth.requestId);
  } catch (error) {
    return errorResponse(error, auth.requestId);
  }
}
