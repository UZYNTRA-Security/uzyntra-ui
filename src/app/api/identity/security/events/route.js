import { db } from "../../../../../db/client.js";
import {
  listIdentitySecurityEvents,
  recordIdentitySecurityEvent,
} from "../../../../../lib/identity-security/index.js";
import {
  json,
  readJson,
  requireManagementPermission,
  routeError,
} from "../../../../../lib/management/api.js";
import { PERMISSIONS } from "../../../../../lib/rbac/catalog.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request) {
  const database = db();
  const auth = await requireManagementPermission(request, PERMISSIONS.IDENTITY_SECURITY_READ, { database });
  if (auth.error) return auth.error;

  const events = await listIdentitySecurityEvents({
    database,
    organizationId: auth.context.organizationId,
    filters: Object.fromEntries(new URL(request.url).searchParams.entries()),
  });
  return json({ success: true, data: events });
}

export async function POST(request) {
  const database = db();
  const auth = await requireManagementPermission(request, PERMISSIONS.IDENTITY_SECURITY_MANAGE, { database });
  if (auth.error) return auth.error;

  const body = await readJson(request);
  if (body.error) return body.error;

  try {
    const event = await recordIdentitySecurityEvent({
      database,
      organizationId: auth.context.organizationId,
      userId: body.data?.userId,
      actorUserId: auth.context.userId,
      eventType: body.data?.eventType,
      category: body.data?.category,
      result: body.data?.result,
      severity: body.data?.severity,
      riskScore: body.data?.riskScore,
      action: body.data?.action,
      summary: body.data?.summary,
      metadata: body.data?.metadata,
      auditContext: auth.auditContext,
    });
    return json({ success: true, data: { event } }, 201);
  } catch (error) {
    return routeError(error);
  }
}
