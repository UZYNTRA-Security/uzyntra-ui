import { db } from "../../../../db/client.js";
import {
  createIdentityAuditReport,
  listIdentityAuditReports,
} from "../../../../lib/identity-hardening/index.js";
import {
  json,
  readJson,
  requireManagementPermission,
  routeError,
} from "../../../../lib/management/api.js";
import { PERMISSIONS } from "../../../../lib/rbac/catalog.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request) {
  const database = db();
  const auth = await requireManagementPermission(request, PERMISSIONS.IDENTITY_REPORTS_READ, { database });
  if (auth.error) return auth.error;

  const reports = await listIdentityAuditReports({
    database,
    organizationId: auth.context.organizationId,
    filters: Object.fromEntries(new URL(request.url).searchParams.entries()),
  });
  return json({ success: true, data: reports });
}

export async function POST(request) {
  const database = db();
  const auth = await requireManagementPermission(request, PERMISSIONS.IDENTITY_REPORTS_MANAGE, { database });
  if (auth.error) return auth.error;

  const body = await readJson(request);
  if (body.error) return body.error;

  try {
    const report = await createIdentityAuditReport({
      database,
      organizationId: auth.context.organizationId,
      reportType: body.data?.reportType,
      exportFormat: body.data?.exportFormat,
      windowStart: body.data?.windowStart,
      windowEnd: body.data?.windowEnd,
      generatedByUserId: auth.context.userId,
      metadata: body.data?.metadata,
      auditContext: auth.auditContext,
    });
    return json({ success: true, data: { report } }, 201);
  } catch (error) {
    return routeError(error);
  }
}
