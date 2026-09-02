import { db } from "../../../../db/client.js";
import { generateIdentitySecurityReport } from "../../../../lib/identity-hardening/index.js";
import { json, requireManagementPermission, routeError } from "../../../../lib/management/api.js";
import { PERMISSIONS } from "../../../../lib/rbac/catalog.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request) {
  const database = db();
  const auth = await requireManagementPermission(request, PERMISSIONS.IDENTITY_REPORTS_READ, { database });
  if (auth.error) return auth.error;

  try {
    const report = await generateIdentitySecurityReport({
      database,
      organizationId: auth.context.organizationId,
      filters: Object.fromEntries(new URL(request.url).searchParams.entries()),
      generatedByUserId: auth.context.userId,
      auditContext: auth.auditContext,
      recordAudit: false,
    });
    return json({ success: true, data: { report } });
  } catch (error) {
    return routeError(error);
  }
}

export async function POST(request) {
  const database = db();
  const auth = await requireManagementPermission(request, PERMISSIONS.IDENTITY_REPORTS_MANAGE, { database });
  if (auth.error) return auth.error;

  try {
    const report = await generateIdentitySecurityReport({
      database,
      organizationId: auth.context.organizationId,
      filters: Object.fromEntries(new URL(request.url).searchParams.entries()),
      generatedByUserId: auth.context.userId,
      auditContext: auth.auditContext,
      recordAudit: true,
    });
    return json({ success: true, data: { report } }, 201);
  } catch (error) {
    return routeError(error);
  }
}
