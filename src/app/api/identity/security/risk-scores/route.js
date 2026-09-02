import { db } from "../../../../../db/client.js";
import {
  listIdentityRiskScores,
  upsertIdentityRiskScore,
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

  const risks = await listIdentityRiskScores({
    database,
    organizationId: auth.context.organizationId,
    filters: Object.fromEntries(new URL(request.url).searchParams.entries()),
  });
  return json({ success: true, data: risks });
}

export async function POST(request) {
  const database = db();
  const auth = await requireManagementPermission(request, PERMISSIONS.IDENTITY_SECURITY_MANAGE, { database });
  if (auth.error) return auth.error;

  const body = await readJson(request);
  if (body.error) return body.error;

  try {
    const risk = await upsertIdentityRiskScore({
      database,
      organizationId: auth.context.organizationId,
      userId: body.data?.userId,
      subjectType: body.data?.subjectType,
      subjectId: body.data?.subjectId,
      signals: body.data?.signals,
      status: body.data?.status,
      expiresAt: body.data?.expiresAt ? new Date(body.data.expiresAt) : null,
      auditContext: auth.auditContext,
    });
    return json({ success: true, data: { risk } }, 201);
  } catch (error) {
    return routeError(error);
  }
}
