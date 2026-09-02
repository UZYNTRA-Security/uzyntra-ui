import { db } from "../../../../db/client.js";
import {
  createBreakGlassAdministrator,
  createIdentityRecoveryWorkflow,
  listRecoveryState,
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

  const recovery = await listRecoveryState({
    database,
    organizationId: auth.context.organizationId,
    filters: Object.fromEntries(new URL(request.url).searchParams.entries()),
  });
  return json({ success: true, data: recovery });
}

export async function POST(request) {
  const database = db();
  const auth = await requireManagementPermission(request, PERMISSIONS.IDENTITY_RECOVERY_MANAGE, { database });
  if (auth.error) return auth.error;

  const body = await readJson(request);
  if (body.error) return body.error;

  try {
    const data = body.data?.breakGlassAdministrator
      ? {
          breakGlassAdministrator: await createBreakGlassAdministrator({
            database,
            organizationId: auth.context.organizationId,
            userId: body.data.userId,
            reason: body.data.reason,
            status: body.data.status,
            expiresAt: body.data.expiresAt,
            approvedByUserId: auth.context.userId,
            metadata: body.data.metadata,
            auditContext: auth.auditContext,
          }),
        }
      : {
          workflow: await createIdentityRecoveryWorkflow({
            database,
            organizationId: auth.context.organizationId,
            targetUserId: body.data?.targetUserId,
            workflowType: body.data?.workflowType,
            reason: body.data?.reason,
            expiresAt: body.data?.expiresAt,
            requestedByUserId: auth.context.userId,
            metadata: body.data?.metadata,
            auditContext: auth.auditContext,
          }),
        };

    return json({ success: true, data }, 201);
  } catch (error) {
    return routeError(error);
  }
}
