import { db } from "../../../../db/client.js";
import { PERMISSIONS } from "../../../../lib/rbac/catalog.js";
import {
  softDeleteServiceAccount,
  updateServiceAccountStatus,
} from "../../../../lib/management/service-accounts.js";
import {
  json,
  jsonError,
  readJson,
  requireManagementPermission,
  routeError,
} from "../../../../lib/management/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function PATCH(request, context) {
  const database = db();
  const auth = await requireManagementPermission(
    request,
    PERMISSIONS.SERVICE_ACCOUNTS_MANAGE,
    { database },
  );
  if (auth.error) return auth.error;

  const body = await readJson(request);
  if (body.error) return body.error;

  const { serviceAccountId } = await context.params;

  try {
    const serviceAccount =
      body.data?.status === "deleted"
        ? await softDeleteServiceAccount({
            database,
            organizationId: auth.context.organizationId,
            serviceAccountId,
            auditContext: auth.auditContext,
          })
        : await updateServiceAccountStatus({
            database,
            organizationId: auth.context.organizationId,
            serviceAccountId,
            status: body.data?.status,
            auditContext: auth.auditContext,
          });

    if (!serviceAccount) return jsonError("not found", 404);
    return json({ success: true, data: { serviceAccount } });
  } catch (error) {
    return routeError(error);
  }
}
