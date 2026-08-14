import { db } from "../../../db/client.js";
import { PERMISSIONS } from "../../../lib/rbac/catalog.js";
import {
  createServiceAccount,
  listServiceAccounts,
} from "../../../lib/management/service-accounts.js";
import {
  json,
  readJson,
  requireAuthenticatedManagement,
  requireManagementPermission,
  routeError,
} from "../../../lib/management/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request) {
  const database = db();
  const auth = await requireAuthenticatedManagement(request, { database });
  if (auth.error) return auth.error;

  const serviceAccounts = await listServiceAccounts({
    database,
    organizationId: auth.context.organizationId,
  });

  return json({ success: true, data: { serviceAccounts } });
}

export async function POST(request) {
  const database = db();
  const auth = await requireManagementPermission(
    request,
    PERMISSIONS.SERVICE_ACCOUNTS_MANAGE,
    { database },
  );
  if (auth.error) return auth.error;

  const body = await readJson(request);
  if (body.error) return body.error;

  try {
    const serviceAccount = await createServiceAccount({
      database,
      organizationId: auth.context.organizationId,
      name: body.data?.name,
      roleId: body.data?.roleId,
      auditContext: auth.auditContext,
    });

    return json({ success: true, data: { serviceAccount } }, 201);
  } catch (error) {
    return routeError(error);
  }
}
