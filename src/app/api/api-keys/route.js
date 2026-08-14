import { db } from "../../../db/client.js";
import {
  createOrganizationApiKey,
  listApiKeys,
} from "../../../lib/api-keys/index.js";
import { PERMISSIONS } from "../../../lib/rbac/catalog.js";
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

  const apiKeys = await listApiKeys({
    database,
    organizationId: auth.context.organizationId,
  });

  return json({ success: true, data: { apiKeys } });
}

export async function POST(request) {
  const database = db();
  const auth = await requireManagementPermission(request, PERMISSIONS.API_KEYS_MANAGE, {
    database,
  });
  if (auth.error) return auth.error;

  const body = await readJson(request);
  if (body.error) return body.error;

  try {
    const apiKey = await createOrganizationApiKey({
      database,
      organizationId: auth.context.organizationId,
      serviceAccountId: body.data?.serviceAccountId,
      name: body.data?.name,
      expiresAt: body.data?.expiresAt ? new Date(body.data.expiresAt) : null,
      auditContext: auth.auditContext,
    });

    return json({ success: true, data: apiKey }, 201);
  } catch (error) {
    return routeError(error);
  }
}
