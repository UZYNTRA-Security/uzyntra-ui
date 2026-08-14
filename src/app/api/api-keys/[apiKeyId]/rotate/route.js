import { db } from "../../../../../db/client.js";
import { rotateOrganizationApiKey } from "../../../../../lib/api-keys/index.js";
import { PERMISSIONS } from "../../../../../lib/rbac/catalog.js";
import {
  json,
  jsonError,
  readJson,
  requireManagementPermission,
  routeError,
} from "../../../../../lib/management/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request, context) {
  const database = db();
  const auth = await requireManagementPermission(request, PERMISSIONS.API_KEYS_MANAGE, {
    database,
  });
  if (auth.error) return auth.error;

  const body = await readJson(request);
  if (body.error) return body.error;

  const { apiKeyId } = await context.params;
  try {
    const replacement = await rotateOrganizationApiKey({
      database,
      organizationId: auth.context.organizationId,
      apiKeyId,
      replacementName: body.data?.replacementName,
      auditContext: auth.auditContext,
    });

    if (!replacement) return jsonError("not found", 404);
    return json({ success: true, data: replacement }, 201);
  } catch (error) {
    return routeError(error);
  }
}
