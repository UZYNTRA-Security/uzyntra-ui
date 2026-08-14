import { db } from "../../../../../db/client.js";
import { revokeOrganizationApiKey } from "../../../../../lib/api-keys/index.js";
import { PERMISSIONS } from "../../../../../lib/rbac/catalog.js";
import {
  json,
  jsonError,
  requireManagementPermission,
} from "../../../../../lib/management/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request, context) {
  const database = db();
  const auth = await requireManagementPermission(request, PERMISSIONS.API_KEYS_MANAGE, {
    database,
  });
  if (auth.error) return auth.error;

  const { apiKeyId } = await context.params;
  const apiKey = await revokeOrganizationApiKey({
    database,
    organizationId: auth.context.organizationId,
    apiKeyId,
    auditContext: auth.auditContext,
  });

  if (!apiKey) return jsonError("not found", 404);
  return json({ success: true, data: { apiKey } });
}
