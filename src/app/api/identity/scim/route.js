import { db } from "../../../../db/client.js";
import {
  createScimProvider,
  createScimToken,
  listScimProviders,
} from "../../../../lib/scim/index.js";
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
  const auth = await requireManagementPermission(request, PERMISSIONS.SCIM_READ, { database });
  if (auth.error) return auth.error;

  const providers = await listScimProviders({
    database,
    organizationId: auth.context.organizationId,
  });

  return json({ success: true, data: { providers } });
}

export async function POST(request) {
  const database = db();
  const auth = await requireManagementPermission(request, PERMISSIONS.SCIM_MANAGE, { database });
  if (auth.error) return auth.error;

  const body = await readJson(request);
  if (body.error) return body.error;

  try {
    if (body.data?.generateToken) {
      const result = await createScimToken({
        database,
        organizationId: auth.context.organizationId,
        providerId: body.data.providerId,
        name: body.data.name,
        expiresAt: body.data.expiresAt ? new Date(body.data.expiresAt) : null,
        createdByUserId: auth.context.userId,
        auditContext: auth.auditContext,
      });
      return json({ success: true, data: result }, 201);
    }

    const provider = await createScimProvider({
      database,
      organizationId: auth.context.organizationId,
      name: body.data?.name,
      status: body.data?.status,
      endpointConfigurationRef: body.data?.endpointConfigurationRef,
      baseUrl: body.data?.baseUrl,
      createdByUserId: auth.context.userId,
      metadata: body.data?.metadata,
      auditContext: auth.auditContext,
    });

    return json({ success: true, data: { provider } }, 201);
  } catch (error) {
    return routeError(error);
  }
}
