import { db } from "../../../../../db/client.js";
import { createEnterpriseSsoProvider, listEnterpriseSsoProviders } from "../../../../../lib/auth/sso.js";
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
  const auth = await requireManagementPermission(
    request,
    PERMISSIONS.ORGANIZATION_SETTINGS_MANAGE,
    { database },
  );
  if (auth.error) return auth.error;

  const providers = await listEnterpriseSsoProviders({
    database,
    organizationId: auth.context.organizationId,
  });

  return json({ success: true, data: { providers } });
}

export async function POST(request) {
  const database = db();
  const auth = await requireManagementPermission(
    request,
    PERMISSIONS.ORGANIZATION_SETTINGS_MANAGE,
    { database },
  );
  if (auth.error) return auth.error;

  const body = await readJson(request);
  if (body.error) return body.error;

  try {
    const provider = await createEnterpriseSsoProvider({
      database,
      organizationId: auth.context.organizationId,
      createdByUserId: auth.context.userId,
      providerKey: body.data?.providerKey,
      providerType: body.data?.providerType,
      displayName: body.data?.displayName,
      status: body.data?.status,
      issuer: body.data?.issuer,
      clientId: body.data?.clientId,
      allowedDomains: body.data?.allowedDomains,
      authorizationEndpoint: body.data?.authorizationEndpoint,
      tokenEndpoint: body.data?.tokenEndpoint,
      userInfoEndpoint: body.data?.userInfoEndpoint,
      configuration: body.data?.configuration,
      configurationRef: body.data?.configurationRef,
      secretRef: body.data?.secretRef,
      auditContext: auth.auditContext,
    });

    return json({ success: true, data: { provider } }, 201);
  } catch (error) {
    return routeError(error);
  }
}
