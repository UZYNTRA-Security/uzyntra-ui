import { db } from "../../../db/client.js";
import { PERMISSIONS } from "../../../lib/rbac/catalog.js";
import {
  listOrganizationSettings,
  updateOrganizationSettings,
} from "../../../lib/management/organizations.js";
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

  const settings = await listOrganizationSettings({
    database,
    organizationId: auth.context.organizationId,
  });

  return json({ success: true, data: { settings } });
}

export async function PATCH(request) {
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
    const settings = await updateOrganizationSettings({
      database,
      organizationId: auth.context.organizationId,
      mfaRequired: body.data?.mfaRequired,
      sessionTimeoutSeconds: body.data?.sessionTimeoutSeconds,
      allowedEmailDomains: body.data?.allowedEmailDomains,
      ssoMode: body.data?.ssoMode,
      ssoAllowedDomains: body.data?.ssoAllowedDomains,
      ssoPasswordLoginDisabled: body.data?.ssoPasswordLoginDisabled,
      ssoMfaRequired: body.data?.ssoMfaRequired,
      securityLevel: body.data?.securityLevel,
      auditContext: auth.auditContext,
    });

    return json({ success: true, data: { settings } });
  } catch (error) {
    return routeError(error);
  }
}
