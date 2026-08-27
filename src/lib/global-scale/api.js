import "server-only";

import { json, jsonError, readJson, requirePermission, searchParams } from "../alerts/api.js";
import { PERMISSIONS } from "../rbac/catalog.js";
import {
  assignTenantRegion,
  createDeveloperApp,
  createIntegrationCatalogEntry,
  createMarketplaceListing,
  createRegion,
  createRegionalService,
  getPlatformOverview,
  listDeveloperApps,
  listIntegrationCatalog,
  listMarketplace,
  listPlatformHealth,
  listRegions,
  recordPlatformHealth,
} from "./index.js";

export async function requireGlobalScalePermission({ database, request, operation, method }) {
  return requirePermission({
    database,
    request,
    permission: permissionFor(operation, method),
    route: `global-scale/${operation}`,
    method,
  });
}

export async function handleGlobalScaleRequest({
  request,
  database,
  identity,
  requestId,
  operation,
  method,
} = {}) {
  try {
    const query = searchParams(request);
    const body = method === "POST" ? await readJson(request) : {};
    const common = {
      database,
      organizationId: identity.organizationId,
      userId: identity.userId,
      auditContext: { requestId },
    };

    const data =
      operation === "overview"
        ? await getPlatformOverview({ database, organizationId: identity.organizationId })
        : operation === "regions" && method === "GET"
          ? await listRegions({ database, organizationId: identity.organizationId, filters: query })
          : operation === "regions"
            ? await mutateRegion(common, body)
            : operation === "health" && method === "GET"
              ? await listPlatformHealth({ database, organizationId: identity.organizationId, filters: query })
              : operation === "health"
                ? await recordPlatformHealth({ ...common, input: body })
                : operation === "developer-apps" && method === "GET"
                  ? await listDeveloperApps({ database, organizationId: identity.organizationId, filters: query })
                  : operation === "developer-apps"
                    ? await createDeveloperApp({ ...common, input: body })
                    : operation === "integration-catalog" && method === "GET"
                      ? await listIntegrationCatalog({ database, organizationId: identity.organizationId, filters: query })
                      : operation === "integration-catalog"
                        ? await createIntegrationCatalogEntry({ ...common, input: body })
                        : operation === "marketplace" && method === "GET"
                          ? await listMarketplace({ database, organizationId: identity.organizationId, filters: query })
                          : operation === "marketplace"
                            ? await createMarketplaceListing({ ...common, input: body })
                            : null;

    if (!data) return jsonError("Not found", 404, requestId);
    return json({ success: true, data }, method === "GET" ? 200 : 201, requestId);
  } catch (error) {
    return globalScaleError(error, requestId);
  }
}

async function mutateRegion(common, body) {
  if (body.assignTenantRegion) return assignTenantRegion({ ...common, input: body.assignTenantRegion });
  if (body.regionalService) return createRegionalService({ ...common, input: body.regionalService });
  return createRegion({ ...common, input: body });
}

function permissionFor(operation, method) {
  if (operation === "overview") return PERMISSIONS.PLATFORM_READ;
  if (operation === "regions") return method === "GET" ? PERMISSIONS.REGIONS_READ : PERMISSIONS.REGIONS_MANAGE;
  if (operation === "health") return method === "GET" ? PERMISSIONS.PLATFORM_READ : PERMISSIONS.PLATFORM_MANAGE;
  if (operation === "developer-apps") return method === "GET" ? PERMISSIONS.DEVELOPER_READ : PERMISSIONS.DEVELOPER_MANAGE;
  if (operation === "integration-catalog") return method === "GET" ? PERMISSIONS.INTEGRATIONS_READ : PERMISSIONS.INTEGRATIONS_MANAGE;
  if (operation === "marketplace") return method === "GET" ? PERMISSIONS.MARKETPLACE_READ : PERMISSIONS.INTEGRATIONS_MANAGE;
  return PERMISSIONS.PLATFORM_READ;
}

function globalScaleError(error, requestId) {
  const message = error?.message || "global scale request failed";
  const status = /forbidden/i.test(message)
    ? 403
    : /not found/i.test(message)
      ? 404
      : /invalid|required|period|scope|customer|organization|date|email|numeric|region|path|integration/i.test(message)
        ? 400
        : 500;
  return jsonError(status === 500 ? "global scale operation unavailable" : message, status, requestId);
}
