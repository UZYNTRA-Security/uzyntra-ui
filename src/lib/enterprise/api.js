import "server-only";

import { json, jsonError, readJson, requirePermission, searchParams } from "../alerts/api.js";
import { PERMISSIONS } from "../rbac/catalog.js";
import {
  createComplianceReport,
  createCustomerTenant,
  createDelegatedAccess,
  createOrganizationHierarchy,
  getEnterpriseOverview,
  listComplianceReports,
  listCustomerTenants,
  listDelegatedAccess,
  listOrganizationHierarchy,
  listUsage,
  recordUsage,
} from "./index.js";

export async function requireEnterprisePermission({ database, request, operation, method }) {
  return requirePermission({
    database,
    request,
    permission: permissionFor(operation, method),
    route: `enterprise/${operation}`,
    method,
  });
}

export async function handleEnterpriseRequest({
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
        ? await getEnterpriseOverview({ database, organizationId: identity.organizationId })
        : operation === "hierarchy" && method === "GET"
          ? await listOrganizationHierarchy({ database, organizationId: identity.organizationId, filters: query })
          : operation === "hierarchy"
            ? await createOrganizationHierarchy({ ...common, input: body })
            : operation === "customers" && method === "GET"
              ? await listCustomerTenants({ database, organizationId: identity.organizationId, filters: query })
              : operation === "customers"
                ? await createCustomerTenant({ ...common, input: body })
                : operation === "delegated-access" && method === "GET"
                  ? await listDelegatedAccess({ database, organizationId: identity.organizationId, filters: query })
                  : operation === "delegated-access"
                    ? await createDelegatedAccess({ ...common, input: body })
                    : operation === "compliance-reports" && method === "GET"
                      ? await listComplianceReports({ database, organizationId: identity.organizationId, filters: query })
                      : operation === "compliance-reports"
                        ? await createComplianceReport({ ...common, input: body })
                        : operation === "usage" && method === "GET"
                          ? await listUsage({ database, organizationId: identity.organizationId, filters: query })
                          : operation === "usage"
                            ? await recordUsage({ ...common, input: body })
                            : null;

    if (!data) return jsonError("Not found", 404, requestId);
    return json({ success: true, data }, method === "GET" ? 200 : 201, requestId);
  } catch (error) {
    return enterpriseError(error, requestId);
  }
}

function permissionFor(operation, method) {
  if (operation === "overview") return PERMISSIONS.ENTERPRISE_READ;
  if (operation === "hierarchy") return method === "GET" ? PERMISSIONS.ENTERPRISE_READ : PERMISSIONS.ENTERPRISE_MANAGE;
  if (operation === "customers") return method === "GET" ? PERMISSIONS.TENANT_READ : PERMISSIONS.TENANT_MANAGE;
  if (operation === "delegated-access") return method === "GET" ? PERMISSIONS.DELEGATED_ACCESS_READ : PERMISSIONS.DELEGATED_ACCESS_MANAGE;
  if (operation === "compliance-reports") return method === "GET" ? PERMISSIONS.COMPLIANCE_REPORTS_READ : PERMISSIONS.COMPLIANCE_REPORTS_GENERATE;
  if (operation === "usage") return method === "GET" ? PERMISSIONS.USAGE_READ : PERMISSIONS.ENTERPRISE_MANAGE;
  return PERMISSIONS.ENTERPRISE_READ;
}

function enterpriseError(error, requestId) {
  const message = error?.message || "enterprise request failed";
  const status = /forbidden/i.test(message)
    ? 403
    : /not found/i.test(message)
      ? 404
      : /invalid|required|period|scope|customer|organization|date|email|numeric/i.test(message)
        ? 400
        : 500;
  return jsonError(status === 500 ? "enterprise operation unavailable" : message, status, requestId);
}
