import { db } from "../../../../../db/client.js";
import {
  listIdentityMetrics,
  recordIdentityMetric,
} from "../../../../../lib/identity-hardening/index.js";
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
  const auth = await requireManagementPermission(request, PERMISSIONS.IDENTITY_SECURITY_READ, { database });
  if (auth.error) return auth.error;

  const metrics = await listIdentityMetrics({
    database,
    organizationId: auth.context.organizationId,
    filters: Object.fromEntries(new URL(request.url).searchParams.entries()),
  });
  return json({ success: true, data: metrics });
}

export async function POST(request) {
  const database = db();
  const auth = await requireManagementPermission(request, PERMISSIONS.IDENTITY_SECURITY_MANAGE, { database });
  if (auth.error) return auth.error;

  const body = await readJson(request);
  if (body.error) return body.error;

  try {
    const metric = await recordIdentityMetric({
      database,
      organizationId: auth.context.organizationId,
      metricType: body.data?.metricType,
      metricValue: body.data?.metricValue,
      numerator: body.data?.numerator,
      denominator: body.data?.denominator,
      bucketStart: body.data?.bucketStart,
      bucketEnd: body.data?.bucketEnd,
      status: body.data?.status,
      dimensions: body.data?.dimensions,
      metadata: body.data?.metadata,
    });
    return json({ success: true, data: { metric } }, 201);
  } catch (error) {
    return routeError(error);
  }
}
