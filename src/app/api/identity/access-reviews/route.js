import { db } from "../../../../db/client.js";
import {
  completeIdentityAccessReview,
  createIdentityAccessReview,
  listIdentityAccessReviews,
} from "../../../../lib/identity-security/index.js";
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
  const auth = await requireManagementPermission(request, PERMISSIONS.ACCESS_REVIEWS_READ, { database });
  if (auth.error) return auth.error;

  const reviews = await listIdentityAccessReviews({
    database,
    organizationId: auth.context.organizationId,
    filters: Object.fromEntries(new URL(request.url).searchParams.entries()),
  });
  return json({ success: true, data: reviews });
}

export async function POST(request) {
  const database = db();
  const auth = await requireManagementPermission(request, PERMISSIONS.ACCESS_REVIEWS_MANAGE, { database });
  if (auth.error) return auth.error;

  const body = await readJson(request);
  if (body.error) return body.error;

  try {
    const review = body.data?.completeReview
      ? await completeIdentityAccessReview({
          database,
          organizationId: auth.context.organizationId,
          reviewId: body.data.reviewId,
          findings: body.data.findings,
          summary: body.data.summary,
          completedByUserId: auth.context.userId,
          auditContext: auth.auditContext,
        })
      : await createIdentityAccessReview({
          database,
          organizationId: auth.context.organizationId,
          name: body.data?.name,
          reviewType: body.data?.reviewType,
          status: body.data?.status,
          scope: body.data?.scope,
          summary: body.data?.summary,
          findings: body.data?.findings,
          assignedToUserId: body.data?.assignedToUserId,
          dueAt: body.data?.dueAt ? new Date(body.data.dueAt) : null,
          createdByUserId: auth.context.userId,
          auditContext: auth.auditContext,
        });
    return json({ success: true, data: { review } }, 201);
  } catch (error) {
    return routeError(error);
  }
}
