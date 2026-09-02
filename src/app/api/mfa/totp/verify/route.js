import { db } from "../../../../../db/client.js";
import { verifyTotpEnrollment } from "../../../../../lib/auth/mfa.js";
import {
  json,
  readJson,
  requireAuthenticatedManagement,
  routeError,
} from "../../../../../lib/management/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request) {
  const database = db();
  const auth = await requireAuthenticatedManagement(request, { database });
  if (auth.error) return auth.error;

  const body = await readJson(request);
  if (body.error) return body.error;

  try {
    const method = await verifyTotpEnrollment({
      database,
      organizationId: auth.context.organizationId,
      userId: auth.context.userId,
      methodId: body.data?.methodId,
      code: body.data?.code,
      auditContext: auth.auditContext,
    });

    return json({ success: true, data: { method } });
  } catch (error) {
    return routeError(error);
  }
}
