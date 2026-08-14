import { db } from "../../../../db/client.js";
import { switchActiveOrganization } from "../../../../lib/management/organizations.js";
import {
  json,
  jsonError,
  readJson,
  requireAuthenticatedManagement,
} from "../../../../lib/management/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request) {
  const database = db();
  const auth = await requireAuthenticatedManagement(request, { database });
  if (auth.error) return auth.error;

  const body = await readJson(request);
  if (body.error) return body.error;

  const session = await switchActiveOrganization({
    database,
    userId: auth.context.userId,
    sessionId: auth.context.sessionId,
    organizationId: body.data?.organizationId,
    auditContext: auth.auditContext,
  });

  if (!session) {
    return jsonError("Forbidden", 403);
  }

  return json({ success: true, data: { organizationId: session.organizationId } });
}
