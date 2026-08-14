import { db } from "../../../../db/client.js";
import { acceptInvitation } from "../../../../lib/management/members.js";
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

  const accepted = await acceptInvitation({
    database,
    plaintextToken: body.data?.token,
    userId: auth.context.userId,
    auditContext: auth.auditContext,
  });

  if (!accepted) return jsonError("Invalid invitation", 400);
  return json({ success: true, data: accepted });
}
