import { db } from "../../../../db/client.js";
import { selectActiveFirewall } from "../../../../lib/management/firewalls.js";
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

  const session = await selectActiveFirewall({
    database,
    organizationId: auth.context.organizationId,
    sessionId: auth.context.sessionId,
    firewallInstanceId: body.data?.firewallInstanceId || null,
  });

  if (!session) return jsonError("Forbidden", 403);
  return json({
    success: true,
    data: { activeFirewallInstanceId: session.activeFirewallInstanceId },
  });
}
