import { db } from "../../../../db/client.js";
import { getIdentityStatus } from "../../../../lib/identity/index.js";
import { json, requireAuthenticatedManagement } from "../../../../lib/management/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request) {
  const database = db();
  const auth = await requireAuthenticatedManagement(request, { database });
  if (auth.error) return auth.error;

  const status = await getIdentityStatus({
    database,
    organizationId: auth.context.organizationId,
    userId: auth.context.userId,
  });

  return json({ success: true, data: { status } });
}
