import { db } from "../../../db/client.js";
import { listRoles } from "../../../lib/management/organizations.js";
import { json, requireAuthenticatedManagement } from "../../../lib/management/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request) {
  const database = db();
  const auth = await requireAuthenticatedManagement(request, { database });
  if (auth.error) return auth.error;

  const roles = await listRoles({
    database,
    organizationId: auth.context.organizationId,
  });

  return json({ success: true, data: { roles } });
}
