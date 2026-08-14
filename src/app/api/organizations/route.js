import { db } from "../../../db/client.js";
import {
  createOrganizationForUser,
  listOrganizationsForUser,
} from "../../../lib/management/organizations.js";
import {
  json,
  readJson,
  requireAuthenticatedManagement,
  routeError,
} from "../../../lib/management/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request) {
  const database = db();
  const auth = await requireAuthenticatedManagement(request, { database });
  if (auth.error) return auth.error;

  const organizations = await listOrganizationsForUser({
    database,
    userId: auth.context.userId,
  });

  return json({ success: true, data: { organizations, activeOrganizationId: auth.context.organizationId } });
}

export async function POST(request) {
  const database = db();
  const auth = await requireAuthenticatedManagement(request, { database });
  if (auth.error) return auth.error;

  const body = await readJson(request);
  if (body.error) return body.error;

  try {
    const created = await createOrganizationForUser({
      database,
      userId: auth.context.userId,
      name: body.data?.name,
      slug: body.data?.slug,
      auditContext: auth.auditContext,
    });

    return json({ success: true, data: created }, 201);
  } catch (error) {
    return routeError(error);
  }
}
