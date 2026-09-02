import { db } from "../../../../../db/client.js";
import {
  authenticateScimRequest,
  getScimGroup,
  scimError,
  scimJson,
  syncScimGroup,
} from "../../../../../lib/scim/index.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request, context) {
  const database = db();
  const auth = await authenticateScimRequest(request, { database });
  if (!auth) return scimError("Unauthorized", 401);

  const { id } = await context.params;
  const result = await getScimGroup({
    database,
    organizationId: auth.organizationId,
    groupId: id,
  });
  return result ? scimJson(result) : scimError("SCIM group not found", 404);
}

export async function PATCH(request) {
  const database = db();
  const auth = await authenticateScimRequest(request, { database });
  if (!auth) return scimError("Unauthorized", 401);

  try {
    const result = await syncScimGroup({
      database,
      organizationId: auth.organizationId,
      providerId: auth.provider.id,
      payload: await request.json(),
    });
    return scimJson(result);
  } catch (error) {
    return scimError(error?.message || "invalid SCIM group", 400);
  }
}
