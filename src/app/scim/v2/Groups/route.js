import { db } from "../../../../db/client.js";
import {
  authenticateScimRequest,
  listScimGroups,
  scimError,
  scimJson,
  syncScimGroup,
} from "../../../../lib/scim/index.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request) {
  const database = db();
  const auth = await authenticateScimRequest(request, { database });
  if (!auth) return scimError("Unauthorized", 401);

  const url = new URL(request.url);
  const result = await listScimGroups({
    database,
    organizationId: auth.organizationId,
    startIndex: url.searchParams.get("startIndex") || 1,
    count: url.searchParams.get("count") || 100,
  });
  return scimJson(result);
}

export async function POST(request) {
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
    return scimJson(result, 201);
  } catch (error) {
    return scimError(error?.message || "invalid SCIM group", 400);
  }
}
