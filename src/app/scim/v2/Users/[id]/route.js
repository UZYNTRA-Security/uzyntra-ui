import { db } from "../../../../../db/client.js";
import {
  authenticateScimRequest,
  getScimUser,
  patchScimUser,
  scimError,
  scimJson,
  updateScimUser,
} from "../../../../../lib/scim/index.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request, context) {
  const database = db();
  const auth = await authenticateScimRequest(request, { database });
  if (!auth) return scimError("Unauthorized", 401);

  const { id } = await context.params;
  const result = await getScimUser({
    database,
    organizationId: auth.organizationId,
    userId: id,
  });
  return result ? scimJson(result) : scimError("SCIM user not found", 404);
}

export async function PUT(request, context) {
  return update(request, context);
}

export async function PATCH(request, context) {
  const { id } = await context.params;
  const database = db();
  const auth = await authenticateScimRequest(request, { database });
  if (!auth) return scimError("Unauthorized", 401);

  try {
    const result = await patchScimUser({
      database,
      organizationId: auth.organizationId,
      providerId: auth.provider.id,
      userId: id,
      payload: await request.json(),
    });
    return result ? scimJson(result) : scimError("SCIM user not found", 404);
  } catch (error) {
    return scimError(error?.message || "invalid SCIM patch", 400);
  }
}

async function update(request, context) {
  const { id } = await context.params;
  const database = db();
  const auth = await authenticateScimRequest(request, { database });
  if (!auth) return scimError("Unauthorized", 401);

  try {
    const result = await updateScimUser({
      database,
      organizationId: auth.organizationId,
      providerId: auth.provider.id,
      userId: id,
      payload: await request.json(),
    });
    return result ? scimJson(result) : scimError("SCIM user not found", 404);
  } catch (error) {
    return scimError(error?.message || "invalid SCIM user", 400);
  }
}
