import { db } from "../../../db/client.js";
import { contextIdentity, getAuthenticatedContext } from "../../../lib/auth/context.js";
import { handleApiInventoryRequest } from "../../../lib/api-inventory/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request) {
  const database = db();
  return handleApiInventoryRequest({
    request,
    database,
    resolveIdentity: () => authenticatedIdentity(database),
  });
}

async function authenticatedIdentity(database) {
  try {
    return contextIdentity(await getAuthenticatedContext({ database }));
  } catch (error) {
    console.error("API inventory session resolution failed", error);
    return null;
  }
}
