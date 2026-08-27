import { db } from "../../../../db/client.js";
import { contextIdentity, getAuthenticatedContext } from "../../../../lib/auth/context.js";
import { handleSecurityOperationRequest } from "../../../../lib/security-operations/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request) {
  const database = db();
  return handleSecurityOperationRequest({
    request,
    database,
    operation: "trends",
    resolveIdentity: () => authenticatedIdentity(database),
  });
}

async function authenticatedIdentity(database) {
  try {
    return contextIdentity(await getAuthenticatedContext({ database }));
  } catch (error) {
    console.error("Security trends session resolution failed", error);
    return null;
  }
}
