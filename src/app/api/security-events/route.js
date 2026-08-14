import { db } from "../../../db/client.js";
import { contextIdentity, getAuthenticatedContext } from "../../../lib/auth/context.js";
import { handleSecurityEventsRequest } from "../../../lib/security-events/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request) {
  const database = db();
  return handleSecurityEventsRequest({
    request,
    database,
    resolveIdentity: () => authenticatedIdentity(database),
  });
}

async function authenticatedIdentity(database) {
  try {
    return contextIdentity(await getAuthenticatedContext({ database }));
  } catch (error) {
    console.error("Security event session resolution failed", error);
    return null;
  }
}
