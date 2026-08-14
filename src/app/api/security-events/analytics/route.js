import { db } from "../../../../db/client.js";
import { contextIdentity, getAuthenticatedContext } from "../../../../lib/auth/context.js";
import { handleSecurityEventAnalyticsRequest } from "../../../../lib/security-events/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request) {
  const database = db();
  return handleSecurityEventAnalyticsRequest({
    request,
    database,
    resolveIdentity: () => authenticatedIdentity(database),
  });
}

async function authenticatedIdentity(database) {
  try {
    return contextIdentity(await getAuthenticatedContext({ database }));
  } catch (error) {
    console.error("Security event analytics session resolution failed", error);
    return null;
  }
}
