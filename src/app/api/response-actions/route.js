import { db } from "../../../db/client.js";
import { handleResponseActions, requireSoarPermission } from "../../../lib/soar/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requireSoarPermission({ database, request, operation: "response-actions", method: "GET" });
  if (auth.response) return auth.response;
  return handleResponseActions({ request, database, identity: auth.identity, requestId: auth.requestId, method: "GET" });
}

export async function POST(request) {
  const database = db();
  const auth = await requireSoarPermission({ database, request, operation: "response-actions", method: "POST" });
  if (auth.response) return auth.response;
  return handleResponseActions({ request, database, identity: auth.identity, requestId: auth.requestId, method: "POST" });
}
