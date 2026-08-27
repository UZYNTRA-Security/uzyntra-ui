import { db } from "../../../db/client.js";
import { handleInvestigations, requireSoarPermission } from "../../../lib/soar/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requireSoarPermission({ database, request, operation: "investigations", method: "GET" });
  if (auth.response) return auth.response;
  return handleInvestigations({ request, database, identity: auth.identity, requestId: auth.requestId, method: "GET" });
}

export async function POST(request) {
  const database = db();
  const auth = await requireSoarPermission({ database, request, operation: "investigations", method: "POST" });
  if (auth.response) return auth.response;
  return handleInvestigations({ request, database, identity: auth.identity, requestId: auth.requestId, method: "POST" });
}
