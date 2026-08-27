import { db } from "../../../db/client.js";
import { handleAutomationRuns, requireSoarPermission } from "../../../lib/soar/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requireSoarPermission({ database, request, operation: "automation-runs", method: "GET" });
  if (auth.response) return auth.response;
  return handleAutomationRuns({ request, database, identity: auth.identity, requestId: auth.requestId, method: "GET" });
}

export async function POST(request) {
  const database = db();
  const auth = await requireSoarPermission({ database, request, operation: "automation-runs", method: "POST" });
  if (auth.response) return auth.response;
  return handleAutomationRuns({ request, database, identity: auth.identity, requestId: auth.requestId, method: "POST" });
}
