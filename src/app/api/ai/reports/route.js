import { db } from "../../../../db/client.js";
import { handleAiReports, requireAiPermission } from "../../../../lib/ai-copilot/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requireAiPermission({ database, request, operation: "reports", method: "GET" });
  if (auth.response) return auth.response;
  return handleAiReports({ request, database, identity: auth.identity, requestId: auth.requestId, method: "GET" });
}

export async function POST(request) {
  const database = db();
  const auth = await requireAiPermission({ database, request, operation: "reports", method: "POST" });
  if (auth.response) return auth.response;
  return handleAiReports({ request, database, identity: auth.identity, requestId: auth.requestId, method: "POST" });
}
