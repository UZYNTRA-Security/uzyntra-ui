import { db } from "../../../../db/client.js";
import { handleAiMessages, requireAiPermission } from "../../../../lib/ai-copilot/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requireAiPermission({ database, request, operation: "messages", method: "GET" });
  if (auth.response) return auth.response;
  return handleAiMessages({ request, database, identity: auth.identity, requestId: auth.requestId, method: "GET" });
}

export async function POST(request) {
  const database = db();
  const auth = await requireAiPermission({ database, request, operation: "messages", method: "POST" });
  if (auth.response) return auth.response;
  return handleAiMessages({ request, database, identity: auth.identity, requestId: auth.requestId, method: "POST" });
}
