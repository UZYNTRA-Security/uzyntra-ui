import { db } from "../../../../db/client.js";
import { handleAiContext, requireAiPermission } from "../../../../lib/ai-copilot/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requireAiPermission({ database, request, operation: "context", method: "GET" });
  if (auth.response) return auth.response;
  return handleAiContext({ request, database, identity: auth.identity, requestId: auth.requestId });
}
