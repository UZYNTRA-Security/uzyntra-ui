import { db } from "../../../../db/client.js";
import { handleAiExplain, requireAiPermission } from "../../../../lib/ai-copilot/api.js";

export async function POST(request) {
  const database = db();
  const auth = await requireAiPermission({ database, request, operation: "explain", method: "POST" });
  if (auth.response) return auth.response;
  return handleAiExplain({ request, database, identity: auth.identity, requestId: auth.requestId });
}
