import { db } from "../../../../db/client.js";
import { handleAiFeedback, requireAiPermission } from "../../../../lib/ai-copilot/api.js";

export async function POST(request) {
  const database = db();
  const auth = await requireAiPermission({ database, request, operation: "feedback", method: "POST" });
  if (auth.response) return auth.response;
  return handleAiFeedback({ request, database, identity: auth.identity, requestId: auth.requestId });
}
