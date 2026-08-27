import { db } from "../../../../db/client.js";
import {
  handleProtectionSimulation,
  requireProtectionPermission,
} from "../../../../lib/adaptive-protection/api.js";

export async function POST(request) {
  const database = db();
  const auth = await requireProtectionPermission({ database, request, operation: "simulate", method: "POST" });
  if (auth.response) return auth.response;
  return handleProtectionSimulation({ request, database, identity: auth.identity, requestId: auth.requestId });
}
