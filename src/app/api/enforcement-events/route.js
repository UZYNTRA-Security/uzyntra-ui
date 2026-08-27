import { db } from "../../../db/client.js";
import {
  handleEnforcementEvents,
  requireProtectionPermission,
} from "../../../lib/adaptive-protection/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requireProtectionPermission({ database, request, operation: "events", method: "GET" });
  if (auth.response) return auth.response;
  return handleEnforcementEvents({ request, database, identity: auth.identity, requestId: auth.requestId });
}
