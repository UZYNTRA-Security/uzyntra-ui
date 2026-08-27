import { db } from "../../../db/client.js";
import {
  handleThreatIntelRead,
  requireThreatIntelPermission,
} from "../../../lib/threat-intelligence/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requireThreatIntelPermission({
    database,
    request,
    operation: "matches",
    method: "GET",
  });
  if (auth.response) return auth.response;
  return handleThreatIntelRead({
    request,
    database,
    identity: auth.identity,
    requestId: auth.requestId,
    operation: "matches",
  });
}
