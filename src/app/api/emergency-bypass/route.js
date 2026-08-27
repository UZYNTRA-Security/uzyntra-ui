import { db } from "../../../db/client.js";
import {
  handleEmergencyBypassCreate,
  handleEmergencyBypassList,
  requireZeroTrustPermission,
} from "../../../lib/zero-trust/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requireZeroTrustPermission({ database, request, operation: "bypass", method: "GET" });
  if (auth.response) return auth.response;
  return handleEmergencyBypassList({ request, database, identity: auth.identity, requestId: auth.requestId });
}

export async function POST(request) {
  const database = db();
  const auth = await requireZeroTrustPermission({ database, request, operation: "bypass", method: "POST" });
  if (auth.response) return auth.response;
  return handleEmergencyBypassCreate({ request, database, identity: auth.identity, requestId: auth.requestId });
}
