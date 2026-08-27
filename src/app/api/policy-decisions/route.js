import { db } from "../../../db/client.js";
import {
  handleDecisionList,
  requireZeroTrustPermission,
} from "../../../lib/zero-trust/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requireZeroTrustPermission({ database, request, operation: "decisions", method: "GET" });
  if (auth.response) return auth.response;
  return handleDecisionList({ request, database, identity: auth.identity, requestId: auth.requestId });
}
