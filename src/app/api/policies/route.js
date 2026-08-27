import { db } from "../../../db/client.js";
import {
  handlePolicyCreate,
  handlePolicyList,
  requireZeroTrustPermission,
} from "../../../lib/zero-trust/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requireZeroTrustPermission({ database, request, operation: "policies", method: "GET" });
  if (auth.response) return auth.response;
  return handlePolicyList({ request, database, identity: auth.identity, requestId: auth.requestId });
}

export async function POST(request) {
  const database = db();
  const auth = await requireZeroTrustPermission({ database, request, operation: "policies", method: "POST" });
  if (auth.response) return auth.response;
  return handlePolicyCreate({ request, database, identity: auth.identity, requestId: auth.requestId });
}
