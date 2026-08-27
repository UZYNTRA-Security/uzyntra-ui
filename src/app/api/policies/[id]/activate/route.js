import { db } from "../../../../../db/client.js";
import {
  handlePolicyActivate,
  requireZeroTrustPermission,
} from "../../../../../lib/zero-trust/api.js";

export async function POST(request, { params }) {
  const database = db();
  const auth = await requireZeroTrustPermission({ database, request, operation: "policies", method: "POST" });
  if (auth.response) return auth.response;
  const { id } = await params;
  return handlePolicyActivate({ request, database, identity: auth.identity, requestId: auth.requestId, policyId: id });
}
