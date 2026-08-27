import { db } from "../../../../db/client.js";
import {
  handlePolicyGet,
  requireZeroTrustPermission,
} from "../../../../lib/zero-trust/api.js";

export async function GET(request, { params }) {
  const database = db();
  const auth = await requireZeroTrustPermission({ database, request, operation: "policies", method: "GET" });
  if (auth.response) return auth.response;
  const { id } = await params;
  return handlePolicyGet({ database, identity: auth.identity, requestId: auth.requestId, policyId: id });
}
