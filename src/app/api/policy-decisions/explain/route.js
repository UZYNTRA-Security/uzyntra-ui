import { db } from "../../../../db/client.js";
import {
  handleDecisionExplain,
  requirePolicySimulationPermission,
} from "../../../../lib/policy-simulation/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requirePolicySimulationPermission({ database, request, operation: "decisions", method: "GET" });
  if (auth.response) return auth.response;
  return handleDecisionExplain({ request, database, identity: auth.identity, requestId: auth.requestId });
}
