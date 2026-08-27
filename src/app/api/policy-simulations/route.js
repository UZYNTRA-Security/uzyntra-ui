import { db } from "../../../db/client.js";
import {
  handleSimulationList,
  requirePolicySimulationPermission,
} from "../../../lib/policy-simulation/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requirePolicySimulationPermission({ database, request, operation: "simulations", method: "GET" });
  if (auth.response) return auth.response;
  return handleSimulationList({ request, database, identity: auth.identity, requestId: auth.requestId });
}
