import { db } from "../../../db/client.js";
import {
  handleChangeRequestCreate,
  handleChangeRequestList,
  requirePolicySimulationPermission,
} from "../../../lib/policy-simulation/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requirePolicySimulationPermission({ database, request, operation: "change-requests", method: "GET" });
  if (auth.response) return auth.response;
  return handleChangeRequestList({ request, database, identity: auth.identity, requestId: auth.requestId });
}

export async function POST(request) {
  const database = db();
  const auth = await requirePolicySimulationPermission({ database, request, operation: "change-requests", method: "POST" });
  if (auth.response) return auth.response;
  return handleChangeRequestCreate({ request, database, identity: auth.identity, requestId: auth.requestId });
}
