import { db } from "../../../db/client.js";
import {
  handleTestCaseCreate,
  handleTestCaseList,
  requirePolicySimulationPermission,
} from "../../../lib/policy-simulation/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requirePolicySimulationPermission({ database, request, operation: "test-cases", method: "GET" });
  if (auth.response) return auth.response;
  return handleTestCaseList({ request, database, identity: auth.identity, requestId: auth.requestId });
}

export async function POST(request) {
  const database = db();
  const auth = await requirePolicySimulationPermission({ database, request, operation: "test-cases", method: "POST" });
  if (auth.response) return auth.response;
  return handleTestCaseCreate({ request, database, identity: auth.identity, requestId: auth.requestId });
}
