import { db } from "../../../db/client.js";
import {
  handleRateLimitCreate,
  handleRateLimitList,
  requireProtectionPermission,
} from "../../../lib/adaptive-protection/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requireProtectionPermission({ database, request, operation: "rate-limits", method: "GET" });
  if (auth.response) return auth.response;
  return handleRateLimitList({ request, database, identity: auth.identity, requestId: auth.requestId });
}

export async function POST(request) {
  const database = db();
  const auth = await requireProtectionPermission({ database, request, operation: "rate-limits", method: "POST" });
  if (auth.response) return auth.response;
  return handleRateLimitCreate({ request, database, identity: auth.identity, requestId: auth.requestId });
}
