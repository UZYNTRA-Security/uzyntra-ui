import { db } from "../../../db/client.js";
import {
  handleProtectionCreate,
  handleProtectionList,
  requireProtectionPermission,
} from "../../../lib/adaptive-protection/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requireProtectionPermission({ database, request, operation: "protection", method: "GET" });
  if (auth.response) return auth.response;
  return handleProtectionList({ request, database, identity: auth.identity, requestId: auth.requestId });
}

export async function POST(request) {
  const database = db();
  const auth = await requireProtectionPermission({ database, request, operation: "protection", method: "POST" });
  if (auth.response) return auth.response;
  return handleProtectionCreate({ request, database, identity: auth.identity, requestId: auth.requestId });
}
