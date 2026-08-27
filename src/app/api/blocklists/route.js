import { db } from "../../../db/client.js";
import {
  handleProtectionListCreate,
  handleProtectionListRead,
  requireProtectionPermission,
} from "../../../lib/adaptive-protection/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requireProtectionPermission({ database, request, operation: "blocklists", method: "GET" });
  if (auth.response) return auth.response;
  return handleProtectionListRead({ request, database, identity: auth.identity, requestId: auth.requestId, listType: "blocklist" });
}

export async function POST(request) {
  const database = db();
  const auth = await requireProtectionPermission({ database, request, operation: "blocklists", method: "POST" });
  if (auth.response) return auth.response;
  return handleProtectionListCreate({ request, database, identity: auth.identity, requestId: auth.requestId, listType: "blocklist" });
}
