import { db } from "../../../db/client.js";
import {
  handleCredentialProtectionCreate,
  handleCredentialProtectionList,
  requireProtectionPermission,
} from "../../../lib/adaptive-protection/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requireProtectionPermission({ database, request, operation: "credential-protection", method: "GET" });
  if (auth.response) return auth.response;
  return handleCredentialProtectionList({ request, database, identity: auth.identity, requestId: auth.requestId });
}

export async function POST(request) {
  const database = db();
  const auth = await requireProtectionPermission({ database, request, operation: "credential-protection", method: "POST" });
  if (auth.response) return auth.response;
  return handleCredentialProtectionCreate({ request, database, identity: auth.identity, requestId: auth.requestId });
}
