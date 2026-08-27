import { db } from "../../../db/client.js";
import {
  handleAdvancedDetectionList,
  requireAdvancedDetectionPermission,
} from "../../../lib/advanced-detection/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requireAdvancedDetectionPermission({
    database,
    request,
    operation: "risk",
    method: "GET",
  });
  if (auth.response) return auth.response;
  return handleAdvancedDetectionList({
    request,
    database,
    operation: "risk",
    identity: auth.identity,
    requestId: auth.requestId,
  });
}
