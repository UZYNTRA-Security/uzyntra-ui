import { db } from "../../../db/client.js";
import {
  handleGlobalScaleRequest,
  requireGlobalScalePermission,
} from "../../../lib/global-scale/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requireGlobalScalePermission({
    database,
    request,
    operation: "overview",
    method: "GET",
  });
  if (auth.response) return auth.response;
  return handleGlobalScaleRequest({
    request,
    database,
    identity: auth.identity,
    requestId: auth.requestId,
    operation: "overview",
    method: "GET",
  });
}
