import { db } from "../../../db/client.js";
import {
  handleEnterpriseRequest,
  requireEnterprisePermission,
} from "../../../lib/enterprise/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requireEnterprisePermission({
    database,
    request,
    operation: "overview",
    method: "GET",
  });
  if (auth.response) return auth.response;
  return handleEnterpriseRequest({
    request,
    database,
    identity: auth.identity,
    requestId: auth.requestId,
    operation: "overview",
    method: "GET",
  });
}
