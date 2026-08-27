import { db } from "../../../db/client.js";
import {
  handleEnterpriseRequest,
  requireEnterprisePermission,
} from "../../../lib/enterprise/api.js";

export async function GET(request) {
  return handle(request, "GET");
}

export async function POST(request) {
  return handle(request, "POST");
}

async function handle(request, method) {
  const database = db();
  const auth = await requireEnterprisePermission({
    database,
    request,
    operation: "usage",
    method,
  });
  if (auth.response) return auth.response;
  return handleEnterpriseRequest({
    request,
    database,
    identity: auth.identity,
    requestId: auth.requestId,
    operation: "usage",
    method,
  });
}
