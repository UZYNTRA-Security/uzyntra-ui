import { db } from "../../../../db/client.js";
import {
  handleGlobalScaleRequest,
  requireGlobalScalePermission,
} from "../../../../lib/global-scale/api.js";

export async function GET(request) {
  return handle(request, "GET");
}

export async function POST(request) {
  return handle(request, "POST");
}

async function handle(request, method) {
  const database = db();
  const auth = await requireGlobalScalePermission({
    database,
    request,
    operation: "regions",
    method,
  });
  if (auth.response) return auth.response;
  return handleGlobalScaleRequest({
    request,
    database,
    identity: auth.identity,
    requestId: auth.requestId,
    operation: "regions",
    method,
  });
}
