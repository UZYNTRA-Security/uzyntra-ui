import { db } from "../../../db/client.js";
import {
  handleAdvancedDetectionList,
  handleDetectorConfigurationUpsert,
  requireAdvancedDetectionPermission,
} from "../../../lib/advanced-detection/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requireAdvancedDetectionPermission({
    database,
    request,
    operation: "rules",
    method: "GET",
  });
  if (auth.response) return auth.response;
  return handleAdvancedDetectionList({
    request,
    database,
    operation: "rules",
    identity: auth.identity,
    requestId: auth.requestId,
  });
}

export async function POST(request) {
  const database = db();
  const auth = await requireAdvancedDetectionPermission({
    database,
    request,
    operation: "rules",
    method: "POST",
  });
  if (auth.response) return auth.response;
  return handleDetectorConfigurationUpsert({
    request,
    database,
    identity: auth.identity,
    requestId: auth.requestId,
  });
}
