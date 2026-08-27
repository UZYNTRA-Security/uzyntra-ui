import { db } from "../../../../db/client.js";
import {
  handleDetectorFeedbackCreate,
  requireAdvancedDetectionPermission,
} from "../../../../lib/advanced-detection/api.js";

export async function POST(request) {
  const database = db();
  const auth = await requireAdvancedDetectionPermission({
    database,
    request,
    operation: "feedback",
    method: "POST",
  });
  if (auth.response) return auth.response;
  return handleDetectorFeedbackCreate({
    request,
    database,
    identity: auth.identity,
    requestId: auth.requestId,
  });
}
