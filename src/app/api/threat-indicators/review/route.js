import { db } from "../../../../db/client.js";
import {
  handleThreatIndicatorReview,
  requireThreatIntelPermission,
} from "../../../../lib/threat-intelligence/api.js";

export async function POST(request) {
  const database = db();
  const auth = await requireThreatIntelPermission({
    database,
    request,
    operation: "indicator-review",
    method: "POST",
  });
  if (auth.response) return auth.response;
  return handleThreatIndicatorReview({
    request,
    database,
    identity: auth.identity,
    requestId: auth.requestId,
  });
}
