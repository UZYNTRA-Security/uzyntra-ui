import { db } from "../../../db/client.js";
import {
  handleThreatIndicatorCreate,
  handleThreatIntelRead,
  requireThreatIntelPermission,
} from "../../../lib/threat-intelligence/api.js";

export async function GET(request) {
  const database = db();
  const auth = await requireThreatIntelPermission({
    database,
    request,
    operation: "indicators",
    method: "GET",
  });
  if (auth.response) return auth.response;
  return handleThreatIntelRead({
    request,
    database,
    identity: auth.identity,
    requestId: auth.requestId,
    operation: "indicators",
  });
}

export async function POST(request) {
  const database = db();
  const auth = await requireThreatIntelPermission({
    database,
    request,
    operation: "indicators",
    method: "POST",
  });
  if (auth.response) return auth.response;
  return handleThreatIndicatorCreate({
    request,
    database,
    identity: auth.identity,
    requestId: auth.requestId,
  });
}
