import { db } from "../../../../db/client.js";
import {
  AUDIT_EVENT_TYPES,
  AUDIT_RESULTS,
  AUDIT_SEVERITIES,
  createAuditEvent,
} from "../../../../lib/audit/index.js";
import { authenticateServiceAccountApiKey } from "../../../../lib/api-keys/index.js";
import { createSecurityEvent } from "../../../../lib/security-events/index.js";

const MAX_INGEST_BODY_BYTES = 256 * 1024;

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request) {
  return handleSecurityEventIngestion({ request });
}

export async function handleSecurityEventIngestion({ request, database = db() } = {}) {
  const requestId = crypto.randomUUID();
  const ipAddress = clientIp(request.headers);
  const agent = userAgent(request.headers);

  if (!isJsonRequest(request)) {
    await recordIngestionAudit(database, {
      result: AUDIT_RESULTS.FAILURE,
      requestId,
      ipAddress,
      userAgent: agent,
      reason: "invalid_content_type",
    });
    return jsonError("content-type must be application/json", 415);
  }

  const presentedKey = bearerToken(request.headers);
  if (!presentedKey) {
    await recordIngestionAudit(database, {
      result: AUDIT_RESULTS.FAILURE,
      requestId,
      ipAddress,
      userAgent: agent,
      reason: "missing_api_key",
    });
    return jsonError("Unauthorized", 401);
  }

  let identity;
  try {
    identity = await authenticateServiceAccountApiKey({
      database,
      plaintextKey: presentedKey,
    });
  } catch (error) {
    console.error("Security event API key authentication failed", error);
    await recordIngestionAudit(database, {
      result: AUDIT_RESULTS.ERROR,
      requestId,
      ipAddress,
      userAgent: agent,
      reason: "authentication_error",
    });
    return jsonError("ingestion unavailable", 500);
  }

  if (!identity) {
    await recordIngestionAudit(database, {
      result: AUDIT_RESULTS.FAILURE,
      requestId,
      ipAddress,
      userAgent: agent,
      reason: "invalid_api_key",
    });
    return jsonError("Unauthorized", 401);
  }

  const body = await readJsonBody(request);
  if (body.error) {
    await recordIngestionAudit(database, {
      result: AUDIT_RESULTS.FAILURE,
      organizationId: identity.organizationId,
      serviceAccountId: identity.serviceAccountId,
      requestId,
      ipAddress,
      userAgent: agent,
      reason: body.reason,
    });
    return body.error;
  }

  try {
    const created = await createSecurityEvent({
      database,
      organizationId: identity.organizationId,
      firewallInstanceId: body.data?.firewallInstanceId,
      eventType: body.data?.eventType,
      attackType: body.data?.attackType,
      severity: body.data?.severity,
      sourceIp: body.data?.sourceIp,
      requestPath: body.data?.requestPath,
      httpMethod: body.data?.httpMethod,
      userAgent: body.data?.userAgent,
      country: body.data?.country,
      confidence: body.data?.confidence,
      actionTaken: body.data?.actionTaken,
      requestId: body.data?.requestId || requestId,
      rawMetadata: body.data?.rawMetadata,
      occurredAt: body.data?.occurredAt,
    });

    await recordIngestionAudit(database, {
      result: AUDIT_RESULTS.SUCCESS,
      organizationId: identity.organizationId,
      serviceAccountId: identity.serviceAccountId,
      firewallInstanceId: created.firewallInstanceId,
      requestId,
      ipAddress,
      userAgent: agent,
      resourceId: created.id,
      metadata: {
        apiKeyPrefix: identity.apiKey.keyPrefix,
        eventType: created.eventType,
        attackType: created.attackType,
        severity: created.severity,
        actionTaken: created.actionTaken,
      },
    });

    return json({ success: true, eventId: created.id }, 201);
  } catch (error) {
    const forbidden = /firewall instance is not available/i.test(error?.message || "");
    await recordIngestionAudit(database, {
      result: forbidden ? AUDIT_RESULTS.DENIED : AUDIT_RESULTS.FAILURE,
      organizationId: identity.organizationId,
      serviceAccountId: identity.serviceAccountId,
      firewallInstanceId: safeString(body.data?.firewallInstanceId, 160),
      requestId,
      ipAddress,
      userAgent: agent,
      reason: forbidden ? "firewall_not_available" : "invalid_payload",
    });

    return jsonError(forbidden ? "Forbidden" : "invalid security event", forbidden ? 403 : 400);
  }
}

function bearerToken(headersList) {
  const authorization = headersList.get("authorization");
  if (!authorization) {
    return null;
  }

  const match = /^Bearer\s+(.+)$/i.exec(authorization.trim());
  return match?.[1]?.trim() || null;
}

function isJsonRequest(request) {
  const contentType = request.headers.get("content-type");
  return !contentType || contentType.toLowerCase().startsWith("application/json");
}

async function readJsonBody(request) {
  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > MAX_INGEST_BODY_BYTES) {
    return { error: jsonError("request body too large", 413), reason: "body_too_large" };
  }

  const body = await request.text();
  if (new TextEncoder().encode(body).length > MAX_INGEST_BODY_BYTES) {
    return { error: jsonError("request body too large", 413), reason: "body_too_large" };
  }

  try {
    return { data: body ? JSON.parse(body) : {} };
  } catch {
    return { error: jsonError("invalid json body", 400), reason: "invalid_json" };
  }
}

async function recordIngestionAudit(database, event = {}) {
  try {
    await createAuditEvent({
      database,
      eventType:
        event.result === AUDIT_RESULTS.SUCCESS
          ? AUDIT_EVENT_TYPES.SECURITY_EVENT_INGESTED
          : AUDIT_EVENT_TYPES.SECURITY_EVENT_INGESTION_FAILED,
      action:
        event.result === AUDIT_RESULTS.SUCCESS
          ? AUDIT_EVENT_TYPES.SECURITY_EVENT_INGESTED
          : AUDIT_EVENT_TYPES.SECURITY_EVENT_INGESTION_FAILED,
      result: event.result,
      severity:
        event.result === AUDIT_RESULTS.SUCCESS ? AUDIT_SEVERITIES.INFO : AUDIT_SEVERITIES.MEDIUM,
      organizationId: event.organizationId,
      serviceAccountId: event.serviceAccountId,
      firewallInstanceId: event.firewallInstanceId,
      resourceType: "security_event",
      resourceId: event.resourceId,
      requestId: event.requestId,
      ipAddress: event.ipAddress,
      userAgent: event.userAgent,
      metadata: {
        reason: event.reason,
        ...event.metadata,
      },
    });
  } catch (error) {
    console.error("Security event ingestion audit failed", error);
  }
}

function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

function jsonError(error, status) {
  return json({ error }, status);
}

function clientIp(headersList) {
  const forwardedFor = headersList.get("x-forwarded-for");
  if (forwardedFor) {
    return safeString(forwardedFor.split(",")[0], 45);
  }

  return safeString(headersList.get("x-real-ip"), 45);
}

function userAgent(headersList) {
  return safeString(headersList.get("user-agent"), 1024);
}

function safeString(value, maxLength) {
  return (
    String(value || "")
      .replace(/[^\x20-\x7E]/g, "")
      .trim()
      .slice(0, maxLength) || null
  );
}
