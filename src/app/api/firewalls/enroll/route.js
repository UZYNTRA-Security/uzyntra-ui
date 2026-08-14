import { db } from "../../../../db/client.js";
import { enrollFirewall } from "../../../../lib/management/firewalls.js";
import { json, jsonError, readJson } from "../../../../lib/management/api.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function POST(request) {
  const database = db();
  const body = await readJson(request);
  if (body.error) return body.error;

  const auditContext = {
    requestId: crypto.randomUUID(),
    ipAddress: clientIp(request.headers),
    userAgent: userAgent(request.headers),
  };

  try {
    const enrolled = await enrollFirewall({
      database,
      plaintextToken: body.data?.enrollmentToken,
      installationIdentifier: body.data?.installationIdentifier,
      hostname: body.data?.hostname,
      version: body.data?.version,
      region: body.data?.region,
      metadata: body.data?.metadata,
      auditContext,
    });

    if (!enrolled) return jsonError("Invalid enrollment", 400);

    return json(
      {
        success: true,
        data: {
          firewall: enrolled.firewall,
          serviceAccount: enrolled.serviceAccount,
          apiKey: enrolled.apiKey.apiKey,
          plaintextApiKey: enrolled.apiKey.plaintextKey,
        },
      },
      201,
    );
  } catch (error) {
    console.error("Firewall enrollment failed", error);
    return jsonError("Invalid enrollment", 400);
  }
}

function clientIp(headersList) {
  const forwardedFor = headersList.get("x-forwarded-for");
  return safeString(forwardedFor ? forwardedFor.split(",")[0] : headersList.get("x-real-ip"), 45);
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
