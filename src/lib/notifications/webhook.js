import "server-only";

import { signWebhookPayload } from "./crypto.js";

const BLOCKED_HOSTS = new Set(["localhost", "metadata.google.internal"]);
const METADATA_IP = "169.254.169.254";
const WEBHOOK_TIMEOUT_MS = 5000;
const MAX_RESPONSE_BYTES = 4096;

export function validateWebhookUrl(value, { allowHttp = false } = {}) {
  let url;
  try {
    url = new URL(String(value || ""));
  } catch {
    throw new Error("webhook url is invalid");
  }

  if (url.protocol !== "https:" && !(allowHttp && url.protocol === "http:")) {
    throw new Error("webhook url must use https");
  }

  if (url.username || url.password) {
    throw new Error("webhook url must not contain credentials");
  }

  const hostname = url.hostname.toLowerCase();
  if (BLOCKED_HOSTS.has(hostname) || hostname.endsWith(".localhost")) {
    throw new Error("webhook destination is blocked");
  }

  if (isBlockedIp(hostname)) {
    throw new Error("webhook destination is blocked");
  }

  return url.toString();
}

export function buildWebhookHeaders({ deliveryId, payload, secret, timestamp = Math.floor(Date.now() / 1000) }) {
  const body = typeof payload === "string" ? payload : JSON.stringify(payload);
  const headers = {
    "content-type": "application/json",
    "x-uzyntra-delivery-id": deliveryId,
    "x-uzyntra-timestamp": String(timestamp),
  };

  if (secret) {
    headers["x-uzyntra-signature"] = signWebhookPayload({
      payload: body,
      timestamp,
      secret,
    });
  }

  return headers;
}

export async function deliverWebhook({ url, payload, deliveryId, secret, fetchImpl = fetch }) {
  const safeUrl = validateWebhookUrl(url);
  const body = JSON.stringify(payload);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), WEBHOOK_TIMEOUT_MS);

  try {
    const response = await fetchImpl(safeUrl, {
      method: "POST",
      headers: buildWebhookHeaders({ deliveryId, payload: body, secret }),
      body,
      redirect: "error",
      signal: controller.signal,
    });

    await readBoundedResponse(response);
    return {
      ok: response.status >= 200 && response.status < 300,
      status: response.status,
      retryable: isRetryableStatus(response.status),
      errorCode: response.status >= 200 && response.status < 300 ? null : `http_${response.status}`,
    };
  } catch (error) {
    return {
      ok: false,
      status: null,
      retryable: error?.name === "AbortError" || true,
      errorCode: error?.name === "AbortError" ? "timeout" : "network_error",
    };
  } finally {
    clearTimeout(timeout);
  }
}

export function isRetryableStatus(status) {
  return status === 408 || status === 429 || (status >= 500 && status <= 599);
}

export function safeWebhookPayload({ deliveryId, eventType, organizationId, alert, incident }) {
  return {
    deliveryId,
    eventType,
    organizationId,
    alert: alert
      ? {
          id: alert.id,
          severity: alert.severity,
          status: alert.status,
          title: alert.title,
          detectorId: alert.detectorId,
          attackType: alert.attackType,
          sourceIp: alert.sourceIp,
          route: alert.route,
          eventCount: alert.eventCount,
          firstSeenAt: alert.firstSeenAt,
          lastSeenAt: alert.lastSeenAt,
        }
      : null,
    incident: incident
      ? {
          id: incident.id,
          severity: incident.severity,
          status: incident.status,
          title: incident.title,
          firstSeenAt: incident.firstSeenAt,
          lastSeenAt: incident.lastSeenAt,
        }
      : null,
  };
}

function isBlockedIp(hostname) {
  if (hostname === METADATA_IP || hostname === "::1" || hostname === "[::1]") return true;
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return false;

  const octets = hostname.split(".").map(Number);
  if (octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;

  const [a, b] = octets;
  return (
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
}

async function readBoundedResponse(response) {
  const reader = response.body?.getReader?.();
  if (!reader) {
    return "";
  }

  let received = 0;
  const chunks = [];
  while (received <= MAX_RESPONSE_BYTES) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    chunks.push(value);
  }

  return new TextDecoder().decode(Buffer.concat(chunks).subarray(0, MAX_RESPONSE_BYTES));
}
