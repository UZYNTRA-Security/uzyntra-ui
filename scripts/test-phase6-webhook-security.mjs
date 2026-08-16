import assert from "node:assert/strict";
import {
  buildWebhookHeaders,
  safeWebhookPayload,
  validateWebhookUrl,
} from "../src/lib/notifications/webhook.js";

assert.equal(validateWebhookUrl("https://example.com/uzyntra"), "https://example.com/uzyntra");
assert.throws(() => validateWebhookUrl("http://127.0.0.1/hook"), /https/);
assert.throws(() => validateWebhookUrl("https://127.0.0.1/hook"), /blocked/);
assert.throws(() => validateWebhookUrl("https://localhost/hook"), /blocked/);
assert.throws(() => validateWebhookUrl("https://10.0.0.1/hook"), /blocked/);
assert.throws(() => validateWebhookUrl("https://192.168.1.2/hook"), /blocked/);
assert.throws(() => validateWebhookUrl("https://169.254.169.254/latest"), /blocked/);
assert.throws(() => validateWebhookUrl("file:///tmp/x"), /https/);
assert.throws(() => validateWebhookUrl("gopher://example.com"), /https/);

const payload = safeWebhookPayload({
  deliveryId: "delivery-1",
  eventType: "alert.created",
  organizationId: "org-1",
  alert: {
    id: "alert-1",
    severity: "critical",
    status: "open",
    title: "Alert",
    detectorId: "uz-ssrf-001",
    rawMetadata: { token: "must-not-copy" },
  },
});
assert.equal(JSON.stringify(payload).includes("must-not-copy"), false);

const headers = buildWebhookHeaders({
  deliveryId: "delivery-1",
  payload,
  secret: "receiver-secret",
  timestamp: 123,
});
assert.equal(headers["x-uzyntra-delivery-id"], "delivery-1");
assert.match(headers["x-uzyntra-signature"], /^v1=/);

console.log("phase 6 webhook security tests passed");
