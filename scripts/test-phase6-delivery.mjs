import assert from "node:assert/strict";
import { classifyDeliveryResult, nextRetryAt } from "../src/lib/notifications/delivery.js";
import { isRetryableStatus } from "../src/lib/notifications/webhook.js";

assert.deepEqual(classifyDeliveryResult({ ok: true }, 1, 5), { status: "delivered", retry: false });
assert.deepEqual(classifyDeliveryResult({ ok: false, retryable: false, errorCode: "http_400" }, 1, 5), { status: "failed", retry: false });
assert.deepEqual(classifyDeliveryResult({ ok: false, retryable: true, errorCode: "http_500" }, 1, 5), { status: "retry", retry: true });
assert.deepEqual(classifyDeliveryResult({ ok: false, retryable: true, errorCode: "timeout" }, 5, 5), { status: "failed", retry: false });

assert.equal(isRetryableStatus(408), true);
assert.equal(isRetryableStatus(429), true);
assert.equal(isRetryableStatus(500), true);
assert.equal(isRetryableStatus(400), false);
assert.ok(nextRetryAt(1, new Date("2026-08-16T00:00:00Z")) > new Date("2026-08-16T00:00:00Z"));

console.log("phase 6 delivery retry tests passed");
