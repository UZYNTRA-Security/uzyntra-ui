import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  openIntegrationSecret,
  sealIntegrationSecret,
  signWebhookPayload,
  verifyWebhookSignature,
} from "../src/lib/notifications/crypto.js";

const key = crypto.randomBytes(32);
const sealedA = sealIntegrationSecret("receiver-secret", { key });
const sealedB = sealIntegrationSecret("receiver-secret", { key });
assert.notEqual(sealedA.ciphertext, sealedB.ciphertext);
assert.equal(openIntegrationSecret(sealedA, { key }), "receiver-secret");

assert.throws(
  () => openIntegrationSecret({ ...sealedA, ciphertext: sealedA.ciphertext.replace(/.$/, "A") }, { key }),
  /Unsupported state|authenticate|bad decrypt|invalid/i,
);

const payload = JSON.stringify({ deliveryId: "delivery-1" });
const signature = signWebhookPayload({ payload, timestamp: 123, secret: "secret" });
assert.equal(verifyWebhookSignature({ payload, timestamp: 123, secret: "secret", signature }), true);
assert.equal(verifyWebhookSignature({ payload: `${payload} `, timestamp: 123, secret: "secret", signature }), false);
assert.equal(verifyWebhookSignature({ payload, timestamp: 124, secret: "secret", signature }), false);
assert.equal(verifyWebhookSignature({ payload, timestamp: 123, secret: "wrong", signature }), false);

console.log("phase 6 encryption and signing tests passed");
