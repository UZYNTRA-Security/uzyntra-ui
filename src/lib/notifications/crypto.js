import "server-only";

import crypto from "node:crypto";

const SECRET_FORMAT = "uzyntra.secret.v1";
const KEY_VERSION = "v1";
const IV_BYTES = 12;

export function sealIntegrationSecret(plaintext, { key = integrationEncryptionKey() } = {}) {
  const value = String(plaintext || "");
  if (!value) {
    throw new Error("integration secret is required");
  }

  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    format: SECRET_FORMAT,
    keyVersion: KEY_VERSION,
    iv: iv.toString("base64url"),
    ciphertext: ciphertext.toString("base64url"),
    tag: tag.toString("base64url"),
  };
}

export function openIntegrationSecret(sealed, { key = integrationEncryptionKey() } = {}) {
  if (!sealed || sealed.format !== SECRET_FORMAT || sealed.keyVersion !== KEY_VERSION) {
    throw new Error("integration secret format is unsupported");
  }

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(sealed.iv, "base64url"),
  );
  decipher.setAuthTag(Buffer.from(sealed.tag, "base64url"));
  return Buffer.concat([
    decipher.update(Buffer.from(sealed.ciphertext, "base64url")),
    decipher.final(),
  ]).toString("utf8");
}

export function signWebhookPayload({ payload, timestamp, secret }) {
  const body = typeof payload === "string" ? payload : JSON.stringify(payload);
  const signingInput = `${timestamp}.${body}`;
  return `v1=${crypto.createHmac("sha256", secret).update(signingInput).digest("hex")}`;
}

export function verifyWebhookSignature({ payload, timestamp, secret, signature }) {
  const expected = signWebhookPayload({ payload, timestamp, secret });
  const left = Buffer.from(String(signature || ""), "utf8");
  const right = Buffer.from(expected, "utf8");
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function integrationEncryptionKey() {
  const raw = process.env.INTEGRATION_SECRET_ENCRYPTION_KEY;
  if (!raw) {
    throw new Error("INTEGRATION_SECRET_ENCRYPTION_KEY is required");
  }

  const key =
    raw.length === 64 && /^[a-f0-9]+$/i.test(raw)
      ? Buffer.from(raw, "hex")
      : Buffer.from(raw, "base64");

  if (key.length !== 32) {
    throw new Error("INTEGRATION_SECRET_ENCRYPTION_KEY must decode to 32 bytes");
  }

  return key;
}
