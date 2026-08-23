import "server-only";

import crypto from "node:crypto";

export const SERVICE_AUTH_HEADER = "x-uzyntra-service-token";

export function verifyServiceRequest(headersList) {
  const expected = serviceToken();
  if (!expected) {
    return true;
  }

  const presented = headersList.get(SERVICE_AUTH_HEADER);
  if (!presented) {
    return false;
  }

  return timingSafeEqual(presented.trim(), expected);
}

function serviceToken() {
  return process.env.CONTROL_PLANE_SERVICE_TOKEN || process.env.UZYNTRA_CONTROL_PLANE_SERVICE_TOKEN || "";
}

function timingSafeEqual(left, right) {
  const leftBuffer = Buffer.from(String(left), "utf8");
  const rightBuffer = Buffer.from(String(right), "utf8");

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}
