import assert from "node:assert/strict";
import {
  enrollmentCredentialRejected,
  parseEnrollmentBody,
} from "../src/lib/management/enrollment-contract.js";
import { verifyServiceRequest } from "../src/lib/service-auth.js";

process.env.CONTROL_PLANE_SERVICE_TOKEN = "staging-service-token-0123456789";

assert.equal(verifyServiceRequest(new Headers(headers({ serviceToken: null }))), false);
assert.equal(verifyServiceRequest(new Headers(headers({ serviceToken: "wrong-service-token" }))), false);
assert.equal(verifyServiceRequest(new Headers(headers())), true);

assert.deepEqual(parseEnrollmentBody(null), { error: "invalid request", status: 400 });
assert.deepEqual(parseEnrollmentBody([]), { error: "invalid request", status: 400 });
assert.deepEqual(parseEnrollmentBody({}), { error: "Unauthorized", status: 401 });
assert.deepEqual(parseEnrollmentBody({ data: { hostname: "gateway" } }), {
  error: "Unauthorized",
  status: 401,
});
assert.deepEqual(parseEnrollmentBody(validPayload()), { enrollmentToken: "enroll_valid_token" });

assert.deepEqual(enrollmentCredentialRejected(), { error: "Unauthorized", status: 401 });

console.log("firewall enrollment tests passed");

function validPayload() {
  return {
    data: {
      enrollmentToken: "enroll_valid_token",
      installationIdentifier: "phase76b2-test",
      hostname: "gateway.validation",
      version: "phase-6-alerts-integrations",
      region: "staging",
    },
  };
}

function headers({ serviceToken = process.env.CONTROL_PLANE_SERVICE_TOKEN } = {}) {
  const values = {
    "content-type": "application/json",
    "user-agent": "test-agent",
    "x-forwarded-for": "198.51.100.10",
  };

  if (serviceToken) {
    values["x-uzyntra-service-token"] = serviceToken;
  }

  return values;
}
