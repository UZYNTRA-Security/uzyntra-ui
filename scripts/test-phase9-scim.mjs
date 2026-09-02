import assert from "node:assert/strict";
import {
  AUDIT_EVENT_TYPES,
} from "../src/lib/audit/index.js";
import {
  IDENTITY_AUDIT_EVENT_TYPES,
} from "../src/lib/identity/index.js";
import {
  SCIM_AUDIT_EVENTS,
  authenticateScimRequest,
  createScimProvider,
  createScimToken,
  generateScimToken,
  hashScimToken,
  listScimUsers,
  patchScimUser,
  provisionScimUser,
  syncScimGroup,
  updateScimUser,
} from "../src/lib/scim/index.js";

process.env.AUTH_API_KEY_SECRET = "0123456789abcdef0123456789abcdef";
process.env.AUTH_SESSION_SECRET = "abcdef0123456789abcdef0123456789";

assert.equal(AUDIT_EVENT_TYPES.SCIM_USER_CREATED, "scim.user.created");
assert.equal(AUDIT_EVENT_TYPES.SCIM_USER_UPDATED, "scim.user.updated");
assert.equal(AUDIT_EVENT_TYPES.SCIM_USER_DEACTIVATED, "scim.user.deactivated");
assert.equal(AUDIT_EVENT_TYPES.SCIM_GROUP_SYNCED, "scim.group.synced");
assert.equal(AUDIT_EVENT_TYPES.SCIM_SYNC_STARTED, "scim.sync.started");
assert.equal(AUDIT_EVENT_TYPES.SCIM_SYNC_COMPLETED, "scim.sync.completed");
assert.equal(AUDIT_EVENT_TYPES.SCIM_SYNC_FAILED, "scim.sync.failed");
assert.equal(IDENTITY_AUDIT_EVENT_TYPES.SCIM_GROUP_SYNCED, "scim.group.synced");

const plaintext = generateScimToken();
assert.match(plaintext, /^scim_[A-Za-z0-9_-]+$/);
assert.notEqual(hashScimToken(plaintext), plaintext);
assert.equal(hashScimToken(plaintext), hashScimToken(plaintext));

const providerWrites = [];
const provider = await createScimProvider({
  database: fakeDatabase({ writes: providerWrites }),
  organizationId: "org-1",
  name: "Okta SCIM",
  status: "active",
  endpointConfigurationRef: "OKTA_SCIM_CONFIG",
  baseUrl: "https://console.uzyntra.com/scim/v2",
  createdByUserId: "owner-1",
});
assert.equal(provider.name, "Okta SCIM");
assert.equal(provider.status, "active");
assert.equal(JSON.stringify(providerWrites).includes("plain-token"), false);

const tokenWrites = [];
const createdToken = await createScimToken({
  database: fakeDatabase({
    writes: tokenWrites,
    selectQueue: [[{ id: "scim-provider-1", organizationId: "org-1", status: "active" }]],
  }),
  organizationId: "org-1",
  providerId: "scim-provider-1",
  name: "Okta token",
});
assert.match(createdToken.plaintextToken, /^scim_/);
assert.equal(JSON.stringify(tokenWrites).includes(createdToken.plaintextToken), false);
assert.ok(JSON.stringify(tokenWrites).includes(hashScimToken(createdToken.plaintextToken)));

const authWrites = [];
const request = {
  headers: new Map([["authorization", `Bearer ${createdToken.plaintextToken}`]]),
};
request.headers.get = request.headers.get.bind(request.headers);
const auth = await authenticateScimRequest(request, {
  database: fakeDatabase({
    writes: authWrites,
    selectQueue: [
      [{
        id: "token-1",
        organizationId: "org-1",
        providerId: "scim-provider-1",
        tokenHash: hashScimToken(createdToken.plaintextToken),
        status: "active",
        expiresAt: null,
      }],
      [{
        id: "scim-provider-1",
        organizationId: "org-1",
        name: "Okta SCIM",
        status: "active",
        deletedAt: null,
      }],
    ],
  }),
});
assert.equal(auth.organizationId, "org-1");
assert.ok(authWrites.some((write) => write.lastUsedAt));
assert.equal(JSON.stringify(authWrites).includes(createdToken.plaintextToken), false);

const denied = await authenticateScimRequest(
  { headers: { get: () => "Bearer invalid-token" } },
  { database: fakeDatabase({ selectQueue: [[]] }) },
);
assert.equal(denied, null);

const list = await listScimUsers({
  database: fakeDatabase({
    selectQueue: [[{ user: userRecord(), membership: membershipRecord("active") }]],
  }),
  organizationId: "org-1",
});
assert.equal(list.totalResults, 1);
assert.equal(list.Resources[0].userName, "user@example.com");

const provisionWrites = [];
const provisioned = await provisionScimUser({
  database: fakeDatabase({ writes: provisionWrites }),
  organizationId: "org-1",
  providerId: "scim-provider-1",
  payload: {
    externalId: "idp-user-1",
    userName: "User@Example.com",
    active: true,
    name: { formatted: "Example User" },
  },
});
assert.equal(provisioned.userName, "user@example.com");
assert.equal(provisioned.active, true);
assert.ok(provisionWrites.some((write) => write.eventType === SCIM_AUDIT_EVENTS.USER_CREATED));
assert.ok(provisionWrites.some((write) => write.eventType === SCIM_AUDIT_EVENTS.SYNC_STARTED));
assert.equal(JSON.stringify(provisionWrites).includes("idp-user-1"), false);

const updateWrites = [];
const updated = await updateScimUser({
  database: fakeDatabase({
    writes: updateWrites,
    selectQueue: [[{ user: userRecord(), membership: membershipRecord("active") }]],
  }),
  organizationId: "org-1",
  providerId: "scim-provider-1",
  userId: "user-1",
  payload: {
    userName: "renamed@example.com",
    active: true,
  },
});
assert.equal(updated.userName, "renamed@example.com");
assert.ok(updateWrites.some((write) => write.eventType === SCIM_AUDIT_EVENTS.USER_UPDATED));

const deactivationWrites = [];
const deactivated = await patchScimUser({
  database: fakeDatabase({
    writes: deactivationWrites,
    selectQueue: [[{ user: userRecord(), membership: membershipRecord("active") }]],
  }),
  organizationId: "org-1",
  providerId: "scim-provider-1",
  userId: "user-1",
  payload: {
    Operations: [{ op: "Replace", path: "active", value: false }],
  },
});
assert.equal(deactivated.active, false);
assert.ok(deactivationWrites.some((write) => write.status === "disabled"));
assert.ok(deactivationWrites.some((write) => write.eventType === SCIM_AUDIT_EVENTS.USER_DEACTIVATED));

const groupWrites = [];
const group = await syncScimGroup({
  database: fakeDatabase({ writes: groupWrites }),
  organizationId: "org-1",
  providerId: "scim-provider-1",
  payload: {
    externalId: "idp-group-admins",
    displayName: "Security-Admins",
    members: [{ value: "user-1" }],
  },
});
assert.equal(group.displayName, "Security-Admins");
assert.ok(groupWrites.some((write) => write.eventType === SCIM_AUDIT_EVENTS.GROUP_SYNCED));
assert.ok(groupWrites.some((write) => write.status === "pending"));
assert.equal(JSON.stringify(groupWrites).includes("idp-group-admins"), false);

await assert.rejects(
  () =>
    provisionScimUser({
      database: fakeDatabase(),
      organizationId: "org-1",
      providerId: "scim-provider-1",
      payload: { userName: "not-an-email" },
    }),
  /email is invalid|email is required/,
);

console.log("phase 9 SCIM tests passed");

function userRecord(overrides = {}) {
  return {
    id: "user-1",
    email: overrides.email || "user@example.com",
    status: overrides.status || "active",
    createdAt: new Date(),
    updatedAt: new Date(),
  };
}

function membershipRecord(status = "active") {
  return {
    id: "membership-1",
    organizationId: "org-1",
    userId: "user-1",
    status,
    createdAt: new Date(),
  };
}

function fakeDatabase({ selectQueue = [], writes = [] } = {}) {
  return {
    select() {
      return chain({ result: () => selectQueue.shift() || [] });
    },
    insert() {
      return {
        values(value) {
          writes.push(value);
          const firstValue = Array.isArray(value) ? value[0] : value;
          return {
            onConflictDoUpdate() {
              return this;
            },
            onConflictDoNothing() {
              return this;
            },
            async returning() {
              return [insertResult(firstValue)];
            },
          };
        },
      };
    },
    update() {
      return {
        set(value) {
          writes.push(value);
          return chain({ result: () => [updateResult(value)] });
        },
      };
    },
    transaction(callback) {
      return callback(this);
    },
  };
}

function chain({ result }) {
  return {
    from() {
      return this;
    },
    innerJoin() {
      return this;
    },
    leftJoin() {
      return this;
    },
    where() {
      return this;
    },
    orderBy() {
      return this;
    },
    limit() {
      return Promise.resolve(result());
    },
    returning() {
      return Promise.resolve(result());
    },
  };
}

function insertResult(value) {
  if (value.tokenHash) {
    return { id: "scim-token-1", ...value };
  }
  if (value.eventType) {
    return { id: `event-${value.eventType}`, ...value };
  }
  if (value.operationType) {
    return { id: "sync-job-1", ...value };
  }
  if (value.externalGroupIdHash) {
    return { id: "group-mapping-1", status: value.status || "pending", ...value };
  }
  if (value.organizationId && value.userId) {
    return membershipRecord(value.status || "active");
  }
  if (value.email) {
    return userRecord({ email: value.email, status: value.status || "active" });
  }
  if (value.name) {
    return {
      id: "scim-provider-1",
      organizationId: value.organizationId,
      name: value.name,
      status: value.status || "disabled",
      endpointConfigurationRef: value.endpointConfigurationRef || null,
      baseUrl: value.baseUrl || null,
    };
  }
  return { id: "inserted-1", ...value };
}

function updateResult(value) {
  if (value.email || value.status) {
    if (value.email) return userRecord({ email: value.email, status: value.status || "active" });
    return membershipRecord(value.status || "active");
  }
  return { id: "updated-1", ...value };
}
