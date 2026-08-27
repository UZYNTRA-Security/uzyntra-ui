import "server-only";

import { PERMISSIONS } from "../rbac/catalog.js";
import { errorResponse, json, readJson, requirePermission, searchParams } from "../alerts/api.js";
import {
  collectEvidence,
  createInvestigationCase,
  createManualResponseAction,
  createSecurityPlaybook,
  listAutomationRuns,
  listEvidenceItems,
  listInvestigationCases,
  listResponseActions,
  listSecurityPlaybooks,
  triggerAutomationRun,
} from "./index.js";

export async function requireSoarPermission({ database, request, operation, method }) {
  return requirePermission({
    database,
    request,
    permission: permissionFor(operation, method),
    route: `soar/${operation}`,
    method,
  });
}

export async function handlePlaybooks({ request, database, identity, requestId, method }) {
  try {
    const data =
      method === "GET"
        ? await listSecurityPlaybooks({ database, organizationId: identity.organizationId, filters: searchParams(request) })
        : await createSecurityPlaybook({
            database,
            organizationId: identity.organizationId,
            userId: identity.userId,
            input: await readJson(request),
            auditContext: { requestId },
          });
    return json({ success: true, data }, method === "GET" ? 200 : 201, requestId);
  } catch (error) {
    return errorResponse(error, requestId);
  }
}

export async function handleAutomationRuns({ request, database, identity, requestId, method }) {
  try {
    const data =
      method === "GET"
        ? await listAutomationRuns({ database, organizationId: identity.organizationId, filters: searchParams(request) })
        : await triggerAutomationRun({
            database,
            organizationId: identity.organizationId,
            userId: identity.userId,
            input: await readJson(request),
            auditContext: { requestId },
          });
    return json({ success: true, data }, method === "GET" ? 200 : 201, requestId);
  } catch (error) {
    return errorResponse(error, requestId);
  }
}

export async function handleResponseActions({ request, database, identity, requestId, method }) {
  try {
    const data =
      method === "GET"
        ? await listResponseActions({ database, organizationId: identity.organizationId, filters: searchParams(request) })
        : await createManualResponseAction({
            database,
            organizationId: identity.organizationId,
            userId: identity.userId,
            input: await readJson(request),
            auditContext: { requestId },
          });
    return json({ success: true, data }, method === "GET" ? 200 : 201, requestId);
  } catch (error) {
    return errorResponse(error, requestId);
  }
}

export async function handleInvestigations({ request, database, identity, requestId, method }) {
  try {
    const data =
      method === "GET"
        ? await listInvestigationCases({ database, organizationId: identity.organizationId, filters: searchParams(request) })
        : await createInvestigationCase({
            database,
            organizationId: identity.organizationId,
            userId: identity.userId,
            input: await readJson(request),
            auditContext: { requestId },
          });
    return json({ success: true, data }, method === "GET" ? 200 : 201, requestId);
  } catch (error) {
    return errorResponse(error, requestId);
  }
}

export async function handleEvidence({ request, database, identity, requestId, method }) {
  try {
    const data =
      method === "GET"
        ? await listEvidenceItems({ database, organizationId: identity.organizationId, filters: searchParams(request) })
        : await collectEvidence({
            database,
            organizationId: identity.organizationId,
            userId: identity.userId,
            input: await readJson(request),
            auditContext: { requestId },
          });
    return json({ success: true, data }, method === "GET" ? 200 : 201, requestId);
  } catch (error) {
    return errorResponse(error, requestId);
  }
}

function permissionFor(operation, method) {
  if (operation === "playbooks") {
    return method === "GET" ? PERMISSIONS.PLAYBOOKS_READ : PERMISSIONS.PLAYBOOKS_MANAGE;
  }
  if (operation === "automation-runs") {
    return method === "GET" ? PERMISSIONS.AUTOMATION_RUNS_READ : PERMISSIONS.RESPONSE_ACTIONS_MANAGE;
  }
  if (operation === "response-actions") {
    return method === "GET" ? PERMISSIONS.RESPONSE_ACTIONS_READ : PERMISSIONS.RESPONSE_ACTIONS_MANAGE;
  }
  if (operation === "investigations" || operation === "cases") {
    return method === "GET" ? PERMISSIONS.INVESTIGATIONS_READ : PERMISSIONS.INVESTIGATIONS_MANAGE;
  }
  if (operation === "evidence") {
    return method === "GET" ? PERMISSIONS.EVIDENCE_READ : PERMISSIONS.INVESTIGATIONS_MANAGE;
  }
  return PERMISSIONS.AUDITS_READ;
}
