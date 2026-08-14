import { db } from "../../../../db/client.js";
import { authError, authJson } from "../../../../lib/auth/api.js";
import { getAuthenticatedContext } from "../../../../lib/auth/context.js";
import { listOrganizationsForUser } from "../../../../lib/management/organizations.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET() {
  try {
    const database = db();
    const context = await getAuthenticatedContext({ database });
    if (!context) {
      return authError("Unauthorized", 401);
    }

    const organizations = await listOrganizationsForUser({ database, userId: context.userId });

    return authJson({
      userId: context.userId,
      email: context.email,
      organizationId: context.organizationId,
      organizationName: context.organizationName,
      activeFirewallInstanceId: context.activeFirewallInstanceId,
      activeFirewallName: context.activeFirewallName,
      organizations,
    });
  } catch (error) {
    console.error("Authentication context lookup failed", error);
    return authError("Authentication unavailable", 500);
  }
}
