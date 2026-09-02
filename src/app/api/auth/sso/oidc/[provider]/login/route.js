import { cookies, headers } from "next/headers";
import { clientIp, requestId, userAgent } from "../../../../../../../lib/auth/api.js";
import {
  ssoCookieOptions,
  ssoPkceCookieName,
  ssoStateCookieName,
  startEnterpriseOidcLogin,
} from "../../../../../../../lib/auth/sso.js";
import { db } from "../../../../../../../db/client.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request, context) {
  const { provider } = await context.params;
  const id = requestId();
  const headersList = await headers();
  const url = new URL(request.url);

  try {
    const result = await startEnterpriseOidcLogin({
      database: db(),
      providerKey: provider,
      requestUrl: request.url,
      redirectPath: url.searchParams.get("redirect") || "/",
      ipAddress: clientIp(headersList),
      userAgent: userAgent(headersList),
      requestId: id,
    });

    const cookieStore = await cookies();
    cookieStore.set(ssoStateCookieName("oidc", provider), result.state, ssoCookieOptions(result.expiresAt));
    cookieStore.set(ssoPkceCookieName(provider), result.codeVerifier, ssoCookieOptions(result.expiresAt));

    return Response.redirect(result.authorizationUrl, 302);
  } catch (error) {
    console.error("Enterprise OIDC login start failed", safeError(error));
    return Response.redirect(new URL("/login?sso_error=provider_unavailable", request.url), 302);
  }
}

function safeError(error) {
  return { message: error?.message || "enterprise oidc login failed" };
}

