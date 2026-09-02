import { cookies, headers } from "next/headers";
import { clientIp, requestId, userAgent } from "../../../../../../../lib/auth/api.js";
import {
  ssoCookieOptions,
  ssoStateCookieName,
  startSamlLogin,
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
    const result = await startSamlLogin({
      database: db(),
      providerKey: provider,
      requestUrl: request.url,
      redirectPath: url.searchParams.get("redirect") || "/",
      ipAddress: clientIp(headersList),
      userAgent: userAgent(headersList),
      requestId: id,
    });

    const cookieStore = await cookies();
    cookieStore.set(ssoStateCookieName("saml", provider), result.state, ssoCookieOptions(result.expiresAt));

    return Response.redirect(result.redirectUrl, 302);
  } catch (error) {
    console.error("SAML login start failed", safeError(error));
    return Response.redirect(new URL("/login?sso_error=provider_unavailable", request.url), 302);
  }
}

function safeError(error) {
  return { message: error?.message || "saml login failed" };
}

