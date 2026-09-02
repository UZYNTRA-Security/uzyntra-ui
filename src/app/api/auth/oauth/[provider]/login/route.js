import { cookies, headers } from "next/headers";
import {
  oauthCookieOptions,
  oauthPkceCookieName,
  oauthStateCookieName,
  startOAuthLogin,
} from "../../../../../../lib/auth/oauth.js";
import { clientIp, requestId, userAgent } from "../../../../../../lib/auth/api.js";
import { db } from "../../../../../../db/client.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request, context) {
  const { provider } = await context.params;
  const id = requestId();
  const headersList = await headers();
  const url = new URL(request.url);

  try {
    const result = await startOAuthLogin({
      database: db(),
      providerKey: provider,
      requestUrl: request.url,
      redirectPath: url.searchParams.get("redirect") || "/",
      ipAddress: clientIp(headersList),
      userAgent: userAgent(headersList),
      requestId: id,
    });

    const cookieStore = await cookies();
    cookieStore.set(oauthStateCookieName(provider), result.state, oauthCookieOptions(result.expiresAt));
    cookieStore.set(
      oauthPkceCookieName(provider),
      result.codeVerifier,
      oauthCookieOptions(result.expiresAt),
    );

    return Response.redirect(result.authorizationUrl, 302);
  } catch (error) {
    console.error("OAuth login start failed", safeError(error));
    return Response.redirect(new URL("/login?oauth_error=provider_unavailable", request.url), 302);
  }
}

function safeError(error) {
  return { message: error?.message || "oauth login failed" };
}
