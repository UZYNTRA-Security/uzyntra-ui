import { cookies, headers } from "next/headers";
import {
  completeOAuthCallback,
  oauthPkceCookieName,
  oauthStateCookieName,
} from "../../../../../../lib/auth/oauth.js";
import {
  mfaChallengeIdCookieName,
  mfaChallengeTokenCookieName,
  mfaCookieOptions,
} from "../../../../../../lib/auth/mfa.js";
import { clientIp, requestId, userAgent } from "../../../../../../lib/auth/api.js";
import {
  sessionCookieName,
  sessionCookieOptions,
} from "../../../../../../lib/auth/session.js";
import { db } from "../../../../../../db/client.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request, context) {
  const { provider } = await context.params;
  const id = requestId();
  const headersList = await headers();
  const url = new URL(request.url);
  const cookieStore = await cookies();

  try {
    const result = await completeOAuthCallback({
      database: db(),
      providerKey: provider,
      requestUrl: request.url,
      state: url.searchParams.get("state"),
      stateCookie: cookieStore.get(oauthStateCookieName(provider))?.value,
      codeVerifier: cookieStore.get(oauthPkceCookieName(provider))?.value,
      authorizationCode: url.searchParams.get("code"),
      ipAddress: clientIp(headersList),
      userAgent: userAgent(headersList),
      requestId: id,
    });

    cookieStore.delete(oauthStateCookieName(provider));
    cookieStore.delete(oauthPkceCookieName(provider));
    if (result.mfaRequired) {
      cookieStore.set(
        mfaChallengeIdCookieName(),
        result.challenge.id,
        mfaCookieOptions(result.challenge.expiresAt),
      );
      cookieStore.set(
        mfaChallengeTokenCookieName(),
        result.challenge.token,
        mfaCookieOptions(result.challenge.expiresAt),
      );
      return Response.redirect(new URL("/login?mfa=required", request.url), 302);
    }

    cookieStore.set(sessionCookieName(), result.token, sessionCookieOptions(result.session.expiresAt));

    return Response.redirect(new URL(result.redirectPath || "/", request.url), 302);
  } catch (error) {
    console.error("OAuth callback failed", safeError(error));
    cookieStore.delete(oauthStateCookieName(provider));
    cookieStore.delete(oauthPkceCookieName(provider));
    return Response.redirect(new URL("/login?oauth_error=authentication_failed", request.url), 302);
  }
}

function safeError(error) {
  return { message: error?.message || "oauth callback failed" };
}
