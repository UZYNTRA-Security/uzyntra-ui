import { cookies, headers } from "next/headers";
import { clientIp, requestId, userAgent } from "../../../../../../../lib/auth/api.js";
import {
  mfaChallengeIdCookieName,
  mfaChallengeTokenCookieName,
  mfaCookieOptions,
} from "../../../../../../../lib/auth/mfa.js";
import { sessionCookieName, sessionCookieOptions } from "../../../../../../../lib/auth/session.js";
import {
  completeEnterpriseOidcCallback,
  ssoPkceCookieName,
  ssoStateCookieName,
} from "../../../../../../../lib/auth/sso.js";
import { db } from "../../../../../../../db/client.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request, context) {
  const { provider } = await context.params;
  const id = requestId();
  const headersList = await headers();
  const url = new URL(request.url);
  const cookieStore = await cookies();

  try {
    const result = await completeEnterpriseOidcCallback({
      database: db(),
      providerKey: provider,
      requestUrl: request.url,
      state: url.searchParams.get("state"),
      stateCookie: cookieStore.get(ssoStateCookieName("oidc", provider))?.value,
      codeVerifier: cookieStore.get(ssoPkceCookieName(provider))?.value,
      authorizationCode: url.searchParams.get("code"),
      ipAddress: clientIp(headersList),
      userAgent: userAgent(headersList),
      requestId: id,
    });

    cookieStore.delete(ssoStateCookieName("oidc", provider));
    cookieStore.delete(ssoPkceCookieName(provider));
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
    console.error("Enterprise OIDC callback failed", safeError(error));
    cookieStore.delete(ssoStateCookieName("oidc", provider));
    cookieStore.delete(ssoPkceCookieName(provider));
    return Response.redirect(new URL("/login?sso_error=authentication_failed", request.url), 302);
  }
}

function safeError(error) {
  return { message: error?.message || "enterprise oidc callback failed" };
}

