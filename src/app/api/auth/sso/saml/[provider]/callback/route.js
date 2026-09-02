import { cookies, headers } from "next/headers";
import { clientIp, requestId, userAgent } from "../../../../../../../lib/auth/api.js";
import {
  mfaChallengeIdCookieName,
  mfaChallengeTokenCookieName,
  mfaCookieOptions,
} from "../../../../../../../lib/auth/mfa.js";
import { sessionCookieName, sessionCookieOptions } from "../../../../../../../lib/auth/session.js";
import {
  completeSamlCallback,
  ssoStateCookieName,
} from "../../../../../../../lib/auth/sso.js";
import { db } from "../../../../../../../db/client.js";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request, context) {
  return handleCallback(request, context);
}

export async function POST(request, context) {
  return handleCallback(request, context);
}

async function handleCallback(request, context) {
  const { provider } = await context.params;
  const id = requestId();
  const headersList = await headers();
  const cookieStore = await cookies();

  try {
    const payload = await callbackPayload(request);
    const result = await completeSamlCallback({
      database: db(),
      providerKey: provider,
      requestUrl: request.url,
      relayState: payload.relayState,
      stateCookie: cookieStore.get(ssoStateCookieName("saml", provider))?.value,
      samlResponse: payload.samlResponse,
      ipAddress: clientIp(headersList),
      userAgent: userAgent(headersList),
      requestId: id,
    });

    cookieStore.delete(ssoStateCookieName("saml", provider));
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
    console.error("SAML callback failed", safeError(error));
    cookieStore.delete(ssoStateCookieName("saml", provider));
    return Response.redirect(new URL("/login?sso_error=authentication_failed", request.url), 302);
  }
}

async function callbackPayload(request) {
  const url = new URL(request.url);
  if (request.method === "POST") {
    const form = await request.formData();
    return {
      relayState: form.get("RelayState") || form.get("relayState"),
      samlResponse: form.get("SAMLResponse") || form.get("samlResponse"),
    };
  }

  return {
    relayState: url.searchParams.get("RelayState") || url.searchParams.get("relayState"),
    samlResponse: url.searchParams.get("SAMLResponse") || url.searchParams.get("samlResponse"),
  };
}

function safeError(error) {
  return { message: error?.message || "saml callback failed" };
}

