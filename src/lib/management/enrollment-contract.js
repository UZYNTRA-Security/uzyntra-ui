export function parseEnrollmentBody(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { error: "invalid request", status: 400 };
  }

  const enrollmentToken = safeString(body.data?.enrollmentToken, 512);
  if (!enrollmentToken) {
    return { error: "Unauthorized", status: 401 };
  }

  return { enrollmentToken };
}

export function enrollmentCredentialRejected() {
  return { error: "Unauthorized", status: 401 };
}

function safeString(value, maxLength) {
  return (
    String(value || "")
      .replace(/[^\x20-\x7E]/g, "")
      .trim()
      .slice(0, maxLength) || null
  );
}
