function expectedOriginFromRequest(request: Request) {
  const url = new URL(request.url);
  return `${url.protocol}//${url.host}`;
}

export function ensureTrustedOrigin(request: Request) {
  const origin = request.headers.get("origin");
  if (!origin) {
    return null;
  }

  if (origin !== expectedOriginFromRequest(request)) {
    return Response.json({ error: "Invalid request origin." }, { status: 403 });
  }

  return null;
}

export function getClientIp(request: Request) {
  const forwardedFor = request.headers.get("x-forwarded-for");
  if (forwardedFor) {
    return forwardedFor.split(",")[0]?.trim() || "unknown";
  }

  return request.headers.get("x-real-ip")?.trim() || "unknown";
}
